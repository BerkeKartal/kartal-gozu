package settings

import (
	"strings"
	"testing"
	"time"
)

func TestSilenceValidate(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	ok := Silence{Cluster: "prod", Namespace: "shop-*", Starts: now, Ends: now.Add(2 * time.Hour)}
	if err := ok.Validate(now); err != nil {
		t.Fatalf("a good silence: %v", err)
	}
	for name, s := range map[string]Silence{
		"ends before it starts": {Starts: now, Ends: now.Add(-time.Minute)},
		"ends as it starts":     {Starts: now, Ends: now},
		"over already":          {Starts: now.Add(-3 * time.Hour), Ends: now.Add(-time.Hour)},
		"longer than a month":   {Starts: now, Ends: now.Add(32 * 24 * time.Hour)},
		"too far ahead":         {Starts: now.Add(91 * 24 * time.Hour), Ends: now.Add(92 * 24 * time.Hour)},
		"a star inside":         {Namespace: "shop-*-prod", Starts: now, Ends: now.Add(time.Hour)},
		"a star in the cluster": {Cluster: "prod*", Starts: now, Ends: now.Add(time.Hour)},
		"a star in the kind":    {Kind: "Pod*", Starts: now, Ends: now.Add(time.Hour)},
		"a space":               {Object: "web 1", Starts: now, Ends: now.Add(time.Hour)},
		"a comment of 2 lines":  {Comment: "deploy\nagain", Starts: now, Ends: now.Add(time.Hour)},
		"a long comment":        {Comment: strings.Repeat("x", 501), Starts: now, Ends: now.Add(time.Hour)},
	} {
		if err := s.Validate(now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSilenceCovers(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	window := Silence{Cluster: "prod", Namespace: "shop-*", Starts: now, Ends: now.Add(time.Hour)}
	for _, c := range []struct {
		cluster, kind, ns, object string
		at                        time.Time
		want                      bool
	}{
		{"prod", "PodFailing", "shop-prod", "web-1", now, true},
		{"prod", "WorkloadDegraded", "shop-staging", "Deployment/web", now.Add(59 * time.Minute), true},
		{"prod", "PodFailing", "shop-prod", "web-1", now.Add(time.Hour), false},    // over
		{"prod", "PodFailing", "shop-prod", "web-1", now.Add(-time.Second), false}, // not yet
		{"test", "PodFailing", "shop-prod", "web-1", now, false},                   // another cluster
		{"prod", "PodFailing", "shop", "web-1", now, false},                        // another namespace
		{"prod", "NodeNotReady", "", "n1", now, false},                             // of no namespace
	} {
		if got := window.Covers(c.cluster, c.kind, c.ns, c.object, c.at); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
	// One problem: its kind and object, anywhere in the cluster.
	one := Silence{Cluster: "prod", Kind: "NodeDiskFilling", Object: "n1*", Starts: now, Ends: now.Add(time.Hour)}
	if !one.Covers("prod", "NodeDiskFilling", "", "n1 (images)", now) || one.Covers("prod", "NodeNotReady", "", "n1", now) {
		t.Error("a silence of one kind on one node")
	}
	// No cluster: every cluster and the server's own checks.
	all := Silence{Kind: "URLDown", Starts: now, Ends: now.Add(time.Hour)}
	if !all.Covers("", "URLDown", "", "shop", now) || !all.Covers("prod", "URLDown", "", "x", now) {
		t.Error("a silence of every cluster")
	}
}
