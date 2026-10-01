package changes

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func snap(web, api protocol.Workload, nodes []protocol.Node, crons []protocol.CronJob) *protocol.Snapshot {
	return &protocol.Snapshot{Workloads: []protocol.Workload{web, api}, Nodes: nodes, CronJobs: crons}
}

func summary(cs []Change) string {
	var s []string
	for _, c := range cs {
		s = append(s, c.Kind+"/"+c.Name+" "+c.What+" "+c.From+">"+c.To)
	}
	sort.Strings(s)
	return strings.Join(s, "; ")
}

func TestObserve(t *testing.T) {
	l := New()
	now := time.Now()
	web := protocol.Workload{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 2, Images: []string{"web:1"}, Generation: 3}
	api := protocol.Workload{Kind: "Deployment", Namespace: "a", Name: "api", Desired: 1, Images: []string{"api:1"}, Generation: 7}
	node := protocol.Node{Name: "n1", Ready: true}
	cron := protocol.CronJob{Namespace: "a", Name: "backup", Schedule: "0 3 * * *"}

	l.Observe("prod", snap(web, api, []protocol.Node{node}, []protocol.CronJob{cron}), now)
	if got := l.Recent(nil, 10); len(got) != 0 {
		t.Fatalf("the first snapshot is only a baseline: %v", summary(got))
	}

	web2, api2, node2, cron2 := web, api, node, cron
	web2.Images, web2.Generation = []string{"web:2"}, 4
	api2.Generation = 8 // a restart: same images and replicas
	node2.Unschedulable = true
	cron2.Suspended = true
	l.Observe("prod", snap(web2, api2, []protocol.Node{node2}, []protocol.CronJob{cron2}), now.Add(time.Minute))
	want := "CronJob/backup suspended >; Deployment/api template >; Deployment/web image web:1>web:2; Node/n1 cordoned >"
	if got := summary(l.Recent(nil, 10)); got != want {
		t.Errorf("changes:\n got %s\nwant %s", got, want)
	}

	// The deployments list failed this time: nothing about them changed.
	failed := snap(protocol.Workload{Kind: "StatefulSet", Namespace: "a", Name: "db"}, protocol.Workload{Kind: "StatefulSet", Namespace: "a", Name: "db2"},
		[]protocol.Node{node2}, []protocol.CronJob{cron2})
	failed.Errors = []string{"deployments: forbidden"}
	l.Observe("prod", failed, now.Add(2*time.Minute))
	if got := summary(l.Recent(func(c Change) bool { return c.Time.After(now.Add(time.Minute)) }, 10)); got != "StatefulSet/db created >; StatefulSet/db2 created >" {
		t.Errorf("after a failed list: %s", got)
	}
	// ... and when it works again, only real changes show.
	web3 := web2
	web3.Desired = 3
	l.Observe("prod", snap(web3, api2, nil, nil), now.Add(3*time.Minute))
	want = "CronJob/backup deleted >; Deployment/web replicas 2>3; Node/n1 deleted >; StatefulSet/db deleted >; StatefulSet/db2 deleted >"
	if got := summary(l.Recent(func(c Change) bool { return c.Time.After(now.Add(2 * time.Minute)) }, 10)); got != want {
		t.Errorf("after recovery:\n got %s\nwant %s", got, want)
	}
	// Clusters are separate, and the newest comes first.
	l.Observe("dev", snap(web, api, nil, nil), now)
	if got := l.Recent(nil, 1); len(got) != 1 || !got[0].Time.Equal(now.Add(3*time.Minute).UTC()) {
		t.Errorf("newest first: %+v", got)
	}
}
