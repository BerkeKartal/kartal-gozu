package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const teamTok = "team-a-token-0123456789"

// A user limited to one namespace sees only that namespace, anywhere in
// the API, and may act only there.
func TestScopedUser(t *testing.T) {
	grant, err := auth.ParseGrant("operator@prod/team-a")
	if err != nil {
		t.Fatal(err)
	}
	alerts := alert.NewManager(0, nil)
	st := store.New("prod", "dev")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users:       map[string]auth.User{teamTok: auth.NewUser("takim", []auth.Grant{grant})},
		AdminToken:  adminTok,
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: 50 * time.Millisecond,
		Alerts: alerts,
	}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	snap := &protocol.Snapshot{
		Nodes:      []protocol.Node{{Name: "n1", Ready: false}},
		Namespaces: []protocol.Namespace{{Name: "team-a"}, {Name: "team-b"}},
		Pods: []protocol.Pod{
			{Namespace: "team-a", Name: "a1", Phase: "Running", Ready: 1, Total: 1},
			{Namespace: "team-b", Name: "b1", Phase: "Running", Reason: "CrashLoopBackOff", Total: 1},
		},
		Errors: []string{"secrets in team-b: forbidden"},
	}
	now := time.Now()
	st.PutSnapshot("prod", snap, now)
	alerts.Observe("prod", snap, now)

	get := func(path string, v any) int {
		rec := do(s, "GET", path, teamTok, "")
		if v != nil {
			json.Unmarshal(rec.Body.Bytes(), v)
		}
		return rec.Code
	}
	var clusters []clusterSummary
	get("/api/v1/clusters", &clusters)
	// The not-ready node's alert concerns everyone in the cluster; the
	// crash loop in team-b does not.
	if len(clusters) != 1 || clusters[0].Name != "prod" || clusters[0].Counts.Pods != 1 || clusters[0].Counts.PodsUnhealthy != 0 ||
		clusters[0].Counts.Nodes != 0 || len(clusters[0].Errors) != 0 || clusters[0].Alerts != 1 {
		t.Errorf("clusters: %+v", clusters)
	}
	var pods []protocol.Pod
	if get("/api/v1/clusters/prod/pods", &pods); len(pods) != 1 || pods[0].Name != "a1" {
		t.Errorf("pods: %+v", pods)
	}
	var nodes []protocol.Node
	if get("/api/v1/clusters/prod/nodes", &nodes); len(nodes) != 0 {
		t.Errorf("nodes: %+v", nodes)
	}
	var ns []namespaceSummary
	if get("/api/v1/clusters/prod/namespaces", &ns); len(ns) != 1 || ns[0].Name != "team-a" {
		t.Errorf("namespaces: %+v", ns)
	}
	var st2 alert.State
	if get("/api/v1/alerts", &st2); len(st2.Active) != 1 || st2.Active[0].Kind != "NodeNotReady" {
		// The node alert is about the cluster, the crash loop about team-b.
		t.Errorf("alerts: %+v", st2.Active)
	}

	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/v1/clusters/dev/pods", 403},
		{"GET", "/api/v1/clusters/prod/namespaces/team-b/pods/b1/logs", 403},
		{"GET", "/api/v1/clusters/prod/resources/core/v1/pods", 403},            // the whole cluster
		{"GET", "/api/v1/clusters/prod/resources/core/v1/nodes/n1", 403},        // a cluster-wide object
		{"GET", "/api/v1/clusters/prod/metrics?kind=node&name=n1", 403},         // node usage
		{"GET", "/api/v1/clusters/prod/metrics?kind=pod&namespace=team-a", 200}, // its own pods
		{"POST", "/api/v1/clusters/prod/nodes/n1/cordon", 403},
		{"DELETE", "/api/v1/clusters/prod/namespaces/team-b/pods/b1", 403},
		{"POST", "/api/v1/clusters/prod/namespaces/team-a/pods/a1/exec", 403}, // admin only
		{"GET", "/api/v1/settings/email", 403},
		// Allowed: they reach the agent, which does not answer in this test.
		{"DELETE", "/api/v1/clusters/prod/namespaces/team-a/pods/a1", 504},
		{"GET", "/api/v1/clusters/prod/resources/core/v1/pods?namespace=team-a", 504},
	} {
		body := ""
		if c.method == "POST" {
			body = `{"unschedulable":true,"command":["ls"]}`
		}
		if rec := do(s, c.method, c.path, teamTok, body); rec.Code != c.want {
			t.Errorf("%s %s: %d, want %d (%s)", c.method, c.path, rec.Code, c.want, rec.Body)
		}
	}

	var entries []AuditEntry
	do(s, "POST", "/api/v1/clusters/prod/nodes/n1/cordon", adminTok, `{"unschedulable":true}`)
	json.Unmarshal(do(s, "GET", "/api/v1/audit", teamTok, "").Body.Bytes(), &entries)
	for _, e := range entries {
		if e.Namespace != "team-a" {
			t.Errorf("an entry outside team-a: %+v", e)
		}
	}
	if len(entries) != 1 {
		t.Errorf("audit: %+v", entries)
	}

	var me struct {
		Role, Everywhere string
		Grants           []struct {
			Role   string
			Scopes []auth.Scope
		}
	}
	get("/api/v1/me", &me)
	if me.Role != "operator" || me.Everywhere != "none" || len(me.Grants) != 1 || me.Grants[0].Scopes[0].Namespace != "team-a" {
		t.Errorf("me: %+v", me)
	}
	if rec := do(s, "GET", "/api/v1/me", adminTok, ""); !strings.Contains(rec.Body.String(), `"everywhere":"admin"`) {
		t.Errorf("admin: %s", rec.Body)
	}
}
