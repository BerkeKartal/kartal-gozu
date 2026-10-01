package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/changes"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestTimelineAndReleases(t *testing.T) {
	viewer, _ := auth.ParseGrant("viewer@prod/team-a")
	viewerB, _ := auth.ParseGrant("viewer@prod/team-b")
	const teamBTok = "team-b-token"
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:  auth.NewUser("takim", []auth.Grant{viewer}),
			teamBTok: auth.NewUser("b", []auth.Grant{viewerB}),
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
	}, store.New("prod"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	report := func(snap protocol.Snapshot) {
		b, _ := json.Marshal(snap)
		if rec := do(s, "POST", "/agent/v1/report", agentTok, string(b)); rec.Code != 204 {
			t.Fatalf("report: %d %s", rec.Code, rec.Body)
		}
	}
	a := protocol.Workload{Kind: "Deployment", Namespace: "team-a", Name: "web", Desired: 1, Images: []string{"web:1"}}
	b := protocol.Workload{Kind: "Deployment", Namespace: "team-b", Name: "api", Desired: 1, Images: []string{"api:1"}}
	report(protocol.Snapshot{Workloads: []protocol.Workload{a, b}, Nodes: []protocol.Node{{Name: "n1", Ready: true}}})
	a.Images, b.Images = []string{"web:2"}, []string{"api:2"}
	report(protocol.Snapshot{Workloads: []protocol.Workload{a, b}, Nodes: []protocol.Node{{Name: "n1", Ready: true, Unschedulable: true}}})
	s.audit.add(AuditEntry{Time: time.Now().UTC(), User: "admin", Role: "admin", Action: "restart", Cluster: "prod", Namespace: "team-a", Object: "deployment/web", OK: true})

	var all []changes.Change
	json.Unmarshal(do(s, "GET", "/api/v1/changes", adminTok, "").Body.Bytes(), &all)
	if len(all) != 4 || all[0].By != "admin" || all[0].What != "restart" {
		t.Fatalf("admin's timeline: %+v", all)
	}
	var mine []changes.Change
	json.Unmarshal(do(s, "GET", "/api/v1/changes", teamTok, "").Body.Bytes(), &mine)
	// Only team-a's image; no node (the whole cluster) and no names of who
	// did what (that is for operators).
	if len(mine) != 1 || mine[0].Name != "web" || mine[0].What != "image" || mine[0].To != "web:2" {
		t.Errorf("a viewer of team-a: %+v", mine)
	}
	json.Unmarshal(do(s, "GET", "/api/v1/changes?namespace=team-b", adminTok, "").Body.Bytes(), &all)
	if len(all) != 1 || all[0].Name != "api" {
		t.Errorf("?namespace=team-b: %+v", all)
	}

	// Someone scales api through Kartal Gözü and the next snapshot shows it:
	// the two are one change, which says who made it.
	s.audit.add(AuditEntry{Time: time.Now().UTC(), User: "admin", Role: "admin", Action: "scale", Cluster: "prod", Namespace: "team-b", Object: "deployment/api", Detail: "replicas=3", OK: true})
	b.Desired = 3
	report(protocol.Snapshot{Workloads: []protocol.Workload{a, b}, Nodes: []protocol.Node{{Name: "n1", Ready: true, Unschedulable: true}}})
	var api []changes.Change
	json.Unmarshal(do(s, "GET", "/api/v1/changes?kind=deployment&name=api", adminTok, "").Body.Bytes(), &api)
	if len(api) != 2 || api[0].What != "replicas" || api[0].By != "admin" || api[0].From != "1" || api[0].To != "3" || api[1].What != "image" {
		t.Errorf("a scale through Kartal Gözü: %+v", api)
	}
	// A viewer sees the change, not who made it.
	var seen []changes.Change
	json.Unmarshal(do(s, "GET", "/api/v1/changes?name=api", teamBTok, "").Body.Bytes(), &seen)
	if len(seen) != 2 || seen[0].What != "replicas" || seen[0].By != "" {
		t.Errorf("a viewer of team-b: %+v", seen)
	}

	var rel []release
	json.Unmarshal(do(s, "GET", "/api/v1/releases", teamTok, "").Body.Bytes(), &rel)
	if len(rel) != 1 || rel[0].Name != "web" || rel[0].Images[0] != "web:2" {
		t.Errorf("releases for team-a: %+v", rel)
	}
	json.Unmarshal(do(s, "GET", "/api/v1/releases", adminTok, "").Body.Bytes(), &rel)
	if len(rel) != 2 {
		t.Errorf("releases for the admin: %+v", rel)
	}
}
