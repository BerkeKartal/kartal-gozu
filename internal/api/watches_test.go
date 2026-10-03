package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/appmetrics"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

// Everyone sees the watches of the namespaces they see; operators change
// those of their own namespaces only.
func TestWatchesFollowRoles(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	watches := appmetrics.New(keeper, nil, log)
	grant, err := auth.ParseGrant("operator@prod/team-a")
	if err != nil {
		t.Fatal(err)
	}
	st := store.New("prod")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:   auth.NewUser("takim", []auth.Grant{grant}),
			viewerTok: {Name: "ekip", Role: auth.Viewer},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Watches: watches,
	}, st, log)
	st.PutSnapshot("prod", &protocol.Snapshot{Pods: []protocol.Pod{
		{Namespace: "team-a", Name: "web-1", Phase: "Running", Owner: "Deployment/web"},
	}}, time.Now())

	body := `{"target": "Deployment/web", "port": "9100", "metric": "http_requests_total", "rate": true, "cluster": "elsewhere"}`
	for _, c := range []struct {
		tok, path string
		want      int
	}{
		{viewerTok, "/api/v1/clusters/prod/namespaces/team-a/watches", 403},
		{teamTok, "/api/v1/clusters/prod/namespaces/team-b/watches", 403},
		{teamTok, "/api/v1/clusters/nowhere/namespaces/team-a/watches", 403},
		{adminTok, "/api/v1/clusters/nowhere/namespaces/team-a/watches", 404},
		{teamTok, "/api/v1/clusters/prod/namespaces/team-a/watches", 201},
		{adminTok, "/api/v1/clusters/prod/namespaces/team-b/watches", 201},
	} {
		if rec := do(s, "POST", c.path, c.tok, body); rec.Code != c.want {
			t.Errorf("%s %s: %d %s", c.tok, c.path, rec.Code, rec.Body)
		}
	}
	list := func(tok string) []appmetrics.Status {
		var out struct{ Watches []appmetrics.Status }
		json.Unmarshal(do(s, "GET", "/api/v1/clusters/prod/watches", tok, "").Body.Bytes(), &out)
		return out.Watches
	}
	mine := list(teamTok)
	if len(mine) != 1 || mine[0].Namespace != "team-a" || mine[0].Cluster != "prod" || len(list(adminTok)) != 2 || len(list(viewerTok)) != 2 {
		t.Fatalf("lists: %+v", mine)
	}
	var b appmetrics.Status
	for _, w := range list(adminTok) {
		if w.Namespace == "team-b" {
			b = w
		}
	}
	// The team cannot reach team-b's watch, not even through its own
	// namespace's path.
	if rec := do(s, "DELETE", "/api/v1/clusters/prod/namespaces/team-a/watches/"+b.ID, teamTok, ""); rec.Code != 404 {
		t.Errorf("deleted another namespace's watch: %d", rec.Code)
	}
	if rec := do(s, "PUT", "/api/v1/clusters/prod/namespaces/team-a/watches/"+mine[0].ID, teamTok,
		`{"name": "Requests", "target": "Deployment/web", "port": "9100", "metric": "http_requests_total", "rate": true}`); rec.Code != 200 {
		t.Errorf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "DELETE", "/api/v1/clusters/prod/namespaces/team-a/watches/"+mine[0].ID, teamTok, ""); rec.Code != 200 {
		t.Errorf("remove: %d %s", rec.Code, rec.Body)
	}
	var audit []AuditEntry
	json.Unmarshal(do(s, "GET", "/api/v1/audit", adminTok, "").Body.Bytes(), &audit)
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action+" "+e.Namespace)
	}
	if got := strings.Join(actions, ","); got != "remove-watch team-a,change-watch team-a,add-watch team-b,add-watch team-a" {
		t.Errorf("audit: %s", got)
	}

	// A pod's page is read through its agent, for viewers too.
	go func() {
		cmds, _ := st.TakeCommands(context.Background(), "prod", time.Second)
		for _, c := range cmds {
			if c.Type == protocol.CommandScrape && c.Port == "9100" && c.Name == "web-1" {
				st.Deliver("prod", protocol.Result{CommandID: c.ID, OK: true, Output: `{"families":[]}`})
			}
		}
	}()
	if rec := do(s, "GET", "/api/v1/clusters/prod/namespaces/team-a/pods/web-1/scrape?port=9100&path=/metrics", viewerTok, ""); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), "families") {
		t.Errorf("scrape: %d %s", rec.Code, rec.Body)
	}
}
