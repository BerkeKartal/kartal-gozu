package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/collect"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// Everyone sees the stored metrics and targets of the namespaces they see;
// operators choose the targets of their own namespaces; only admins set
// how long data is kept and delete it.
func TestStoreFollowsRoles(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	dir := t.TempDir()
	db, err := tsdb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	grant, err := auth.ParseGrant("operator@prod/team-a")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:   auth.NewUser("takim", []auth.Grant{grant}),
			viewerTok: {Name: "ekip", Role: auth.Viewer},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Collect: collect.New(keeper, db, dir, log),
	}, store.New("prod"), log)

	now := time.Now()
	for _, ns := range []string{"team-a", "team-b"} {
		ls := tsdb.FromMap("http_requests_total", map[string]string{"cluster": "prod", "namespace": ns, "pod": "web-1"})
		if err := db.Append(now.Add(-time.Minute), []tsdb.Sample{{Labels: ls, Type: "counter", Value: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	series := func(tok string) int {
		rec := do(s, "GET", "/api/v1/store/metrics", tok, "")
		var out []tsdb.MetricInfo
		json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 || len(out) == 0 {
			return 0
		}
		return out[0].Series
	}
	if a, v := series(teamTok), series(viewerTok); a != 1 || v != 2 {
		t.Errorf("series seen: team %d, viewer %d; want 1 and 2", a, v)
	}

	body := `{"target": "Deployment/web", "port": "9100", "cluster": "elsewhere"}`
	for _, c := range []struct {
		tok, path string
		want      int
	}{
		{viewerTok, "/api/v1/clusters/prod/namespaces/team-a/collect", 403},
		{teamTok, "/api/v1/clusters/prod/namespaces/team-b/collect", 403},
		{adminTok, "/api/v1/clusters/nowhere/namespaces/team-a/collect", 404},
		{teamTok, "/api/v1/clusters/prod/namespaces/team-a/collect", 201},
		{teamTok, "/api/v1/clusters/prod/namespaces/team-a/collect", 400}, // the same pages again
		{adminTok, "/api/v1/clusters/prod/namespaces/team-b/collect", 201},
	} {
		if rec := do(s, "POST", c.path, c.tok, body); rec.Code != c.want {
			t.Errorf("%s %s: %d %s", c.tok, c.path, rec.Code, rec.Body)
		}
	}
	list := func(tok string) []collect.Status {
		var out []collect.Status
		json.Unmarshal(do(s, "GET", "/api/v1/store/targets?cluster=prod", tok, "").Body.Bytes(), &out)
		return out
	}
	mine, all := list(teamTok), list(adminTok)
	if len(mine) != 1 || mine[0].Namespace != "team-a" || mine[0].Path != "/metrics" || len(all) != 2 {
		t.Fatalf("lists: %+v, %+v", mine, all)
	}
	other := all[1]
	if rec := do(s, "DELETE", "/api/v1/clusters/prod/namespaces/team-a/collect/"+other.ID, teamTok, ""); rec.Code != 404 {
		t.Errorf("removed another namespace's target: %d", rec.Code)
	}
	if rec := do(s, "PUT", "/api/v1/clusters/prod/namespaces/team-a/collect/"+mine[0].ID, teamTok, `{"target": "Deployment/web", "port": "8080"}`); rec.Code != 200 {
		t.Errorf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "DELETE", "/api/v1/clusters/prod/namespaces/team-a/collect/"+mine[0].ID, teamTok, ""); rec.Code != 200 {
		t.Errorf("remove: %d %s", rec.Code, rec.Body)
	}

	for _, c := range []struct {
		tok, method, path, body string
		want                    int
	}{
		{teamTok, "PUT", "/api/v1/store/config", `{"interval": 60}`, 403},
		{adminTok, "PUT", "/api/v1/store/config", `{"interval": 1}`, 400},
		{adminTok, "PUT", "/api/v1/store/config", `{"interval": 60, "retentionDays": 30}`, 200},
		{teamTok, "POST", "/api/v1/store/delete", `{"from": 0, "to": 1}`, 403},
		{adminTok, "POST", "/api/v1/store/delete", `{"from": 5, "to": 1}`, 400},
		{adminTok, "POST", "/api/v1/store/delete", `{"from": 5}`, 400},
		{adminTok, "POST", "/api/v1/store/delete", fmt.Sprintf(`{"from": 0, "to": %d}`, now.UnixMilli()), 200},
	} {
		if rec := do(s, c.method, c.path, c.tok, c.body); rec.Code != c.want {
			t.Errorf("%s %s %s: %d %s", c.tok, c.method, c.body, rec.Code, rec.Body)
		}
	}
	if v := series(viewerTok); v != 0 {
		t.Errorf("%d series left after deleting everything", v)
	}
	var stats collect.Stats
	json.Unmarshal(do(s, "GET", "/api/v1/store", viewerTok, "").Body.Bytes(), &stats)
	if stats.Interval != 60 || stats.RetentionDays != 30 || stats.Targets != 1 || stats.Dir != dir {
		t.Errorf("stats %+v", stats)
	}
	// The team sees no target of team-b.
	json.Unmarshal(do(s, "GET", "/api/v1/store", teamTok, "").Body.Bytes(), &stats)
	if stats.Targets != 0 {
		t.Errorf("the team counts %d targets, want 0", stats.Targets)
	}
}

func TestStoreOffWithoutDirectory(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(Config{AgentTokens: map[string]string{agentTok: "prod"}, AdminToken: adminTok, StaleAfter: time.Minute,
		MaxPollWait: time.Second, CommandTimeout: time.Second}, store.New("prod"), log)
	if rec := do(s, "GET", "/api/v1/store", adminTok, ""); rec.Code != 404 {
		t.Errorf("store without a directory: %d", rec.Code)
	}
}

// Queries see only the series of the namespaces a user sees.
func TestStoreQueriesFollowRoles(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	dir := t.TempDir()
	db, err := tsdb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	grant, err := auth.ParseGrant("viewer@prod/team-a")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users:       map[string]auth.User{teamTok: auth.NewUser("takim", []auth.Grant{grant})},
		AdminToken:  adminTok,
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Collect: collect.New(keeper, db, dir, log),
	}, store.New("prod"), log)
	now := time.Now().Truncate(time.Second)
	for _, ns := range []string{"team-a", "team-b"} {
		ls := tsdb.FromMap("mem", map[string]string{"cluster": "prod", "namespace": ns, "pod": "web-1"})
		if err := db.Append(now.Add(-time.Minute), []tsdb.Sample{{Labels: ls, Type: "gauge", Value: 100}}); err != nil {
			t.Fatal(err)
		}
	}
	sum := func(tok string) float64 {
		rec := do(s, "GET", fmt.Sprintf("/api/v1/store/query?query=sum(mem)&time=%d", now.UnixMilli()), tok, "")
		var res struct {
			Series []struct{ Values []float64 }
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != 200 || len(res.Series) != 1 {
			t.Fatalf("query as %s: %d %s", tok, rec.Code, rec.Body)
		}
		return res.Series[0].Values[0]
	}
	if a, all := sum(teamTok), sum(adminTok); a != 100 || all != 200 {
		t.Errorf("sum(mem): team %v, admin %v; want 100 and 200", a, all)
	}
	rec := do(s, "GET", fmt.Sprintf("/api/v1/store/query_range?query=mem&start=%d&end=%d&step=15000", now.Add(-5*time.Minute).UnixMilli(), now.UnixMilli()), teamTok, "")
	if rec.Code != 200 {
		t.Errorf("range query: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"/api/v1/store/query?query=sum(", "/api/v1/store/query", "/api/v1/store/query_range?query=mem&step=x",
		"/api/v1/store/query_range?query=mem&start=0&end=9223372036854775807&step=1"} {
		if rec := do(s, "GET", bad, teamTok, ""); rec.Code != 400 {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	var values []string
	json.Unmarshal(do(s, "GET", "/api/v1/store/labels/namespace/values?match=mem", teamTok, "").Body.Bytes(), &values)
	if len(values) != 1 || values[0] != "team-a" {
		t.Errorf("namespaces the team sees: %v", values)
	}
	var names []string
	json.Unmarshal(do(s, "GET", "/api/v1/store/labels", adminTok, "").Body.Bytes(), &names)
	if strings.Join(names, ",") != "cluster,namespace,pod" {
		t.Errorf("label names: %v", names)
	}
}
