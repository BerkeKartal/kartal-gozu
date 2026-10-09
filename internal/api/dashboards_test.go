package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/dashboard"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestDashboards(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	team, _ := auth.ParseGrant("operator@prod/team-a")
	other, _ := auth.ParseGrant("operator@prod/team-b")
	const otherTok = "other-token-0123456789"
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:   auth.NewUser("takim", []auth.Grant{team}),
			otherTok:  auth.NewUser("diger", []auth.Grant{other}),
			viewerTok: {Name: "ekip", Role: auth.Viewer},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Dashboards: dashboard.New(keeper),
	}, store.New("prod"), log)

	body := `{"title": "Shop", "range": "3h", "variables": [{"name": "ns", "label": "namespace"}],
		"panels": [{"title": "Requests", "type": "graph", "w": 8, "h": 5, "queries": [["sum(rate(http_requests_total{namespace=~\"$ns\"}[$__rate_interval]))", "all"]]},
		{"type": "text", "text": "Ask the shop team."}]}`
	if rec := do(s, "POST", "/api/v1/dashboards", viewerTok, body); rec.Code != 403 {
		t.Errorf("a viewer made a dashboard: %d", rec.Code)
	}
	for _, bad := range []string{
		`{"title": ""}`,
		`{"title": "x", "panels": [{"type": "pie"}]}`,
		`{"title": "x", "panels": [{"type": "graph", "w": 13}]}`,
		`{"title": "x", "range": "forever"}`,
		`{"title": "x", "variables": [{"name": "a b", "label": "pod"}]}`,
		`{"title": "x", "variables": [{"name": "__interval", "label": "pod"}]}`,
		`{"title": "x", "panels": [{"type": "graph", "queries": [{"not": "a query"}]}]}`,
	} {
		if rec := do(s, "POST", "/api/v1/dashboards", teamTok, bad); rec.Code != 400 {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	rec := do(s, "POST", "/api/v1/dashboards", teamTok, body)
	if rec.Code != 201 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	var d dashboardView
	json.Unmarshal(rec.Body.Bytes(), &d)
	if d.Owner != "takim" || d.Version != 1 || len(d.Panels) != 2 || d.Panels[1].W != 6 || d.Panels[0].ID == "" {
		t.Fatalf("saved %+v", d)
	}
	// Everyone sees it; only its maker and admins may change it.
	var list struct{ Dashboards []dashboard.Summary }
	json.Unmarshal(do(s, "GET", "/api/v1/dashboards", viewerTok, "").Body.Bytes(), &list)
	if len(list.Dashboards) != 1 || list.Dashboards[0].Panels != 2 {
		t.Errorf("list %+v", list)
	}
	for tok, want := range map[string]bool{viewerTok: false, otherTok: false, teamTok: true, adminTok: true} {
		var v dashboardView
		json.Unmarshal(do(s, "GET", "/api/v1/dashboards/"+d.ID, tok, "").Body.Bytes(), &v)
		if v.CanEdit != want {
			t.Errorf("%s may edit: %v", tok, v.CanEdit)
		}
	}
	d.Title = "Shop (changed)"
	change, _ := json.Marshal(d.Dashboard)
	if rec := do(s, "PUT", "/api/v1/dashboards/"+d.ID, otherTok, string(change)); rec.Code != 403 {
		t.Errorf("another team changed it: %d", rec.Code)
	}
	if rec := do(s, "PUT", "/api/v1/dashboards/"+d.ID, adminTok, string(change)); rec.Code != 200 {
		t.Fatalf("admin's change: %d %s", rec.Code, rec.Body)
	}
	// The team's change was made on the version before: it is refused,
	// not saved over the admin's.
	if rec := do(s, "PUT", "/api/v1/dashboards/"+d.ID, teamTok, string(change)); rec.Code != 409 || !strings.Contains(rec.Body.String(), "admin") {
		t.Errorf("a change on an old version: %d %s", rec.Code, rec.Body)
	}
	var now dashboardView
	json.Unmarshal(do(s, "GET", "/api/v1/dashboards/"+d.ID, teamTok, "").Body.Bytes(), &now)
	if now.Version != 2 || now.Owner != "takim" || now.UpdatedBy != "admin" || now.Title != "Shop (changed)" {
		t.Errorf("after the change: %+v", now)
	}
	if rec := do(s, "DELETE", "/api/v1/dashboards/"+d.ID, otherTok, ""); rec.Code != 403 {
		t.Errorf("another team removed it: %d", rec.Code)
	}
	if rec := do(s, "DELETE", "/api/v1/dashboards/"+d.ID, teamTok, ""); rec.Code != 200 {
		t.Errorf("remove: %d", rec.Code)
	}
	if rec := do(s, "GET", "/api/v1/dashboards/"+d.ID, teamTok, ""); rec.Code != 404 {
		t.Errorf("a removed dashboard: %d", rec.Code)
	}
}

// The dashboards may not outgrow the Secret they are kept in.
func TestDashboardsHaveABudget(t *testing.T) {
	m := dashboard.New(settings.NewKeeper(context.Background(), settings.Memory{}, nil))
	text := strings.Repeat("x", 9000)
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		d := settings.Dashboard{Title: "big"}
		for j := 0; j < 10; j++ {
			d.Panels = append(d.Panels, settings.Panel{Type: "text", Text: text})
		}
		_, err = m.Add(context.Background(), d, "a")
	}
	var invalid *settings.InvalidError
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "KiB") {
		t.Errorf("no budget: %v", err)
	}
}
