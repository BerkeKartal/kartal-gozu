package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/fakees"
	"github.com/BerkeKartal/kartal-gozu/internal/logwatch"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestLogRules(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	es := httptest.NewServer(&fakees.Server{})
	defer es.Close()
	keeper := settings.NewKeeper(ctx, settings.Memory{}, log)
	sources := datasource.NewManager(keeper)
	src, err := sources.Add(ctx, settings.DataSource{Name: "Logs", Type: settings.SourceElasticsearch, URL: es.URL, Index: "logs-*"})
	if err != nil {
		t.Fatal(err)
	}
	alerts := alert.NewManager(time.Minute, log)
	rules := logwatch.New(keeper, sources, alerts, log)
	team, _ := auth.ParseGrant("operator@prod/team-a")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:   auth.NewUser("takim", []auth.Grant{team}),
			viewerTok: {Name: "ekip", Role: auth.Viewer},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Alerts: alerts, DataSources: sources, LogRules: rules,
	}, store.New("prod"), log)

	rule := `{"name": "Errors", "source": "` + src.ID + `", "query": "log.level:ERROR", "window": 1800, "above": 3, "severity": "critical"}`
	// A rule counts in every namespace's lines: only admins make one.
	for _, tok := range []string{viewerTok, teamTok} {
		if rec := do(s, "POST", "/api/v1/logrules", tok, rule); rec.Code != 403 {
			t.Errorf("%s made a log rule: %d", tok, rec.Code)
		}
		if rec := do(s, "POST", "/api/v1/logrules/try", tok, rule); rec.Code != 403 {
			t.Errorf("%s tried a log rule: %d", tok, rec.Code)
		}
	}
	for _, bad := range []string{
		`{"name": "x", "source": "` + src.ID + `"}`,
		`{"name": "x", "source": "nowhere", "query": "a"}`,
		`{"name": "x", "source": "` + src.ID + `", "query": "a", "window": 10}`,
	} {
		if rec := do(s, "POST", "/api/v1/logrules", adminTok, bad); rec.Code != 400 {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	// Tried first: counted once, nothing saved.
	rec := do(s, "POST", "/api/v1/logrules/try", adminTok, rule)
	var tried logwatch.Result
	json.Unmarshal(rec.Body.Bytes(), &tried)
	if rec.Code != 200 || tried.Error != "" || tried.Count == 0 {
		t.Fatalf("try: %d %s", rec.Code, rec.Body)
	}
	rec = do(s, "POST", "/api/v1/logrules", adminTok, rule)
	var saved settings.LogRule
	json.Unmarshal(rec.Body.Bytes(), &saved)
	if rec.Code != 201 || saved.ID == "" || saved.Name != "Errors" {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}

	// Everyone sees the rules, on the alerts page too, and their alerts.
	rules.Round(ctx)
	for _, tok := range []string{viewerTok, teamTok, adminTok} {
		var list struct{ Rules []logwatch.Status }
		json.Unmarshal(do(s, "GET", "/api/v1/logrules", tok, "").Body.Bytes(), &list)
		if len(list.Rules) != 1 || !list.Rules[0].Firing || list.Rules[0].SourceName != "Logs" || list.Rules[0].Last == nil {
			t.Errorf("%s lists %+v", tok, list.Rules)
		}
		var page struct {
			LogRules []logwatch.Status
			Active   []alert.Alert
		}
		json.Unmarshal(do(s, "GET", "/api/v1/alerts", tok, "").Body.Bytes(), &page)
		if len(page.LogRules) != 1 || len(page.Active) != 1 || page.Active[0].Kind != alert.LogLimit || page.Active[0].Object != "Errors" {
			t.Errorf("%s sees on the alerts page: %+v %+v", tok, page.LogRules, page.Active)
		}
	}

	quiet := `{"name": "Errors", "source": "` + src.ID + `", "query": "log.level:ERROR", "window": 1800, "above": 1000000}`
	if rec := do(s, "PUT", "/api/v1/logrules/"+saved.ID, teamTok, quiet); rec.Code != 403 {
		t.Errorf("an operator changed a log rule: %d", rec.Code)
	}
	if rec := do(s, "PUT", "/api/v1/logrules/"+saved.ID, adminTok, quiet); rec.Code != 200 {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "PUT", "/api/v1/logrules/nothing", adminTok, quiet); rec.Code != 404 {
		t.Errorf("changing an unknown rule: %d", rec.Code)
	}
	rules.Round(ctx)
	if n := alerts.ActiveCount("", nil); n != 0 {
		t.Errorf("%d alerts with the limit out of reach", n)
	}
	if rec := do(s, "DELETE", "/api/v1/logrules/"+saved.ID, teamTok, ""); rec.Code != 403 {
		t.Errorf("an operator removed a log rule: %d", rec.Code)
	}
	if rec := do(s, "DELETE", "/api/v1/logrules/"+saved.ID, adminTok, ""); rec.Code != 200 {
		t.Errorf("remove: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "DELETE", "/api/v1/logrules/"+saved.ID, adminTok, ""); rec.Code != 404 {
		t.Errorf("removed twice: %d", rec.Code)
	}

	// A server without log rules says so, and its alerts page has none.
	bare := New(Config{AgentTokens: map[string]string{agentTok: "prod"}, AdminToken: adminTok, StaleAfter: time.Minute,
		MaxPollWait: time.Second, CommandTimeout: time.Second, Alerts: alert.NewManager(time.Minute, log)}, store.New("prod"), log)
	if rec := do(bare, "GET", "/api/v1/logrules", adminTok, ""); rec.Code != 404 {
		t.Errorf("log rules on a server without them: %d", rec.Code)
	}
	var page map[string]json.RawMessage
	json.Unmarshal(do(bare, "GET", "/api/v1/alerts", adminTok, "").Body.Bytes(), &page)
	if string(page["logRules"]) != "null" {
		t.Errorf("the alerts page of a server without log rules has %s", page["logRules"])
	}
}
