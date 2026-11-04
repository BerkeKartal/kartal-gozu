package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/silence"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestSilences(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	team, _ := auth.ParseGrant("operator@prod/team-a")
	other, _ := auth.ParseGrant("operator@prod/team-b")
	clusterOp, _ := auth.ParseGrant("operator@prod/*")
	const otherTok, clusterTok = "other-token-0123456789", "cluster-token-0123456789"
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:    auth.NewUser("takim", []auth.Grant{team}),
			otherTok:   auth.NewUser("diger", []auth.Grant{other}),
			clusterTok: auth.NewUser("kume", []auth.Grant{clusterOp}),
			viewerTok:  {Name: "ekip", Role: auth.Viewer},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Alerts:   alert.NewManager(time.Minute, log),
		Silences: silence.New(keeper),
	}, store.New("prod"), log)

	ends := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	window := `{"cluster": "prod", "namespace": "team-a", "comment": "deploy", "ends": "` + ends + `"}`
	if rec := do(s, "POST", "/api/v1/silences", viewerTok, window); rec.Code != 403 {
		t.Errorf("a viewer silenced: %d", rec.Code)
	}
	// An operator silences only what is theirs: their namespace, not
	// another's, the whole cluster, a pattern or every cluster.
	for _, c := range []struct{ tok, body string }{
		{otherTok, window},
		{teamTok, `{"cluster": "prod", "ends": "` + ends + `"}`},
		{teamTok, `{"cluster": "prod", "namespace": "team-*", "ends": "` + ends + `"}`},
		{clusterTok, `{"ends": "` + ends + `"}`},
	} {
		if rec := do(s, "POST", "/api/v1/silences", c.tok, c.body); rec.Code != 403 {
			t.Errorf("%s silenced %s: %d %s", c.tok, c.body, rec.Code, rec.Body)
		}
	}
	if rec := do(s, "POST", "/api/v1/silences", adminTok, `{"cluster": "nowhere", "ends": "`+ends+`"}`); rec.Code != 404 {
		t.Errorf("an unknown cluster: %d", rec.Code)
	}
	for _, bad := range []string{
		`{"cluster": "prod", "namespace": "team-a"}`,
		`{"cluster": "prod", "namespace": "team-a", "ends": "2020-01-01T00:00:00Z"}`,
		`{"cluster": "prod", "namespace": "team-a", "object": "a b", "ends": "` + ends + `"}`,
	} {
		if rec := do(s, "POST", "/api/v1/silences", teamTok, bad); rec.Code != 400 {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	rec := do(s, "POST", "/api/v1/silences", teamTok, window)
	if rec.Code != 201 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	var saved settings.Silence
	json.Unmarshal(rec.Body.Bytes(), &saved)
	if saved.By != "takim" || saved.ID == "" || saved.Starts.IsZero() {
		t.Fatalf("saved %+v", saved)
	}
	if rec := do(s, "POST", "/api/v1/silences", clusterTok, `{"cluster": "prod", "namespace": "team-*", "ends": "`+ends+`"}`); rec.Code != 201 {
		t.Fatalf("a cluster's operator, by a pattern: %d %s", rec.Code, rec.Body)
	}

	// Each sees the silences over what they see, on the alerts page too.
	count := func(tok, path string) int {
		var x struct{ Silences []settings.Silence }
		json.Unmarshal(do(s, "GET", path, tok, "").Body.Bytes(), &x)
		return len(x.Silences)
	}
	for tok, want := range map[string]int{teamTok: 2, otherTok: 1, viewerTok: 2, adminTok: 2} {
		if got := count(tok, "/api/v1/silences"); got != want {
			t.Errorf("%s sees %d silences, want %d", tok, got, want)
		}
		if got := count(tok, "/api/v1/alerts"); got != want {
			t.Errorf("%s sees %d silences with the alerts, want %d", tok, got, want)
		}
	}

	if rec := do(s, "DELETE", "/api/v1/silences/"+saved.ID, otherTok, ""); rec.Code != 403 {
		t.Errorf("another team ended it: %d", rec.Code)
	}
	if rec := do(s, "DELETE", "/api/v1/silences/"+saved.ID, clusterTok, ""); rec.Code != 200 {
		t.Errorf("the cluster's operator ended it: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "DELETE", "/api/v1/silences/"+saved.ID, teamTok, ""); rec.Code != 404 {
		t.Errorf("ended twice: %d", rec.Code)
	}
}
