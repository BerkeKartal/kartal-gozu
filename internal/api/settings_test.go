package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func newSettingsServer(t *testing.T) (*Server, *alert.Manager) {
	t.Helper()
	email := alert.NewSwitchable("email")
	alerts := alert.NewManager(time.Minute, nil, email)
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"},
		Users: map[string]auth.User{
			viewerTok:   {Name: "ekip", Role: auth.Viewer},
			operatorTok: {Name: "nobet", Role: auth.Operator},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
		Alerts: alerts,
		Mail:   settings.NewMail(settings.NewKeeper(context.Background(), settings.Memory{}, nil), email, nil),
	}, store.New("demo"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	return s, alerts
}

func TestEmailSettings(t *testing.T) {
	s, alerts := newSettingsServer(t)
	const path = "/api/v1/settings/email"
	body := `{"enabled":true,"addr":"smtp.example.org:587","from":"kartal@example.org","to":["ops@example.org"],"username":"k","password":"TOPSECRET"}`

	// Only admins see or change them.
	for _, tok := range []string{viewerTok, operatorTok} {
		if rec := do(s, "GET", path, tok, ""); rec.Code != 403 {
			t.Errorf("GET as %s: %d", tok, rec.Code)
		}
		if rec := do(s, "PUT", path, tok, body); rec.Code != 403 {
			t.Errorf("PUT as %s: %d", tok, rec.Code)
		}
		if rec := do(s, "POST", path+"/test", tok, body); rec.Code != 403 {
			t.Errorf("test as %s: %d", tok, rec.Code)
		}
	}

	if rec := do(s, "PUT", path, adminTok, `{"enabled":true,"addr":"nope"}`); rec.Code != 400 {
		t.Errorf("bad settings: %d %s", rec.Code, rec.Body)
	}
	rec := do(s, "PUT", path, adminTok, body)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "TOPSECRET") {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	var v settings.View
	json.Unmarshal(do(s, "GET", path, adminTok, "").Body.Bytes(), &v)
	if !v.Enabled || !v.PasswordSet || v.Where != "" || v.To[0] != "ops@example.org" {
		t.Errorf("view: %+v", v)
	}
	if ch := alerts.Channels(); len(ch) != 1 || ch[0] != "email" {
		t.Errorf("the e-mail channel is not on: %v", ch)
	}

	// Nobody listens on port 1: the test fails, as a bad server would.
	test := `{"enabled":true,"addr":"127.0.0.1:1","from":"kartal@example.org","to":["ops@example.org"]}`
	if rec := do(s, "POST", path+"/test", adminTok, test); rec.Code != 502 {
		t.Errorf("test against nothing: %d %s", rec.Code, rec.Body)
	}

	var entries []AuditEntry
	json.Unmarshal(do(s, "GET", "/api/v1/audit", adminTok, "").Body.Bytes(), &entries)
	if len(entries) != 2 || entries[0].Action != "test-email" || entries[0].OK || entries[1].Action != "email-settings" ||
		!entries[1].OK || strings.Contains(entries[1].Detail, "TOPSECRET") {
		t.Errorf("audit: %+v", entries)
	}
}

func TestEmailSettingsNeedTheFeature(t *testing.T) {
	_, s := newRoleServer()
	if rec := do(s, "GET", "/api/v1/settings/email", adminTok, ""); rec.Code != 404 {
		t.Errorf("without Mail: %d", rec.Code)
	}
}
