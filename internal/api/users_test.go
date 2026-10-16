package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestUsersInTheUI(t *testing.T) {
	const adminTok, viewerTok = "admin-token-0123456789", "viewer-token-0123456789"
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, nil)
	accts := accounts.New(keeper, []auth.User{{Name: "admin", Role: auth.Admin}, {Name: "script", Role: auth.Viewer}})
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"},
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
		AdminToken: adminTok,
		Users:      map[string]auth.User{viewerTok: {Name: "script", Role: auth.Viewer}},
		Login:      auth.Chain{accts}, Accounts: accts,
	}, store.New("demo"), slog.New(slog.NewTextHandler(io.Discard, nil)))

	methods := func() string { return do(s, "GET", "/api/v1/login", "", "").Body.String() }
	if !strings.Contains(methods(), `"password":false`) {
		t.Errorf("before any user, the sign-in page should ask for a token: %s", methods())
	}
	add := `{"name":"ali","grant":"operator@demo/team-a","password":"dogru-parola-1"}`
	if rec := do(s, "POST", "/api/v1/users", viewerTok, add); rec.Code != 403 {
		t.Errorf("a viewer added a user: %d", rec.Code)
	}
	if rec := do(s, "POST", "/api/v1/users", adminTok, add); rec.Code != 201 || strings.Contains(rec.Body.String(), "hash") {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "POST", "/api/v1/users", adminTok, `{"name":"Admin","grant":"viewer","password":"dogru-parola-1"}`); rec.Code != 400 {
		t.Errorf("a fixed user's name was taken: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(methods(), `"password":true`) {
		t.Errorf("with a user, the sign-in page should ask for a password: %s", methods())
	}
	login := func(password string) (int, string) {
		rec := do(s, "POST", "/api/v1/login", "", `{"username":"ali","password":"`+password+`"}`)
		var got struct{ Token string }
		json.Unmarshal(rec.Body.Bytes(), &got)
		return rec.Code, got.Token
	}
	code, ses := login("dogru-parola-1")
	if code != 200 {
		t.Fatalf("sign in: %d", code)
	}
	if rec := do(s, "GET", "/api/v1/me", ses, ""); !strings.Contains(rec.Body.String(), `"ownPassword":true`) || !strings.Contains(rec.Body.String(), `"namespace":"team-a"`) {
		t.Errorf("me: %s", rec.Body)
	}
	if rec := do(s, "GET", "/api/v1/users", ses, ""); rec.Code != 403 {
		t.Errorf("an operator listed the users: %d", rec.Code)
	}
	if rec := do(s, "POST", "/api/v1/me/password", ses, `{"current":"yanlis-parola","password":"yeni-parola-22"}`); rec.Code != 403 {
		t.Errorf("own change with a wrong password: %d", rec.Code)
	}
	if rec := do(s, "POST", "/api/v1/me/password", ses, `{"current":"dogru-parola-1","password":"yeni-parola-22"}`); rec.Code != 204 {
		t.Fatalf("own change: %d %s", rec.Code, rec.Body)
	}
	if code, _ := login("yeni-parola-22"); code != 200 {
		t.Errorf("sign in with the new password: %d", code)
	}
	if rec := do(s, "POST", "/api/v1/me/password", viewerTok, `{"current":"x","password":"yeni-parola-22"}`); rec.Code != 400 {
		t.Errorf("a token user changed a password kept elsewhere: %d", rec.Code)
	}
	// A change ends the user's sessions, so the new grant applies at once.
	if rec := do(s, "PUT", "/api/v1/users/ali", adminTok, `{"grant":"viewer"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"viewer"`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "GET", "/api/v1/me", ses, ""); rec.Code != 401 {
		t.Errorf("a session outlived the change: %d", rec.Code)
	}
	rec := do(s, "GET", "/api/v1/users", adminTok, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"ali"`) || !strings.Contains(rec.Body.String(), `"name":"script"`) || strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "DELETE", "/api/v1/users/ali", adminTok, ""); rec.Code != 200 {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if code, _ := login("yeni-parola-22"); code != 401 {
		t.Errorf("a removed user signed in: %d", code)
	}
	if rec := do(s, "GET", "/api/v1/audit", adminTok, ""); !strings.Contains(rec.Body.String(), "add-user") || !strings.Contains(rec.Body.String(), "remove-user") {
		t.Errorf("audit: %s", rec.Body)
	}
}
