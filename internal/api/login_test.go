package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/ldap"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestPasswordSignIn(t *testing.T) {
	dir := &ldap.Fake{Domain: "example.org", People: map[string]ldap.FakePerson{
		"ali":   {Password: "pass", Groups: []string{"CN=Team-A,OU=Groups,DC=example,DC=org"}},
		"guest": {Password: "guest"},
	}}
	url, err := dir.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	rules, _ := ldap.ParseRules("Team-A => operator@demo/team-a")
	// No token users: with password sign-in on, nobody is let in anonymously.
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"},
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
		Login: ldap.Authenticator{Config: ldap.Config{URL: url, UPNDomain: "example.org", UserBase: "DC=example,DC=org"}, Rules: rules},
	}, store.New("demo"), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if rec := do(s, "GET", "/api/v1/clusters", "", ""); rec.Code != 401 {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if rec := do(s, "GET", "/api/v1/login", "", ""); !strings.Contains(rec.Body.String(), `"password":true`) {
		t.Errorf("methods: %s", rec.Body)
	}
	if rec := do(s, "POST", "/api/v1/login", "", `{"username":"ali","password":"nope"}`); rec.Code != 401 {
		t.Errorf("wrong password: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "POST", "/api/v1/login", "", `{"username":"guest","password":"guest"}`); rec.Code != 403 {
		t.Errorf("in no allowed group: %d %s", rec.Code, rec.Body)
	}
	rec := do(s, "POST", "/api/v1/login", "", `{"username":"ali","password":"pass"}`)
	var got struct{ Token, Name, Role string }
	json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || !strings.HasPrefix(got.Token, "kgs_") || got.Name != "ali" || got.Role != "operator" {
		t.Fatalf("sign in: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "GET", "/api/v1/me", got.Token, ""); !strings.Contains(rec.Body.String(), `"namespace":"team-a"`) {
		t.Errorf("me: %s", rec.Body)
	}
	if rec := do(s, "GET", "/api/v1/audit", got.Token, ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "sign-in") {
		// Sign-ins are the server's business: only operators over everything see them.
		t.Errorf("audit for a scoped operator: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "POST", "/api/v1/logout", got.Token, ""); rec.Code != 204 {
		t.Errorf("logout: %d", rec.Code)
	}
	if rec := do(s, "GET", "/api/v1/me", got.Token, ""); rec.Code != 401 {
		t.Errorf("a signed-out session still works: %d", rec.Code)
	}

	// Guessing: after five wrong passwords, even the right one waits.
	for i := 0; i < 5; i++ {
		do(s, "POST", "/api/v1/login", "", `{"username":"ALI","password":"guess"}`)
	}
	if rec := do(s, "POST", "/api/v1/login", "", `{"username":"ali","password":"pass"}`); rec.Code != 429 {
		t.Errorf("after five wrong passwords: %d %s", rec.Code, rec.Body)
	}
}

func TestThrottle(t *testing.T) {
	var th throttle
	now := time.Now()
	for i := 0; i < nameFailures; i++ {
		th.failed("a", now)
	}
	if th.wait("a", now) <= 0 || th.wait("b", now) != 0 {
		t.Error("the name should wait, another not")
	}
	if th.wait("a", now.Add(nameWindow)) != 0 {
		t.Error("failures should age out")
	}
	for i := 0; i < allFailures; i++ {
		th.failed("x"+string(rune('a'+i%26)), now)
	}
	if th.wait("fresh", now) <= 0 {
		t.Error("too many failures overall should slow everyone down")
	}
}

func TestAccountKey(t *testing.T) {
	for _, name := range []string{"ayse", " AYSE ", `EXAMPLE\Ayse`, "ayse@example.org"} {
		if got := accountKey(name); got != "ayse" {
			t.Errorf("%q: %q", name, got)
		}
	}
}
