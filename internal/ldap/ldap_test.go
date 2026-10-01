package ldap

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

func TestIntegers(t *testing.T) {
	for _, v := range []int{0, 1, 3, 127, 128, 255, 256, 500, 65535, 1 << 20, -1, -128, -129} {
		p, rest, err := parse(integer(tagInteger, v))
		if err != nil || len(rest) != 0 {
			t.Fatalf("%d: %v", v, err)
		}
		if got, err := p.int(); err != nil || got != v {
			t.Errorf("%d came back as %d (%v)", v, got, err)
		}
	}
}

const (
	admins = "CN=K8s-Admins,OU=Groups,DC=example,DC=org"
	teamA  = "CN=Team-A,OU=Groups,DC=example,DC=org"
)

func fakeDirectory(t *testing.T, serviceAccount bool) (*Fake, Config) {
	t.Helper()
	f := &Fake{Domain: "example.org", People: map[string]FakePerson{
		"ayse":  {Password: "s3cret", DisplayName: "Ayşe", Groups: []string{admins}},
		"ali":   {Password: "pass", DisplayName: "Ali", Groups: []string{teamA}},
		"guest": {Password: "guest", DisplayName: "Guest"},
		"old":   {Password: "old", DisplayName: "Old", Groups: []string{admins}, Refusal: "532"},
	}}
	if serviceAccount {
		f.BindDN, f.BindPassword = "CN=svc,DC=example,DC=org", "svcpass"
	}
	url, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	cfg := Config{URL: url, UserBase: "DC=example,DC=org", Timeout: 5 * time.Second}
	if serviceAccount {
		cfg.BindDN, cfg.BindPassword = f.BindDN, f.BindPassword
	} else {
		cfg.UPNDomain = f.Domain
	}
	return f, cfg
}

func TestAuthenticate(t *testing.T) {
	for _, sa := range []bool{false, true} {
		_, cfg := fakeDirectory(t, sa)
		ctx := context.Background()
		e, err := cfg.Authenticate(ctx, "ayse", "s3cret")
		if err != nil || e.DisplayName != "Ayşe" || len(e.Groups) != 1 || e.Groups[0] != admins {
			t.Fatalf("service account %v: %+v %v", sa, e, err)
		}
		for _, c := range []struct{ user, password string }{
			{"ayse", "wrong"},
			{"nobody", "s3cret"},
			{"ayse", ""}, // an anonymous bind must not sign anyone in
			{"", ""},
		} {
			if _, err := cfg.Authenticate(ctx, c.user, c.password); !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("service account %v, %q/%q: %v", sa, c.user, c.password, err)
			}
		}
	}
	// A wrong service account password is the server's problem, not the
	// user's: it is not reported as a wrong password.
	_, cfg := fakeDirectory(t, true)
	cfg.BindPassword = "nope"
	if _, err := cfg.Authenticate(context.Background(), "ayse", "s3cret"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("service account refused: %v", err)
	}
}

func TestRules(t *testing.T) {
	rules, err := ParseRules("CN=k8s-admins, OU=Groups, DC=example, DC=org => admin\n# comment\nTeam-A => operator@production/team-a;")
	if err != nil {
		t.Fatal(err)
	}
	g := Grants(rules, []string{admins, teamA})
	if len(g) != 2 || g[0].Role != auth.Admin || g[1].String() != "operator@production/team-a" {
		t.Errorf("grants: %+v", g)
	}
	if g := Grants(rules, []string{"CN=Other,DC=example,DC=org"}); len(g) != 0 {
		t.Errorf("an unknown group got %+v", g)
	}
	for _, bad := range []string{"no arrow", "=> admin", "Team-A => root"} {
		if _, err := ParseRules(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestAuthenticator(t *testing.T) {
	_, cfg := fakeDirectory(t, false)
	rules, _ := ParseRules("K8s-Admins => admin\nTeam-A => operator@production/team-a")
	a := Authenticator{Config: cfg, Rules: rules}
	u, err := a.Login(context.Background(), "ali", "pass")
	if err != nil || u.Name != "ali" || u.RoleIn("production", "team-a") != auth.Operator || u.RoleIn("production", "team-b") != 0 {
		t.Errorf("ali: %+v %v", u, err)
	}
	if _, err := a.Login(context.Background(), "guest", "guest"); !errors.Is(err, ErrNoAccess) {
		t.Errorf("someone in no allowed group: %v", err)
	}
}

func TestSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	cfg := Config{URL: "ldap://" + ln.Addr().String(), UPNDomain: "example.org", UserBase: "DC=x", Timeout: 300 * time.Millisecond}
	start := time.Now()
	if _, err := cfg.Authenticate(context.Background(), "a", "b"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}
	if _, err := (Config{URL: "http://x"}).Authenticate(context.Background(), "a", "b"); err == nil || !strings.Contains(err.Error(), "ldap://") {
		t.Errorf("bad URL: %v", err)
	}
}

func TestHowPeopleWriteTheirName(t *testing.T) {
	for _, sa := range []bool{false, true} {
		_, cfg := fakeDirectory(t, sa)
		for _, name := range []string{"ayse", "AYSE", `EXAMPLE\ayse`, "ayse@example.org", " Ayse@EXAMPLE.org "} {
			e, err := cfg.Authenticate(context.Background(), name, "s3cret")
			if err != nil || e.Name != "ayse" {
				t.Errorf("service account %v, %q: %+v %v", sa, name, e, err)
			}
		}
	}
}

func TestAccountRefusals(t *testing.T) {
	for _, sa := range []bool{false, true} {
		_, cfg := fakeDirectory(t, sa)
		// With the right password, Active Directory says why; it counts as a
		// refused sign-in all the same.
		_, err := cfg.Authenticate(context.Background(), "old", "old")
		if !errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "expired") {
			t.Errorf("service account %v, expired password: %v", sa, err)
		}
		if _, err := cfg.Authenticate(context.Background(), "old", "wrong"); err != ErrInvalidCredentials {
			t.Errorf("service account %v, wrong password: %v", sa, err)
		}
	}
}
