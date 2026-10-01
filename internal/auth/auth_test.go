package auth

import (
	"strings"
	"testing"
)

func TestParseUsers(t *testing.T) {
	users, err := ParseUsers("ozan:admin:aaaaaaaaaaaaaaaa1\n# comment\nekip:viewer:bbbbbbbbbbbbbbbb2, nobet : operator : cccccccccccccccc3\n" +
		"takim:operator@production/team-a+staging/*:dddddddddddddddd4")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDirectory(users)
	for token, want := range map[string]struct {
		name string
		role Role
	}{
		"aaaaaaaaaaaaaaaa1": {"ozan", Admin},
		"bbbbbbbbbbbbbbbb2": {"ekip", Viewer},
		"cccccccccccccccc3": {"nobet", Operator},
		"dddddddddddddddd4": {"takim", Operator},
	} {
		if got, ok := d.Lookup(token); !ok || got.Name != want.name || got.Role != want.role {
			t.Errorf("%s: got %+v %v, want %+v", token, got, ok, want)
		}
	}
	if u, _ := d.Lookup("dddddddddddddddd4"); u.RoleIn("production", "team-b") != 0 || u.RoleIn("staging", "x") != Operator {
		t.Errorf("scoped user: %+v", u)
	}
	if _, ok := d.Lookup("aaaaaaaaaaaaaaaa"); ok {
		t.Error("a prefix of a token was accepted")
	}
}

func TestParseUsersRejects(t *testing.T) {
	for _, raw := range []string{
		"ozan:admin",                  // no token
		"ozan:root:aaaaaaaaaaaaaaaa1", // unknown role
		"ozan:admin:short",            // short token
		"a:viewer:aaaaaaaaaaaaaaaa1,a:admin:bbbbbbbbbbbbbbbb2", // duplicate name
		"a:viewer:aaaaaaaaaaaaaaaa1,b:admin:aaaaaaaaaaaaaaaa1", // shared token
		"a:viewer@prod/team a:aaaaaaaaaaaaaaaa1",               // bad scope
		"a:viewer@:aaaaaaaaaaaaaaaa1",                          // empty scope
	} {
		if _, err := ParseUsers(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		} else if strings.Contains(err.Error(), "aaaaaaaaaaaaaaaa1") {
			t.Errorf("error reveals a token: %v", err)
		}
	}
}

func TestOpenDirectory(t *testing.T) {
	u, ok := NewDirectory(nil).Lookup("")
	if !ok || u.Role != Admin || u.Everywhere() != Admin {
		t.Errorf("an empty directory should let everyone in as admin: %+v", u)
	}
}

func TestScopes(t *testing.T) {
	grant := func(s string) Grant {
		g, err := ParseGrant(s)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	u := NewUser("ayse", []Grant{
		grant("viewer@production/*"),
		grant("operator@production/team-a+staging/team-*"),
		grant("admin@lab"),
	})
	for _, c := range []struct {
		cluster, ns string
		want        Role
	}{
		{"production", "team-a", Operator},
		{"production", "team-b", Viewer},
		{"production", "", Viewer}, // the whole cluster: from production/*
		{"staging", "team-x", Operator},
		{"staging", "other", 0},
		{"staging", "", 0}, // team-* is not every namespace
		{"lab", "", Admin},
		{"lab", "any", Admin},
		{"prod", "team-a", 0},
	} {
		if got := u.RoleIn(c.cluster, c.ns); got != c.want {
			t.Errorf("RoleIn(%q, %q) = %v, want %v", c.cluster, c.ns, got, c.want)
		}
	}
	if u.Role != Admin || u.RoleSomewhere("staging") != Operator || u.RoleSomewhere("dev") != 0 || u.Everywhere() != 0 {
		t.Errorf("role %v, staging %v, dev %v, everywhere %v", u.Role, u.RoleSomewhere("staging"), u.RoleSomewhere("dev"), u.Everywhere())
	}
	if g := grant("operator@*/*"); NewUser("x", []Grant{g}).Everywhere() != Operator || g.String() != "operator@*/*" {
		t.Errorf("*/* is everywhere: %v", g)
	}
	if NewUser("nobody", nil).RoleSomewhere("production") != 0 {
		t.Error("a user without grants got a role")
	}
}
