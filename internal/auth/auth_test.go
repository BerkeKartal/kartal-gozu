package auth

import (
	"strings"
	"testing"
)

func TestParseUsers(t *testing.T) {
	users, err := ParseUsers("ozan:admin:aaaaaaaaaaaaaaaa1\n# comment\nekip:viewer:bbbbbbbbbbbbbbbb2, nobet : operator : cccccccccccccccc3")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDirectory(users)
	for token, want := range map[string]User{
		"aaaaaaaaaaaaaaaa1": {"ozan", Admin},
		"bbbbbbbbbbbbbbbb2": {"ekip", Viewer},
		"cccccccccccccccc3": {"nobet", Operator},
	} {
		if got, ok := d.Lookup(token); !ok || got != want {
			t.Errorf("%s: got %+v %v, want %+v", token, got, ok, want)
		}
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
	if !ok || u.Role != Admin {
		t.Errorf("an empty directory should let everyone in as admin: %+v", u)
	}
}
