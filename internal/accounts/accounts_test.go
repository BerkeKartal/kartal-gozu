package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

func newManager() (*Manager, *settings.Keeper) {
	k := settings.NewKeeper(context.Background(), settings.Memory{}, nil)
	return New(k, []auth.User{{Name: "admin", Role: auth.Admin}}), k
}

func TestAccounts(t *testing.T) {
	ctx := context.Background()
	m, k := newManager()
	e, err := m.Add(ctx, "ali", "operator@production/payments", "dogru-parola-1", "admin")
	if err != nil || e.Role != "operator" || e.By != "admin" {
		t.Fatalf("add: %+v %v", e, err)
	}
	if strings.Contains(k.Get().Users[0].Hash, "dogru") || !auth.IsPasswordHash(k.Get().Users[0].Hash) {
		t.Fatal("the password is not kept as a hash")
	}
	u, err := m.Login(ctx, "ALI", "dogru-parola-1")
	if err != nil || u.Name != "ali" || u.RoleIn("production", "payments") != auth.Operator || u.RoleIn("production", "x") != 0 {
		t.Fatalf("login: %+v %v", u, err)
	}
	for _, c := range [][2]string{{"ali", "yanlis-parola-1"}, {"veli", "dogru-parola-1"}} {
		if _, err := m.Login(ctx, c[0], c[1]); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: %v", c[0], err)
		}
	}
	// A new grant, then a new password; the other stays.
	if e, err = m.Update(ctx, "ali", "admin", "", "admin"); err != nil || e.Role != "admin" || e.ChangedBy != "admin" {
		t.Fatalf("update grant: %+v %v", e, err)
	}
	if _, err := m.Login(ctx, "ali", "dogru-parola-1"); err != nil {
		t.Errorf("the password changed with the grant: %v", err)
	}
	if _, err := m.Update(ctx, "ali", "", "yeni-parola-22", "admin"); err != nil {
		t.Fatal(err)
	}
	if u, err := m.Login(ctx, "ali", "yeni-parola-22"); err != nil || u.Role != auth.Admin {
		t.Errorf("after the new password: %+v %v", u, err)
	}
	// One's own password needs the current one.
	if err := m.ChangeOwn(ctx, "ali", "yanlis", "baska-parola-33"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("own change with a wrong password: %v", err)
	}
	if err := m.ChangeOwn(ctx, "ali", "yeni-parola-22", "baska-parola-33"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login(ctx, "ali", "baska-parola-33"); err != nil {
		t.Errorf("after the own change: %v", err)
	}
	if _, err := m.Remove(ctx, "Ali"); err != nil {
		t.Fatal(err)
	}
	if m.Count() != 0 || m.Has("ali") {
		t.Error("removed user still there")
	}
	if _, err := m.Remove(ctx, "ali"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing twice: %v", err)
	}
}

func TestAccountsRejects(t *testing.T) {
	ctx := context.Background()
	m, _ := newManager()
	if _, err := m.Add(ctx, "ali", "viewer", "dogru-parola-1", "admin"); err != nil {
		t.Fatal(err)
	}
	var invalid *settings.InvalidError
	for _, c := range []struct{ name, grant, password string }{
		{"ALI", "viewer", "dogru-parola-1"},   // taken, in another case
		{"Admin", "viewer", "dogru-parola-1"}, // a user the server was started with
		{"veli", "root", "dogru-parola-1"},    // no such role
		{"veli", "viewer", "kisa"},            // short password
		{"ve li", "viewer", "dogru-parola-1"}, // a space
		{"", "viewer", "dogru-parola-1"},      // no name
		{"veli", "viewer@", "dogru-parola-1"}, // empty scope
	} {
		if _, err := m.Add(ctx, c.name, c.grant, c.password, "admin"); !errors.As(err, &invalid) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if _, err := m.Update(ctx, "yok", "viewer", "", "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("updating nobody: %v", err)
	}
	if fixed := m.Fixed(); len(fixed) != 1 || fixed[0].Name != "admin" || fixed[0].Role != "admin" {
		t.Errorf("fixed: %+v", fixed)
	}
}
