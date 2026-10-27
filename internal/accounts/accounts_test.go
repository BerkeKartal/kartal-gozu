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

func ptr[T any](v T) *T { return &v }

func TestAccounts(t *testing.T) {
	ctx := context.Background()
	m, k := newManager()
	e, err := m.Add(ctx, UserInput{Name: "ali", Grants: []string{"operator@production/payments"}, Password: "dogru-parola-1"}, "admin")
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
	// New grants, then a new password; the other stays.
	if e, err = m.Update(ctx, "ali", UserInput{Grants: []string{"admin"}}, "admin"); err != nil || e.Role != "admin" || e.ChangedBy != "admin" {
		t.Fatalf("update grant: %+v %v", e, err)
	}
	if _, err := m.Login(ctx, "ali", "dogru-parola-1"); err != nil {
		t.Errorf("the password changed with the grant: %v", err)
	}
	if _, err := m.Update(ctx, "ali", UserInput{Password: "yeni-parola-22"}, "admin"); err != nil {
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
	// No one locks themselves out.
	var invalid *settings.InvalidError
	if _, err := m.Update(ctx, "ali", UserInput{Disabled: ptr(true)}, "ALI"); !errors.As(err, &invalid) {
		t.Errorf("disabling oneself: %v", err)
	}
	if _, err := m.Remove(ctx, "ali", "Ali"); !errors.As(err, &invalid) {
		t.Errorf("removing oneself: %v", err)
	}
	if _, err := m.Remove(ctx, "Ali", "admin"); err != nil {
		t.Fatal(err)
	}
	if m.Count() != 0 || m.Has("ali") {
		t.Error("removed user still there")
	}
	if _, err := m.Remove(ctx, "ali", "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing twice: %v", err)
	}
}

func TestAccountsRejects(t *testing.T) {
	ctx := context.Background()
	m, _ := newManager()
	if _, err := m.Add(ctx, UserInput{Name: "ali", Grants: []string{"viewer"}, Password: "dogru-parola-1"}, "admin"); err != nil {
		t.Fatal(err)
	}
	var invalid *settings.InvalidError
	for _, c := range []UserInput{
		{Name: "ALI", Grants: []string{"viewer"}, Password: "dogru-parola-1"},   // taken, in another case
		{Name: "Admin", Grants: []string{"viewer"}, Password: "dogru-parola-1"}, // a user the server was started with
		{Name: "veli", Grants: []string{"root"}, Password: "dogru-parola-1"},    // no such role
		{Name: "veli", Grants: []string{"viewer"}, Password: "kisa"},            // short password
		{Name: "veli", Grants: []string{"viewer"}},                              // no password
		{Name: "ve li", Grants: []string{"viewer"}, Password: "dogru-parola-1"}, // a space
		{Name: "", Grants: []string{"viewer"}, Password: "dogru-parola-1"},      // no name
		{Name: "veli", Grants: []string{"viewer@"}, Password: "dogru-parola-1"}, // empty scope
		{Name: "veli", Password: "dogru-parola-1", Email: ptr("not an address")},
		{Name: "veli", Password: "dogru-parola-1", FullName: ptr("two\nlines")},
		{Name: "veli", Password: "dogru-parola-1", Groups: []string{"no-such-group"}},
	} {
		if _, err := m.Add(ctx, c, "admin"); !errors.As(err, &invalid) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if _, err := m.Update(ctx, "yok", UserInput{Grants: []string{"viewer"}}, "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("updating nobody: %v", err)
	}
	if fixed := m.Fixed(); len(fixed) != 1 || fixed[0].Name != "admin" || fixed[0].Role != "admin" || fixed[0].Grants[0] != "admin" {
		t.Errorf("fixed: %+v", fixed)
	}
}

// A user saved before there could be several grants keeps theirs, and has
// it folded into the list at their next change.
func TestOldSingleGrant(t *testing.T) {
	ctx := context.Background()
	m, k := newManager()
	h, _ := auth.HashPassword("dogru-parola-1")
	k.Update(ctx, func(s *settings.Settings) error {
		s.Users = append(s.Users, settings.User{Name: "eski", Grant: "operator@production/payments", Hash: h})
		return nil
	})
	if u, err := m.Login(ctx, "eski", "dogru-parola-1"); err != nil || u.RoleIn("production", "payments") != auth.Operator {
		t.Fatalf("login with the old grant: %+v %v", u, err)
	}
	if e := m.List()[0]; len(e.Grants) != 1 || e.Grants[0] != "operator@production/payments" {
		t.Errorf("list: %+v", e)
	}
	if _, err := m.Update(ctx, "eski", UserInput{Grants: []string{"viewer", "operator@production/payments"}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if u := k.Get().Users[0]; u.Grant != "" || len(u.Grants) != 2 {
		t.Errorf("after a change: %+v", u)
	}
}

func TestGroups(t *testing.T) {
	ctx := context.Background()
	m, _ := newManager()
	// A user with no grant of their own gets in through a group.
	if _, err := m.Add(ctx, UserInput{Name: "ayse", Password: "dogru-parola-1", FullName: ptr("Ayşe Yılmaz"), Email: ptr("ayse@example.org")}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login(ctx, "ayse", "dogru-parola-1"); !errors.Is(err, auth.ErrNoAccess) {
		t.Errorf("no grants anywhere: %v", err)
	}
	g, err := m.AddGroup(ctx, GroupInput{Name: "Payments team", Description: ptr("ödeme ekibi"),
		Grants:    []string{"operator@production/payments", "viewer@staging/*", "operator@production/payments"},
		Members:   []string{"Ayse", "bob.dir"},
		Directory: []string{"CN=Payments,OU=Groups,DC=example,DC=org"}}, "admin")
	if err != nil || len(g.Grants) != 2 || g.Role != "operator" {
		t.Fatalf("add group: %+v %v", g, err)
	}
	u, err := m.Login(ctx, "ayse", "dogru-parola-1")
	if err != nil || u.RoleIn("production", "payments") != auth.Operator || u.RoleIn("staging", "web") != auth.Viewer || u.RoleIn("production", "web") != 0 {
		t.Fatalf("login through the group: %+v %v", u, err)
	}
	if e := m.List()[0]; e.Role != "operator" || len(e.Groups) != 1 || e.Groups[0] != "Payments team" || e.FullName != "Ayşe Yılmaz" {
		t.Errorf("entry: %+v", e)
	}
	// Directory users: by name, or by a group's DN or CN.
	if gs := m.GroupGrants("BOB.DIR", nil); len(gs) != 2 {
		t.Errorf("by name: %+v", gs)
	}
	if gs := m.GroupGrants("carol", []string{"cn=payments, ou=groups, dc=example, dc=org"}); len(gs) != 2 {
		t.Errorf("by DN: %+v", gs)
	}
	if gs := m.GroupGrants("carol", []string{"CN=Other,DC=example,DC=org"}); len(gs) != 0 {
		t.Errorf("another group: %+v", gs)
	}
	reach := Reaches(g)
	if !reach(auth.User{Name: "ayse"}) || !reach(auth.User{Name: "x", Directory: []string{"CN=Payments,OU=Groups,DC=example,DC=org"}}) || reach(auth.User{Name: "x"}) {
		t.Error("Reaches")
	}
	// Membership from the user's side.
	if _, err := m.AddGroup(ctx, GroupInput{Name: "readers", Grants: []string{"viewer"}}, "admin"); err != nil {
		t.Fatal(err)
	}
	e, err := m.Update(ctx, "ayse", UserInput{Groups: []string{"readers"}}, "admin")
	if err != nil || len(e.Groups) != 1 || e.Groups[0] != "readers" || e.Role != "viewer" {
		t.Fatalf("set groups: %+v %v", e, err)
	}
	if gr := m.Groups(); gr[0].Name != "Payments team" || len(gr[0].Members) != 1 || gr[1].Members[0] != "ayse" {
		t.Errorf("groups after: %+v", gr)
	}
	// A disabled account is told only with the right password.
	if _, err := m.Update(ctx, "ayse", UserInput{Disabled: ptr(true)}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login(ctx, "ayse", "yanlis-parola-9"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("disabled, wrong password: %v", err)
	}
	if _, err := m.Login(ctx, "ayse", "dogru-parola-1"); !errors.Is(err, auth.ErrDisabled) {
		t.Errorf("disabled: %v", err)
	}
	// Removing a user takes them out of their groups.
	if _, err := m.Remove(ctx, "ayse", "admin"); err != nil {
		t.Fatal(err)
	}
	if gr := m.Groups(); len(gr[1].Members) != 0 || gr[1].ChangedBy != "admin" {
		t.Errorf("still a member: %+v", gr[1])
	}
	before, after, err := m.UpdateGroup(ctx, "PAYMENTS TEAM", GroupInput{Members: []string{}}, "admin")
	if err != nil || len(before.Members) != 1 || len(after.Members) != 0 || len(after.Grants) != 2 {
		t.Errorf("update group: %+v %+v %v", before, after, err)
	}
	if _, err := m.RemoveGroup(ctx, "readers"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RemoveGroup(ctx, "readers"); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("removing twice: %v", err)
	}
	var invalid *settings.InvalidError
	for _, c := range []GroupInput{
		{Name: "payments TEAM"},                                 // taken
		{Name: " "},                                             // no name
		{Name: "x", Grants: []string{"boss"}},                   // no such role
		{Name: "x", Members: []string{"two words"}},             // not a user name
		{Name: "x", Directory: []string{"CN=A\nCN=B"}},          // a line break
		{Name: "x", Description: ptr(strings.Repeat("a", 301))}, // too long
	} {
		if _, err := m.AddGroup(ctx, c, "admin"); !errors.As(err, &invalid) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// The users of KARTAL_USERS who sign in with a password get their groups'
// grants too; those with a token do not, and are not shown as if they did.
func TestWithGroups(t *testing.T) {
	ctx := context.Background()
	h, _ := auth.HashPassword("dogru-parola-1")
	tokens, passwords, err := auth.ParseUsers("zeynep:viewer@staging:" + h + "\nbot:viewer:0123456789abcdef0123")
	if err != nil {
		t.Fatal(err)
	}
	fixed := passwords.Users()
	for _, u := range tokens {
		fixed = append(fixed, u)
	}
	m := New(settings.NewKeeper(ctx, settings.Memory{}, nil), fixed)
	login := m.WithGroups(passwords)
	if _, err := m.AddGroup(ctx, GroupInput{Name: "ops", Grants: []string{"operator@production/*"}, Members: []string{"zeynep", "bot"}}, "admin"); err != nil {
		t.Fatal(err)
	}
	u, err := login.Login(ctx, "zeynep", "dogru-parola-1")
	if err != nil || u.RoleIn("staging", "a") != auth.Viewer || u.RoleIn("production", "a") != auth.Operator || u.Role != auth.Operator {
		t.Fatalf("%+v %v", u, err)
	}
	f := m.Fixed()
	if len(f) != 2 || f[0].Name != "bot" || len(f[0].Groups) != 0 || f[0].Password ||
		f[1].Name != "zeynep" || len(f[1].Groups) != 1 || !f[1].Password {
		t.Errorf("fixed: %+v", f)
	}
}
