package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

func TestWithProjectRole(t *testing.T) {
	for _, c := range []struct {
		in   []string
		role auth.Role
		want string
	}{
		// Added next to what there is.
		{[]string{"viewer@production/payments"}, auth.Operator, "viewer@production/payments | operator@registry:team-a"},
		// Changed: the old grant of the project goes.
		{[]string{"viewer@registry:team-a"}, auth.Admin, "admin@registry:team-a"},
		// One scope of several: the others stay in their grant.
		{[]string{"operator@production/payments+registry:team-a+registry:team-b"}, auth.Viewer,
			"operator@production/payments+registry:team-b | viewer@registry:team-a"},
		// Taken away; patterns and grants everywhere are not the project's own.
		{[]string{"admin", "viewer@registry:*", "operator@registry:team-*", "operator@registry:team-a"}, 0,
			"admin | viewer@registry:* | operator@registry:team-*"},
		// Another project of a like name is another project.
		{[]string{"operator@registry:team-ab"}, 0, "operator@registry:team-ab"},
		{nil, 0, ""},
	} {
		if got := strings.Join(withProjectRole(c.in, "team-a", c.role), " | "); got != c.want {
			t.Errorf("%v → %s: %q, want %q", c.in, c.role, got, c.want)
		}
	}
	if r := ProjectRoleOf([]string{"admin", "viewer@registry:*", "operator@production/x+registry:team-a"}, "team-a"); r != auth.Operator {
		t.Errorf("the project's own role: %v", r)
	}
	if r := ProjectRoleOf([]string{"admin", "admin@registry:*"}, "team-a"); r != 0 {
		t.Errorf("no grant of the project's own: %v", r)
	}
}

func TestSetProjectRoles(t *testing.T) {
	ctx := context.Background()
	m, _ := newManager()
	if _, err := m.Add(ctx, UserInput{Name: "ayse", Grants: []string{"operator@production/payments+registry:team-a"}, Password: "dogru-parola-1"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddGroup(ctx, GroupInput{Name: "devops", Grants: []string{"viewer@staging"}, Members: []string{"ayse"}}, "admin"); err != nil {
		t.Fatal(err)
	}
	e, err := m.SetUserProjectRole(ctx, "AYSE", "team-a", auth.Admin, "lead")
	if err != nil || strings.Join(e.Grants, " | ") != "operator@production/payments | admin@registry:team-a" || e.ChangedBy != "lead" {
		t.Fatalf("a user's role: %+v %v", e, err)
	}
	// What the user signs in with follows.
	u, err := m.Login(ctx, "ayse", "dogru-parola-1")
	if err != nil || u.RoleInProject("team-a") != auth.Admin || u.RoleIn("production", "payments") != auth.Operator || u.RoleIn("staging", "x") != auth.Viewer {
		t.Fatalf("after: %+v %v", u, err)
	}
	if e, err := m.SetUserProjectRole(ctx, "ayse", "team-a", 0, "lead"); err != nil || strings.Join(e.Grants, " | ") != "operator@production/payments" {
		t.Fatalf("taken away: %+v %v", e, err)
	}
	before, after, err := m.SetGroupProjectRole(ctx, "devops", "team-a", auth.Viewer, "lead")
	if err != nil || strings.Join(before.Grants, " | ") != "viewer@staging/*" || strings.Join(after.Grants, " | ") != "viewer@staging/* | viewer@registry:team-a" {
		t.Fatalf("a group's role: %+v %+v %v", before, after, err)
	}
	if _, err := m.SetUserProjectRole(ctx, "nobody", "team-a", auth.Viewer, "lead"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no such user: %v", err)
	}
	if _, _, err := m.SetGroupProjectRole(ctx, "nobody", "team-a", auth.Viewer, "lead"); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("no such group: %v", err)
	}
	// The most grants there may be holds here too.
	many := []string{}
	for i := 0; i < MaxGrants; i++ {
		many = append(many, "viewer@c"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+"/ns"+string(rune('a'+i/26)))
	}
	if _, err := m.Update(ctx, "ayse", UserInput{Grants: many}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetUserProjectRole(ctx, "ayse", "team-a", auth.Viewer, "lead"); err == nil {
		t.Error("one grant more than the most there may be")
	}
}
