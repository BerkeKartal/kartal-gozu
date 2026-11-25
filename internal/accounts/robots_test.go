package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

func TestRobots(t *testing.T) {
	m, k := newManager()
	ctx := context.Background()
	// A robot's grants are the registry's only.
	for _, grants := range [][]string{nil, {}, {"admin"}, {"operator@production/team-a"}, {"operator@registry:team-a+production/x"}} {
		if _, _, err := m.AddRobot(ctx, RobotInput{Name: "ci", Grants: grants}, "admin"); err == nil {
			t.Errorf("grants %v taken", grants)
		}
	}
	if _, _, err := m.AddRobot(ctx, RobotInput{Name: "Bad Name", Grants: []string{"viewer@registry:x"}}, "admin"); err == nil {
		t.Error("a bad name taken")
	}
	e, secret, err := m.AddRobot(ctx, RobotInput{Name: "robot$ci", Grants: []string{"operator@registry:team-a", "viewer@registry:shared-*"}}, "admin")
	if err != nil || e.Name != "ci" || e.Login != "robot$ci" || !strings.HasPrefix(secret, "kgr_") || len(secret) != 68 {
		t.Fatalf("add: %+v %q %v", e, secret, err)
	}
	if strings.Contains(k.Get().Robots[0].Hash, secret[4:20]) {
		t.Fatal("the secret is kept, not its digest")
	}
	if _, _, err := m.AddRobot(ctx, RobotInput{Name: "ci", Grants: []string{"viewer@registry:x"}}, "admin"); err == nil {
		t.Error("the same name twice")
	}
	u, ok := m.CheckRobot("robot$ci", secret)
	if !ok || u.Name != "robot$ci" || u.RoleInProject("team-a") != auth.Operator || u.RoleInProject("shared-tools") != auth.Viewer ||
		u.RoleInProject("team-b") != 0 || u.ClusterRole() != 0 {
		t.Fatalf("check: %+v %v", u, ok)
	}
	for _, c := range [][2]string{{"robot$ci", "kgr_wrong"}, {"ci", secret}, {"robot$other", secret}} {
		if _, ok := m.CheckRobot(c[0], c[1]); ok {
			t.Errorf("%s signed in", c[0])
		}
	}
	// A rotated secret replaces the old one at once.
	_, fresh, err := m.RotateRobot(ctx, "ci", "admin")
	if err != nil || fresh == secret {
		t.Fatal(err)
	}
	if _, ok := m.CheckRobot("robot$ci", secret); ok {
		t.Error("the old secret still works")
	}
	if _, ok := m.CheckRobot("robot$ci", fresh); !ok {
		t.Error("the new secret does not work")
	}
	// Disabled, then expired.
	yes, past := true, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, after, err := m.UpdateRobot(ctx, "ci", RobotInput{Disabled: &yes}, "admin"); err != nil || !after.Disabled || after.ChangedBy != "admin" {
		t.Fatalf("disable: %+v %v", after, err)
	}
	if _, ok := m.CheckRobot("robot$ci", fresh); ok {
		t.Error("a disabled robot signed in")
	}
	no := false
	if _, after, err := m.UpdateRobot(ctx, "ci", RobotInput{Disabled: &no, Expires: &past}, "admin"); err != nil || !after.Expired {
		t.Fatalf("expire: %+v %v", after, err)
	}
	if _, ok := m.CheckRobot("robot$ci", fresh); ok {
		t.Error("an expired robot signed in")
	}
	never := ""
	if _, after, _ := m.UpdateRobot(ctx, "ci", RobotInput{Expires: &never}, "admin"); after.Expires != nil {
		t.Error("the expiry was not cleared")
	}
	if _, _, err := m.UpdateRobot(ctx, "nobody", RobotInput{}, "admin"); !errors.Is(err, ErrRobotNotFound) {
		t.Errorf("a missing robot: %v", err)
	}
	if list := m.Robots(); len(list) != 1 || len(list[0].Grants) != 2 {
		t.Errorf("list: %+v", list)
	}
	if _, err := m.RemoveRobot(ctx, "ci"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.CheckRobot("robot$ci", fresh); ok || len(m.Robots()) != 0 {
		t.Error("the robot is still there")
	}
}
