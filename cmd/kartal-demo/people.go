package main

import (
	"context"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
)

// seedRegistryPeople gives the demo's registry projects members: two
// users of the UI, a group and a robot account, each with roles in some
// projects, as a team would have them. What is there already stays.
func seedRegistryPeople(ctx context.Context, m *accounts.Manager) error {
	users := []accounts.UserInput{
		{Name: "ayse", FullName: ptr("Ayşe Yılmaz"), Password: "ayse-demo-password",
			Grants: []string{"viewer@production/team-0", "admin@registry:team-0"}},
		{Name: "mert", FullName: ptr("Mert Kaya"), Password: "mert-demo-password",
			Grants: []string{"operator@registry:team-0"}},
	}
	for _, u := range users {
		if m.Has(u.Name) {
			continue
		}
		if _, err := m.Add(ctx, u, "demo"); err != nil {
			return err
		}
	}
	have := map[string]bool{}
	for _, g := range m.Groups() {
		have[strings.ToLower(g.Name)] = true
	}
	if !have["qa"] {
		desc := "Testers: they pull the releases"
		if _, err := m.AddGroup(ctx, accounts.GroupInput{Name: "qa", Description: &desc, Grants: []string{"viewer@registry:releases"},
			Members: []string{"mert"}}, "demo"); err != nil {
			return err
		}
	}
	for _, r := range m.Robots() {
		if r.Name == "ci" {
			return nil
		}
	}
	desc := "CI pushes team-0's images"
	_, _, err := m.AddRobot(ctx, accounts.RobotInput{Name: "ci", Description: &desc, Grants: []string{"operator@registry:team-0"}}, "demo")
	return err
}

func ptr[T any](v T) *T { return &v }
