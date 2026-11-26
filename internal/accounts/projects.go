package accounts

import (
	"context"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// A project of the image registry has members as Harbor's do: the users
// and groups whose own grants name the project (role@registry:project).
// Changing a member's role touches only that scope; their other grants,
// clusters' or other projects', and the patterns that reach the project
// (registry:*, registry:team-*) stay as they are.

// withProjectRole is grants with the project's own scope taken out of each
// grant (a grant left without scopes goes) and, unless role is none, a
// grant of role in the project added.
func withProjectRole(grants []string, project string, role auth.Role) []string {
	out := []string{}
	for _, text := range grants {
		g, err := auth.ParseGrant(text)
		if err != nil || len(g.Scopes) == 0 {
			out = append(out, text)
			continue
		}
		kept := g.Scopes[:0:0]
		for _, s := range g.Scopes {
			if !(s.Registry() && s.Project == project) {
				kept = append(kept, s)
			}
		}
		if len(kept) == len(g.Scopes) {
			out = append(out, text)
			continue
		}
		if len(kept) > 0 {
			out = append(out, auth.Grant{Role: g.Role, Scopes: kept}.String())
		}
	}
	if role > 0 {
		out = append(out, auth.Grant{Role: role, Scopes: []auth.Scope{{Project: project}}}.String())
	}
	return out
}

// ProjectRoleOf is the role grants give in a project by its own scope
// alone: what a member's role there is, as the members page changes it.
func ProjectRoleOf(grants []string, project string) auth.Role {
	var best auth.Role
	for _, g := range parseAll(grants) {
		for _, s := range g.Scopes {
			if s.Registry() && s.Project == project {
				best = max(best, g.Role)
			}
		}
	}
	return best
}

// SetUserProjectRole makes a UI user's role in a registry project role, or
// takes it away with none; see withProjectRole.
func (m *Manager) SetUserProjectRole(ctx context.Context, name, project string, role auth.Role, by string) (Entry, error) {
	var changed Entry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := find(s.Users, name)
		if !ok {
			return ErrNotFound
		}
		u := s.Users[i]
		grants, err := checkGrants(withProjectRole(u.AllGrants(), project, role))
		if err != nil {
			return err
		}
		u.Grant, u.Grants = "", grants
		u.Changed, u.ChangedBy = m.now().UTC(), by
		s.Users[i] = u
		changed = entryOf(*s, u)
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return changed, nil
}

// SetGroupProjectRole does the same for a group; it returns the group as
// it was and as it is, as UpdateGroup does.
func (m *Manager) SetGroupProjectRole(ctx context.Context, name, project string, role auth.Role, by string) (before, after GroupEntry, err error) {
	_, err = m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := findGroup(s.Groups, name)
		if !ok {
			return ErrGroupNotFound
		}
		g := s.Groups[i]
		before = groupEntryOf(g)
		grants, err := checkGrants(withProjectRole(g.Grants, project, role))
		if err != nil {
			return err
		}
		g.Grants = grants
		g.Changed, g.ChangedBy = m.now().UTC(), by
		s.Groups[i] = g
		after = groupEntryOf(g)
		return nil
	})
	return before, after, err
}
