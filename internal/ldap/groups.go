package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

// Rule gives a grant to the members of a group, named by its whole DN or
// just its CN.
type Rule struct {
	Group string
	Grant auth.Grant
}

// ParseRules reads "group => grant" rules, one per line or separated by
// ";", where grant is what auth.ParseGrant reads:
//
//	CN=K8s-Admins,OU=Groups,DC=example,DC=org => admin
//	Team-A => operator@production/team-a+staging/team-a
func ParseRules(raw string) ([]Rule, error) {
	var out []Rule
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == ';' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		group, grantText, ok := strings.Cut(line, "=>")
		group = strings.TrimSpace(group)
		if !ok || group == "" {
			return nil, fmt.Errorf("group rule %q must look like group => role", line)
		}
		g, err := auth.ParseGrant(grantText)
		if err != nil {
			return nil, fmt.Errorf("group rule for %q: %w", group, err)
		}
		out = append(out, Rule{Group: group, Grant: g})
	}
	return out, nil
}

// Grants are what the member of groups (their DNs) gets.
func Grants(rules []Rule, groups []string) []auth.Grant {
	var out []auth.Grant
	for _, r := range rules {
		for _, dn := range groups {
			if r.matches(dn) {
				out = append(out, r.Grant)
				break
			}
		}
	}
	return out
}

func (r Rule) matches(dn string) bool {
	if strings.Contains(r.Group, "=") {
		return normalizeDN(r.Group) == normalizeDN(dn)
	}
	return strings.EqualFold(firstValue(dn), r.Group)
}

// normalizeDN makes two spellings of a DN compare equal: case and the
// spaces around separators do not matter.
func normalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		k, v, _ := strings.Cut(p, "=")
		parts[i] = strings.ToLower(strings.TrimSpace(k)) + "=" + strings.ToLower(strings.TrimSpace(v))
	}
	return strings.Join(parts, ",")
}

// firstValue is the value of a DN's first part: "Team-A" in
// "CN=Team-A,OU=Groups,DC=example,DC=org".
func firstValue(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	_, v, _ := strings.Cut(first, "=")
	return strings.TrimSpace(v)
}

// ErrNoAccess is someone the directory knows but no rule lets in.
var ErrNoAccess = auth.ErrNoAccess

// Authenticator signs people in: their password is checked against the
// directory and their groups become grants.
type Authenticator struct {
	Config Config
	Rules  []Rule
}

func (a Authenticator) Login(ctx context.Context, user, password string) (auth.User, error) {
	e, err := a.Config.Authenticate(ctx, user, password)
	if err != nil {
		return auth.User{}, err
	}
	grants := Grants(a.Rules, e.Groups)
	if len(grants) == 0 {
		return auth.User{}, ErrNoAccess
	}
	return auth.NewUser(e.Name, grants), nil
}
