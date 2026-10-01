// Package auth maps the bearer tokens of the UI and the management API to
// named users, and says what each may do where: a role, everywhere or only
// in some clusters and namespaces.
package auth

import (
	"crypto/subtle"
	"fmt"
	"regexp"
	"strings"
)

// Role orders what a user may do; each role includes the ones below it.
type Role int

const (
	// Viewer reads everything the agents report, including logs and objects
	// (Secret values are never sent by the agents).
	Viewer Role = iota + 1
	// Operator also restarts, scales, deletes pods, cordons nodes, runs and
	// suspends CronJobs and rolls Deployments back.
	Operator
	// Admin also runs commands in containers and edits objects.
	Admin
)

func (r Role) String() string {
	switch r {
	case Viewer:
		return "viewer"
	case Operator:
		return "operator"
	case Admin:
		return "admin"
	}
	return "none"
}

// ParseRole reads "viewer", "operator" or "admin".
func ParseRole(s string) (Role, error) {
	for _, r := range []Role{Viewer, Operator, Admin} {
		if strings.EqualFold(strings.TrimSpace(s), r.String()) {
			return r, nil
		}
	}
	return 0, fmt.Errorf("unknown role %q (use viewer, operator or admin)", s)
}

// Scope is a cluster and a namespace, each a name or a pattern: "*" is
// every one and a trailing "*" matches the start of a name ("team-*").
type Scope struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
}

// Grant gives a role in some scopes, or everywhere when it has none.
type Grant struct {
	Role   Role
	Scopes []Scope
}

// User is someone signed in. Role is the highest role the user has
// anywhere; Grants say where. A user without grants has Role everywhere.
type User struct {
	Name   string
	Role   Role
	Grants []Grant
}

// match tells whether a name fits a pattern.
func match(pattern, name string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

func (u User) grants() []Grant {
	if u.Grants == nil {
		return []Grant{{Role: u.Role}}
	}
	return u.Grants
}

// RoleIn is the user's role in a namespace of a cluster. The namespace ""
// stands for the cluster as a whole (nodes, cluster-wide lists and
// objects), which only a grant over every namespace reaches.
func (u User) RoleIn(cluster, ns string) Role {
	var best Role
	for _, g := range u.grants() {
		if g.Role <= best {
			continue
		}
		if len(g.Scopes) == 0 {
			best = g.Role
			continue
		}
		for _, s := range g.Scopes {
			if match(s.Cluster, cluster) && ((ns == "" && s.Namespace == "*") || (ns != "" && match(s.Namespace, ns))) {
				best = g.Role
				break
			}
		}
	}
	return best
}

// RoleSomewhere is the highest role the user has in any part of a cluster.
func (u User) RoleSomewhere(cluster string) Role {
	var best Role
	for _, g := range u.grants() {
		if g.Role <= best {
			continue
		}
		if len(g.Scopes) == 0 {
			best = g.Role
			continue
		}
		for _, s := range g.Scopes {
			if match(s.Cluster, cluster) {
				best = g.Role
				break
			}
		}
	}
	return best
}

// Everywhere is the user's role over every cluster and namespace, which is
// what the server's own settings ask for.
func (u User) Everywhere() Role {
	var best Role
	for _, g := range u.grants() {
		if g.Role <= best {
			continue
		}
		if len(g.Scopes) == 0 {
			best = g.Role
			continue
		}
		for _, s := range g.Scopes {
			if s.Cluster == "*" && s.Namespace == "*" {
				best = g.Role
				break
			}
		}
	}
	return best
}

var patternRe = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._-]*\*?)$`)

// ParseGrant reads "role" (everywhere) or "role@scope+scope", where a scope
// is "cluster/namespace" or "cluster" (all of it), either part a pattern:
//
//	operator@production/team-a+production/team-b+staging/*
func ParseGrant(s string) (Grant, error) {
	roleText, scopeText, scoped := strings.Cut(strings.TrimSpace(s), "@")
	role, err := ParseRole(roleText)
	if err != nil {
		return Grant{}, err
	}
	g := Grant{Role: role}
	if !scoped {
		return g, nil
	}
	for _, item := range strings.Split(scopeText, "+") {
		cluster, ns, _ := strings.Cut(strings.TrimSpace(item), "/")
		if ns == "" {
			ns = "*"
		}
		if !patternRe.MatchString(cluster) || !patternRe.MatchString(ns) {
			return Grant{}, fmt.Errorf("scope %q must look like cluster/namespace, with * for all", item)
		}
		g.Scopes = append(g.Scopes, Scope{Cluster: cluster, Namespace: ns})
	}
	return g, nil
}

// String writes a grant the way ParseGrant reads it.
func (g Grant) String() string {
	if len(g.Scopes) == 0 {
		return g.Role.String()
	}
	parts := make([]string, len(g.Scopes))
	for i, s := range g.Scopes {
		parts[i] = s.Cluster + "/" + s.Namespace
	}
	return g.Role.String() + "@" + strings.Join(parts, "+")
}

// NewUser makes a user with the given grants; nil or empty grants give
// nothing.
func NewUser(name string, grants []Grant) User {
	u := User{Name: name, Grants: grants}
	if u.Grants == nil {
		u.Grants = []Grant{}
	}
	for _, g := range grants {
		u.Role = max(u.Role, g.Role)
	}
	return u
}

// MinTokenLength keeps tokens from being guessable.
const MinTokenLength = 16

// Directory finds users by token. An empty directory lets everyone in as an
// anonymous admin, which only makes sense for local testing.
type Directory struct {
	byToken map[string]User
}

// NewDirectory builds a directory from token -> user entries.
func NewDirectory(users map[string]User) *Directory {
	return &Directory{byToken: users}
}

// Open reports whether the directory has no users at all.
func (d *Directory) Open() bool { return len(d.byToken) == 0 }

// Lookup returns the user a token belongs to. Every token is compared, in
// constant time, so timing does not reveal which one (if any) matched.
func (d *Directory) Lookup(token string) (User, bool) {
	if d.Open() {
		return User{Name: "anonymous", Role: Admin}, true
	}
	var found User
	ok := false
	for t, u := range d.byToken {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			found, ok = u, true
		}
	}
	return found, ok
}

// ParseUsers reads "name:grant:token" entries separated by commas or
// newlines, where grant is what ParseGrant reads; lines starting with # are
// comments.
func ParseUsers(raw string) (map[string]User, error) {
	out := map[string]User{}
	names := map[string]bool{}
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		name, rest, ok1 := strings.Cut(entry, ":")
		grantText, token, ok2 := strings.Cut(rest, ":")
		name, token = strings.TrimSpace(name), strings.TrimSpace(token)
		if !ok1 || !ok2 || name == "" || token == "" {
			return nil, fmt.Errorf("user entry %q must look like name:grant:token, such as ayse:admin:… or ali:operator@production/payments:…", redactEntry(entry))
		}
		g, err := ParseGrant(grantText)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", name, err)
		}
		if len(token) < MinTokenLength {
			return nil, fmt.Errorf("the token of user %q is shorter than %d characters", name, MinTokenLength)
		}
		if names[name] {
			return nil, fmt.Errorf("user %q is listed twice", name)
		}
		if _, dup := out[token]; dup {
			return nil, fmt.Errorf("two users share a token")
		}
		names[name] = true
		out[token] = NewUser(name, []Grant{g})
	}
	return out, nil
}

// redactEntry keeps a malformed entry's token out of error messages.
func redactEntry(entry string) string {
	if i := strings.LastIndex(entry, ":"); i >= 0 {
		return entry[:i+1] + "…"
	}
	return "…"
}
