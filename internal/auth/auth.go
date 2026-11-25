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
// A scope of the image registry names a project instead, with no cluster:
// clusters' scopes never reach the registry, nor the registry's clusters.
type Scope struct {
	Cluster   string `json:"cluster,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
}

// Registry tells whether the scope is of the image registry.
func (s Scope) Registry() bool { return s.Project != "" }

// Grant gives a role in some scopes, or everywhere when it has none.
type Grant struct {
	Role   Role
	Scopes []Scope
}

// User is someone signed in. Role is the highest role the user has
// anywhere; Grants say where. A user without grants has Role everywhere.
// Directory holds the DNs of the directory groups a person who signed in
// with the directory is in, so that what admins map to those groups in the
// UI reaches them, and a change to that mapping ends their sessions. It is
// not nil, if empty, for everyone the directory signed in.
type User struct {
	Name      string
	Role      Role
	Grants    []Grant
	Directory []string
}

// Add gives the user more grants, raising Role where they reach higher.
func (u User) Add(grants ...Grant) User {
	if len(grants) == 0 {
		return u
	}
	u.Grants = append(append([]Grant{}, u.grants()...), grants...)
	for _, g := range grants {
		u.Role = max(u.Role, g.Role)
	}
	return u
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
			if !s.Registry() && match(s.Cluster, cluster) && ((ns == "" && s.Namespace == "*") || (ns != "" && match(s.Namespace, ns))) {
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
			if !s.Registry() && match(s.Cluster, cluster) {
				best = g.Role
				break
			}
		}
	}
	return best
}

// ClusterRole is the highest role the user has in any cluster: what the
// server's pages and API outside the registry ask for.
func (u User) ClusterRole() Role {
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
			if !s.Registry() {
				best = g.Role
				break
			}
		}
	}
	return best
}

// RoleInProject is the user's role in a project of the image registry.
// A grant with no scope reaches it; clusters' scopes do not.
func (u User) RoleInProject(project string) Role {
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
			if s.Registry() && match(s.Project, project) {
				best = g.Role
				break
			}
		}
	}
	return best
}

// RegistryRole is the highest role the user has in any project of the
// image registry.
func (u User) RegistryRole() Role {
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
			if s.Registry() {
				best = g.Role
				break
			}
		}
	}
	return best
}

// RegistryAdmin tells whether the user runs the whole image registry: an
// admin with no scope, or of every project (admin@registry:*). Only they
// make projects and robot accounts.
func (u User) RegistryAdmin() bool {
	for _, g := range u.grants() {
		if g.Role != Admin {
			continue
		}
		if len(g.Scopes) == 0 {
			return true
		}
		for _, s := range g.Scopes {
			if s.Registry() && s.Project == "*" {
				return true
			}
		}
	}
	return false
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
			if !s.Registry() && s.Cluster == "*" && s.Namespace == "*" {
				best = g.Role
				break
			}
		}
	}
	return best
}

var patternRe = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._-]*\*?)$`)

// ParseGrant reads "role" (everywhere) or "role@scope+scope", where a scope
// is "cluster/namespace" or "cluster" (all of it), either part a pattern,
// or "registry:project", a project of the image registry or a pattern:
//
//	operator@production/team-a+production/team-b+staging/*
//	operator@production/team-a+registry:team-a
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
		item = strings.TrimSpace(item)
		if project, ok := strings.CutPrefix(item, "registry:"); ok {
			if !patternRe.MatchString(project) {
				return Grant{}, fmt.Errorf("scope %q must name a registry project, with * for all", item)
			}
			g.Scopes = append(g.Scopes, Scope{Project: project})
			continue
		}
		cluster, ns, _ := strings.Cut(item, "/")
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
		if s.Registry() {
			parts[i] = "registry:" + s.Project
		} else {
			parts[i] = s.Cluster + "/" + s.Namespace
		}
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

// ParseUsers reads "name:grant:secret" entries separated by commas or
// newlines, where grant is what ParseGrant reads and secret a token, or a
// password hash (HashPassword) for someone who signs in with a name and
// password; lines starting with # are comments. It returns the users by
// token, and those with a password.
func ParseUsers(raw string) (map[string]User, *Passwords, error) {
	out := map[string]User{}
	passwords := newPasswords()
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
			return nil, nil, fmt.Errorf("user entry %q must look like name:grant:token, such as ayse:admin:… or ali:operator@production/payments:…", redactEntry(entry))
		}
		g, err := ParseGrant(grantText)
		if err != nil {
			return nil, nil, fmt.Errorf("user %q: %w", name, err)
		}
		// Names sign in regardless of case, so they must differ by more.
		key := strings.ToLower(name)
		if names[key] {
			return nil, nil, fmt.Errorf("user %q is listed twice", name)
		}
		names[key] = true
		if IsPasswordHash(token) {
			h, err := parsePasswordHash(token)
			if err != nil {
				return nil, nil, fmt.Errorf("user %q: %w", name, err)
			}
			passwords.add(NewUser(name, []Grant{g}), h)
			continue
		}
		if len(token) < MinTokenLength {
			return nil, nil, fmt.Errorf("the token of user %q is shorter than %d characters", name, MinTokenLength)
		}
		if _, dup := out[token]; dup {
			return nil, nil, fmt.Errorf("two users share a token")
		}
		out[token] = NewUser(name, []Grant{g})
	}
	return out, passwords, nil
}

// redactEntry keeps a malformed entry's token out of error messages.
func redactEntry(entry string) string {
	if i := strings.LastIndex(entry, ":"); i >= 0 {
		return entry[:i+1] + "…"
	}
	return "…"
}
