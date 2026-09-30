// Package auth maps the bearer tokens of the UI and the management API to
// named users with a role.
package auth

import (
	"crypto/subtle"
	"fmt"
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

type User struct {
	Name string `json:"name"`
	Role Role   `json:"-"`
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

// ParseUsers reads "name:role:token" entries separated by commas or
// newlines; lines starting with # are comments.
func ParseUsers(raw string) (map[string]User, error) {
	out := map[string]User{}
	names := map[string]bool{}
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		name, rest, ok1 := strings.Cut(entry, ":")
		roleText, token, ok2 := strings.Cut(rest, ":")
		name, token = strings.TrimSpace(name), strings.TrimSpace(token)
		if !ok1 || !ok2 || name == "" || token == "" {
			return nil, fmt.Errorf("user entry %q must look like name:role:token", redactEntry(entry))
		}
		role, err := ParseRole(roleText)
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
		out[token] = User{Name: name, Role: role}
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
