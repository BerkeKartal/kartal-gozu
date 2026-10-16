// Package accounts keeps the users admins add in the UI: each signs in with
// a name and password, and a grant says what they may do where. They live
// in the settings (only the password's hash), so a change applies at once,
// without a restart, next to the users of KARTAL_USERS and the directory.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// MaxUsers bounds how many users the settings hold.
const MaxUsers = 500

var (
	// ErrNotFound is a name no UI user has.
	ErrNotFound = errors.New("there is no such user")
	// ErrWrongPassword is a wrong current password when changing one's own.
	ErrWrongPassword = errors.New("the current password is wrong")
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Manager keeps the UI's users.
type Manager struct {
	keeper *settings.Keeper
	now    func() time.Time
	// fixed are the users the server was started with (KARTAL_USERS, the
	// admin token): shown, but changed only where they are set.
	fixed []auth.User
}

// New returns a manager over the settings; fixed are the users the server
// was started with, whose names the UI's users cannot take.
func New(keeper *settings.Keeper, fixed []auth.User) *Manager {
	return &Manager{keeper: keeper, now: time.Now, fixed: fixed}
}

// Entry is a user as the API shows them, without the hash.
type Entry struct {
	Name      string    `json:"name"`
	Grant     string    `json:"grant"`
	Role      string    `json:"role"`
	Created   time.Time `json:"created,omitempty"`
	By        string    `json:"by,omitempty"`
	Changed   time.Time `json:"changed,omitempty"`
	ChangedBy string    `json:"changedBy,omitempty"`
}

func entryOf(u settings.User) Entry {
	e := Entry{Name: u.Name, Grant: u.Grant, Created: u.Created, By: u.By, Changed: u.Changed, ChangedBy: u.ChangedBy}
	if g, err := auth.ParseGrant(u.Grant); err == nil {
		e.Role = g.Role.String()
	}
	return e
}

// List returns the UI's users, by name.
func (m *Manager) List() []Entry {
	users := m.keeper.Get().Users
	out := make([]Entry, 0, len(users))
	for _, u := range users {
		out = append(out, entryOf(u))
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Fixed returns the users the server was started with, by name.
func (m *Manager) Fixed() []Entry {
	out := make([]Entry, 0, len(m.fixed))
	for _, u := range m.fixed {
		out = append(out, Entry{Name: u.Name, Role: u.Role.String()})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Has tells whether name is one of the UI's users.
func (m *Manager) Has(name string) bool {
	_, ok := find(m.keeper.Get().Users, name)
	return ok
}

// Count is how many users the UI has.
func (m *Manager) Count() int { return len(m.keeper.Get().Users) }

func find(users []settings.User, name string) (int, bool) {
	for i, u := range users {
		if strings.EqualFold(u.Name, strings.TrimSpace(name)) {
			return i, true
		}
	}
	return -1, false
}

func invalid(format string, a ...any) error {
	return &settings.InvalidError{Err: fmt.Errorf(format, a...)}
}

// checkGrant reads a grant as KARTAL_USERS writes it: admin, or
// operator@production/payments+staging.
func checkGrant(grant string) (string, error) {
	grant = strings.TrimSpace(grant)
	if _, err := auth.ParseGrant(grant); err != nil {
		return "", invalid("%v", err)
	}
	return grant, nil
}

func hash(password string) (string, error) {
	h, err := auth.HashPassword(password)
	if err != nil {
		return "", invalid("%v", err)
	}
	return h, nil
}

// Add adds a user.
func (m *Manager) Add(ctx context.Context, name, grant, password, by string) (Entry, error) {
	name = strings.TrimSpace(name)
	if !validName.MatchString(name) {
		return Entry{}, invalid("a user name is letters, digits and . _ @ -, starting with a letter or digit, up to 64 characters")
	}
	for _, u := range m.fixed {
		if strings.EqualFold(u.Name, name) {
			return Entry{}, invalid("%q is a user the server was started with (KARTAL_USERS or the admin token)", name)
		}
	}
	grant, err := checkGrant(grant)
	if err != nil {
		return Entry{}, err
	}
	h, err := hash(password)
	if err != nil {
		return Entry{}, err
	}
	var added settings.User
	_, err = m.keeper.Update(ctx, func(s *settings.Settings) error {
		if _, ok := find(s.Users, name); ok {
			return invalid("there is a user named %q already", name)
		}
		if len(s.Users) >= MaxUsers {
			return invalid("there are %d users already, the most there may be", MaxUsers)
		}
		added = settings.User{Name: name, Grant: grant, Hash: h, Created: m.now().UTC(), By: by}
		s.Users = append(s.Users, added)
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return entryOf(added), nil
}

// Update changes a user's grant, password or both; an empty one stays.
func (m *Manager) Update(ctx context.Context, name, grant, password, by string) (Entry, error) {
	if grant != "" {
		var err error
		if grant, err = checkGrant(grant); err != nil {
			return Entry{}, err
		}
	}
	var h string
	if password != "" {
		var err error
		if h, err = hash(password); err != nil {
			return Entry{}, err
		}
	}
	var changed settings.User
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := find(s.Users, name)
		if !ok {
			return ErrNotFound
		}
		u := s.Users[i]
		if grant != "" {
			u.Grant = grant
		}
		if h != "" {
			u.Hash = h
		}
		u.Changed, u.ChangedBy = m.now().UTC(), by
		s.Users[i] = u
		changed = u
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return entryOf(changed), nil
}

// Remove removes a user.
func (m *Manager) Remove(ctx context.Context, name string) (Entry, error) {
	var gone settings.User
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := find(s.Users, name)
		if !ok {
			return ErrNotFound
		}
		gone = s.Users[i]
		s.Users = append(s.Users[:i:i], s.Users[i+1:]...)
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return entryOf(gone), nil
}

// ChangeOwn changes a user's own password, given the current one.
func (m *Manager) ChangeOwn(ctx context.Context, name, current, next string) error {
	users := m.keeper.Get().Users
	i, ok := find(users, name)
	if !ok {
		return ErrNotFound
	}
	if !auth.CheckPassword(users[i].Hash, current) {
		return ErrWrongPassword
	}
	_, err := m.Update(ctx, users[i].Name, "", next, users[i].Name)
	return err
}

// Login checks a name and password against the UI's users.
func (m *Manager) Login(_ context.Context, name, password string) (auth.User, error) {
	users := m.keeper.Get().Users
	i, ok := find(users, name)
	if !ok {
		auth.DecoyPassword(password)
		return auth.User{}, auth.ErrInvalidCredentials
	}
	u := users[i]
	if !auth.CheckPassword(u.Hash, password) {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	g, err := auth.ParseGrant(u.Grant)
	if err != nil {
		return auth.User{}, auth.ErrNoAccess
	}
	return auth.NewUser(u.Name, []auth.Grant{g}), nil
}

// Where names the settings store; empty means users last until a restart.
func (m *Manager) Where() string { return m.keeper.Where() }
