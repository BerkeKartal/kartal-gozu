// Package accounts keeps the users and groups admins manage in the UI.
//
// A user signs in with a name and password (only the hash is kept) and has
// grants of their own: each a role in some clusters and namespaces. A group
// gives its grants to its members: users named in it (of the UI, of
// KARTAL_USERS or of the directory) and the members of the directory
// groups mapped to it. Everything lives in the settings, so a change applies
// at once, without a restart.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/ldap"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// Limits keep the settings a reasonable size.
const (
	MaxUsers     = 500
	MaxGroups    = 200
	MaxGrants    = 50   // per user or group
	MaxMembers   = 1000 // per group
	MaxDirectory = 50   // directory groups mapped to a group
)

var (
	// ErrNotFound is a name no UI user has.
	ErrNotFound = errors.New("there is no such user")
	// ErrGroupNotFound is a name no group has.
	ErrGroupNotFound = errors.New("there is no such group")
	// ErrWrongPassword is a wrong current password when changing one's own.
	ErrWrongPassword = errors.New("the current password is wrong")
)

var (
	validName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	validGroupName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
)

// Manager keeps the UI's users and groups.
type Manager struct {
	keeper *settings.Keeper
	now    func() time.Time
	// fixed are the users the server was started with (KARTAL_USERS, the
	// admin token): shown, but changed only where they are set.
	fixed []auth.User
	// grouped are those of them, by lowercase name, who sign in with a
	// password and so get their groups' grants (WithGroups); tokens do not.
	grouped map[string]bool
}

// New returns a manager over the settings; fixed are the users the server
// was started with, whose names the UI's users cannot take.
func New(keeper *settings.Keeper, fixed []auth.User) *Manager {
	return &Manager{keeper: keeper, now: time.Now, fixed: fixed}
}

// Entry is a user as the API shows them, without the hash. Role is the
// highest role they have anywhere, their groups' grants included.
type Entry struct {
	Name      string    `json:"name"`
	FullName  string    `json:"fullName,omitempty"`
	Email     string    `json:"email,omitempty"`
	Grants    []string  `json:"grants"`
	Groups    []string  `json:"groups"`
	Role      string    `json:"role"`
	Disabled  bool      `json:"disabled,omitempty"`
	Created   time.Time `json:"created,omitempty"`
	By        string    `json:"by,omitempty"`
	Changed   time.Time `json:"changed,omitempty"`
	ChangedBy string    `json:"changedBy,omitempty"`
}

// GroupEntry is a group as the API shows it.
type GroupEntry struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Grants      []string  `json:"grants"`
	Members     []string  `json:"members"`
	Directory   []string  `json:"directory"`
	Role        string    `json:"role"`
	Created     time.Time `json:"created,omitempty"`
	By          string    `json:"by,omitempty"`
	Changed     time.Time `json:"changed,omitempty"`
	ChangedBy   string    `json:"changedBy,omitempty"`
}

// FixedEntry is a user the server was started with. Password says they sign
// in with one, and so get what their groups give; a token gets nothing.
type FixedEntry struct {
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Grants   []string `json:"grants"`
	Groups   []string `json:"groups"`
	Password bool     `json:"password"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func parseAll(grants []string) []auth.Grant {
	out := make([]auth.Grant, 0, len(grants))
	for _, text := range grants {
		if g, err := auth.ParseGrant(text); err == nil {
			out = append(out, g)
		}
	}
	return out
}

func roleOf(grants []auth.Grant) string {
	var best auth.Role
	for _, g := range grants {
		best = max(best, g.Role)
	}
	return best.String()
}

func member(g settings.Group, name string) bool {
	for _, m := range g.Members {
		if strings.EqualFold(m, name) {
			return true
		}
	}
	return false
}

func mapped(g settings.Group, directory []string) bool {
	for _, pattern := range g.Directory {
		for _, dn := range directory {
			if ldap.MatchGroup(pattern, dn) {
				return true
			}
		}
	}
	return false
}

// groupsOf are the names of the groups that name is a member of.
func groupsOf(groups []settings.Group, name string) []string {
	out := []string{}
	for _, g := range groups {
		if member(g, name) {
			out = append(out, g.Name)
		}
	}
	return out
}

func entryOf(s settings.Settings, u settings.User) Entry {
	all := parseAll(u.AllGrants())
	all = append(all, grantsFor(s.Groups, u.Name, nil)...)
	return Entry{Name: u.Name, FullName: u.FullName, Email: u.Email, Grants: nonNil(u.AllGrants()),
		Groups: groupsOf(s.Groups, u.Name), Role: roleOf(all), Disabled: u.Disabled,
		Created: u.Created, By: u.By, Changed: u.Changed, ChangedBy: u.ChangedBy}
}

func groupEntryOf(g settings.Group) GroupEntry {
	return GroupEntry{Name: g.Name, Description: g.Description, Grants: nonNil(g.Grants), Members: nonNil(g.Members),
		Directory: nonNil(g.Directory), Role: roleOf(parseAll(g.Grants)),
		Created: g.Created, By: g.By, Changed: g.Changed, ChangedBy: g.ChangedBy}
}

func byName[T any](items []T, name func(T) string) {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(name(items[i])) < strings.ToLower(name(items[j])) })
}

// List returns the UI's users, by name.
func (m *Manager) List() []Entry {
	s := m.keeper.Get()
	out := make([]Entry, 0, len(s.Users))
	for _, u := range s.Users {
		out = append(out, entryOf(s, u))
	}
	byName(out, func(e Entry) string { return e.Name })
	return out
}

// Groups returns the groups, by name.
func (m *Manager) Groups() []GroupEntry {
	groups := m.keeper.Get().Groups
	out := make([]GroupEntry, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupEntryOf(g))
	}
	byName(out, func(e GroupEntry) string { return e.Name })
	return out
}

// Fixed returns the users the server was started with, by name.
func (m *Manager) Fixed() []FixedEntry {
	groups := m.keeper.Get().Groups
	out := make([]FixedEntry, 0, len(m.fixed))
	for _, u := range m.fixed {
		grants := []string{}
		for _, g := range u.Grants {
			grants = append(grants, g.String())
		}
		if len(u.Grants) == 0 && u.Role > 0 {
			grants = append(grants, u.Role.String())
		}
		password := m.grouped[strings.ToLower(u.Name)]
		in := []string{}
		if password {
			in = groupsOf(groups, u.Name)
		}
		out = append(out, FixedEntry{Name: u.Name, Role: u.Role.String(), Grants: grants, Groups: in, Password: password})
	}
	byName(out, func(e FixedEntry) string { return e.Name })
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

func findGroup(groups []settings.Group, name string) (int, bool) {
	for i, g := range groups {
		if strings.EqualFold(g.Name, strings.TrimSpace(name)) {
			return i, true
		}
	}
	return -1, false
}

func invalid(format string, a ...any) error {
	return &settings.InvalidError{Err: fmt.Errorf(format, a...)}
}

// checkGrants reads grants as KARTAL_USERS writes them (admin, or
// operator@production/payments+staging), dropping blanks and repeats.
func checkGrants(grants []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, text := range grants {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		g, err := auth.ParseGrant(text)
		if err != nil {
			return nil, invalid("%v", err)
		}
		if key := g.String(); !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	if len(out) > MaxGrants {
		return nil, invalid("at most %d grants", MaxGrants)
	}
	return out, nil
}

func plainText(s string, most int, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > most {
		return "", invalid("the %s may be at most %d characters", what, most)
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", invalid("the %s may not contain line breaks or control characters", what)
	}
	return s, nil
}

func checkEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || len(s) > 254 {
		return "", invalid("%q is not an e-mail address", s)
	}
	return s, nil
}

// checkNames reads member names, as people type them to sign in.
func checkNames(names []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !validName.MatchString(n) {
			return nil, invalid("member %q: a user name is letters, digits and . _ @ -, starting with a letter or digit", n)
		}
		if key := strings.ToLower(n); !seen[key] {
			seen[key] = true
			out = append(out, n)
		}
	}
	if len(out) > MaxMembers {
		return nil, invalid("a group may have at most %d members", MaxMembers)
	}
	return out, nil
}

// checkDirectory reads directory groups: whole DNs or CNs.
func checkDirectory(groups []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, d := range groups {
		d, err := plainText(d, 512, "directory group")
		if err != nil {
			return nil, err
		}
		if d == "" {
			continue
		}
		if key := strings.ToLower(d); !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	if len(out) > MaxDirectory {
		return nil, invalid("at most %d directory groups", MaxDirectory)
	}
	return out, nil
}

func hash(password string) (string, error) {
	h, err := auth.HashPassword(password)
	if err != nil {
		return "", invalid("%v", err)
	}
	return h, nil
}

// UserInput is a user to add or a change to one. In a change, nil fields
// and an empty password stay as they are; Groups, when set, is exactly the
// groups the user is a member of.
type UserInput struct {
	Name     string
	FullName *string
	Email    *string
	Grants   []string
	Password string
	Disabled *bool
	Groups   []string
}

// setGroups makes name a member of exactly the groups named.
func setGroups(s *settings.Settings, name string, groups []string, now time.Time, by string) error {
	want := map[int]bool{}
	for _, g := range groups {
		if strings.TrimSpace(g) == "" {
			continue
		}
		i, ok := findGroup(s.Groups, g)
		if !ok {
			return invalid("there is no group named %q", g)
		}
		want[i] = true
	}
	for i := range s.Groups {
		g := &s.Groups[i]
		in := member(*g, name)
		switch {
		case want[i] && !in:
			if len(g.Members) >= MaxMembers {
				return invalid("the group %q has %d members already, the most there may be", g.Name, MaxMembers)
			}
			g.Members = append(g.Members, name)
		case !want[i] && in:
			kept := g.Members[:0:0]
			for _, mem := range g.Members {
				if !strings.EqualFold(mem, name) {
					kept = append(kept, mem)
				}
			}
			g.Members = kept
		default:
			continue
		}
		g.Changed, g.ChangedBy = now, by
	}
	return nil
}

// fill sets what in changes on u, checking it.
func fill(u *settings.User, in UserInput) error {
	if in.FullName != nil {
		v, err := plainText(*in.FullName, 100, "full name")
		if err != nil {
			return err
		}
		u.FullName = v
	}
	if in.Email != nil {
		v, err := checkEmail(*in.Email)
		if err != nil {
			return err
		}
		u.Email = v
	}
	if in.Grants != nil {
		g, err := checkGrants(in.Grants)
		if err != nil {
			return err
		}
		u.Grant, u.Grants = "", g
	}
	if in.Password != "" {
		h, err := hash(in.Password)
		if err != nil {
			return err
		}
		u.Hash = h
	}
	if in.Disabled != nil {
		u.Disabled = *in.Disabled
	}
	return nil
}

// Add adds a user.
func (m *Manager) Add(ctx context.Context, in UserInput, by string) (Entry, error) {
	name := strings.TrimSpace(in.Name)
	if !validName.MatchString(name) {
		return Entry{}, invalid("a user name is letters, digits and . _ @ -, starting with a letter or digit, up to 64 characters")
	}
	for _, u := range m.fixed {
		if strings.EqualFold(u.Name, name) {
			return Entry{}, invalid("%q is a user the server was started with (KARTAL_USERS or the admin token)", name)
		}
	}
	if in.Password == "" {
		return Entry{}, invalid("a new user needs a password")
	}
	u := settings.User{Name: name, Created: m.now().UTC(), By: by}
	if err := fill(&u, in); err != nil {
		return Entry{}, err
	}
	var added Entry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if _, ok := find(s.Users, name); ok {
			return invalid("there is a user named %q already", name)
		}
		if len(s.Users) >= MaxUsers {
			return invalid("there are %d users already, the most there may be", MaxUsers)
		}
		s.Users = append(s.Users, u)
		if in.Groups != nil {
			if err := setGroups(s, name, in.Groups, u.Created, by); err != nil {
				return err
			}
		}
		added = entryOf(*s, u)
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return added, nil
}

// Update changes a user; see UserInput.
func (m *Manager) Update(ctx context.Context, name string, in UserInput, by string) (Entry, error) {
	// Checked before the settings are locked, as hashing takes a while.
	var probe settings.User
	if err := fill(&probe, in); err != nil {
		return Entry{}, err
	}
	var changed Entry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := find(s.Users, name)
		if !ok {
			return ErrNotFound
		}
		u := s.Users[i]
		if in.Disabled != nil && *in.Disabled && !u.Disabled && strings.EqualFold(u.Name, by) {
			return invalid("you cannot disable your own account; another admin can")
		}
		if in.FullName != nil {
			u.FullName = probe.FullName
		}
		if in.Email != nil {
			u.Email = probe.Email
		}
		if in.Grants != nil {
			u.Grant, u.Grants = "", probe.Grants
		}
		if probe.Hash != "" {
			u.Hash = probe.Hash
		}
		if in.Disabled != nil {
			u.Disabled = *in.Disabled
		}
		u.Changed, u.ChangedBy = m.now().UTC(), by
		s.Users[i] = u
		if in.Groups != nil {
			if err := setGroups(s, u.Name, in.Groups, u.Changed, by); err != nil {
				return err
			}
		}
		changed = entryOf(*s, u)
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	return changed, nil
}

// Remove removes a user, and takes them out of their groups, so that no one
// who later takes the name gets what the groups gave.
func (m *Manager) Remove(ctx context.Context, name, by string) (Entry, error) {
	var gone Entry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := find(s.Users, name)
		if !ok {
			return ErrNotFound
		}
		if strings.EqualFold(s.Users[i].Name, by) {
			return invalid("you cannot remove your own account; another admin can")
		}
		gone = entryOf(*s, s.Users[i])
		s.Users = append(s.Users[:i:i], s.Users[i+1:]...)
		return setGroups(s, gone.Name, nil, m.now().UTC(), by)
	})
	if err != nil {
		return Entry{}, err
	}
	return gone, nil
}

// GroupInput is a group to add or a change to one; in a change, nil fields
// stay as they are.
type GroupInput struct {
	Name        string
	Description *string
	Grants      []string
	Members     []string
	Directory   []string
}

func fillGroup(g *settings.Group, in GroupInput) error {
	if in.Description != nil {
		v, err := plainText(*in.Description, 300, "description")
		if err != nil {
			return err
		}
		g.Description = v
	}
	if in.Grants != nil {
		v, err := checkGrants(in.Grants)
		if err != nil {
			return err
		}
		g.Grants = v
	}
	if in.Members != nil {
		v, err := checkNames(in.Members)
		if err != nil {
			return err
		}
		g.Members = v
	}
	if in.Directory != nil {
		v, err := checkDirectory(in.Directory)
		if err != nil {
			return err
		}
		g.Directory = v
	}
	return nil
}

// AddGroup adds a group.
func (m *Manager) AddGroup(ctx context.Context, in GroupInput, by string) (GroupEntry, error) {
	name := strings.TrimSpace(in.Name)
	if !validGroupName.MatchString(name) {
		return GroupEntry{}, invalid("a group name is letters, digits, spaces and . _ -, starting with a letter or digit, up to 64 characters")
	}
	g := settings.Group{Name: name, Created: m.now().UTC(), By: by}
	if err := fillGroup(&g, in); err != nil {
		return GroupEntry{}, err
	}
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if _, ok := findGroup(s.Groups, name); ok {
			return invalid("there is a group named %q already", name)
		}
		if len(s.Groups) >= MaxGroups {
			return invalid("there are %d groups already, the most there may be", MaxGroups)
		}
		s.Groups = append(s.Groups, g)
		return nil
	})
	if err != nil {
		return GroupEntry{}, err
	}
	return groupEntryOf(g), nil
}

// UpdateGroup changes a group; it returns the group as it was and as it is,
// so that the sessions of everyone it reaches, before or after, can end.
func (m *Manager) UpdateGroup(ctx context.Context, name string, in GroupInput, by string) (before, after GroupEntry, err error) {
	var probe settings.Group
	if err := fillGroup(&probe, in); err != nil {
		return GroupEntry{}, GroupEntry{}, err
	}
	_, err = m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := findGroup(s.Groups, name)
		if !ok {
			return ErrGroupNotFound
		}
		g := s.Groups[i]
		before = groupEntryOf(g)
		if in.Description != nil {
			g.Description = probe.Description
		}
		if in.Grants != nil {
			g.Grants = probe.Grants
		}
		if in.Members != nil {
			g.Members = probe.Members
		}
		if in.Directory != nil {
			g.Directory = probe.Directory
		}
		g.Changed, g.ChangedBy = m.now().UTC(), by
		s.Groups[i] = g
		after = groupEntryOf(g)
		return nil
	})
	return before, after, err
}

// RemoveGroup removes a group.
func (m *Manager) RemoveGroup(ctx context.Context, name string) (GroupEntry, error) {
	var gone GroupEntry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := findGroup(s.Groups, name)
		if !ok {
			return ErrGroupNotFound
		}
		gone = groupEntryOf(s.Groups[i])
		s.Groups = append(s.Groups[:i:i], s.Groups[i+1:]...)
		return nil
	})
	return gone, err
}

// Reaches says who signed in has what a group gives: its members by name,
// and the members of its directory groups.
func Reaches(groups ...GroupEntry) func(auth.User) bool {
	return func(u auth.User) bool {
		for _, g := range groups {
			sg := settings.Group{Members: g.Members, Directory: g.Directory}
			if member(sg, u.Name) || mapped(sg, u.Directory) {
				return true
			}
		}
		return false
	}
}

func grantsFor(groups []settings.Group, name string, directory []string) []auth.Grant {
	var out []auth.Grant
	for _, g := range groups {
		if member(g, name) || mapped(g, directory) {
			out = append(out, parseAll(g.Grants)...)
		}
	}
	return out
}

// GroupGrants are what the groups give someone: by name, or by the
// directory groups (DNs) they are in.
func (m *Manager) GroupGrants(name string, directory []string) []auth.Grant {
	return grantsFor(m.keeper.Get().Groups, name, directory)
}

// WithGroups gives the users of KARTAL_USERS who sign in with a password
// what their groups give them. It is called once, before the server serves.
func (m *Manager) WithGroups(p *auth.Passwords) auth.Login {
	m.grouped = map[string]bool{}
	for _, u := range p.Users() {
		m.grouped[strings.ToLower(u.Name)] = true
	}
	return withGroups{m: m, next: p}
}

type withGroups struct {
	m    *Manager
	next *auth.Passwords
}

func (w withGroups) Login(ctx context.Context, user, password string) (auth.User, error) {
	u, err := w.next.Login(ctx, user, password)
	if err != nil {
		return u, err
	}
	return u.Add(w.m.GroupGrants(u.Name, u.Directory)...), nil
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
	_, err := m.Update(ctx, users[i].Name, UserInput{Password: next}, users[i].Name)
	return err
}

// Login checks a name and password against the UI's users. A disabled
// account is told only once the password is right.
func (m *Manager) Login(_ context.Context, name, password string) (auth.User, error) {
	s := m.keeper.Get()
	i, ok := find(s.Users, name)
	if !ok {
		auth.DecoyPassword(password)
		return auth.User{}, auth.ErrInvalidCredentials
	}
	u := s.Users[i]
	if !auth.CheckPassword(u.Hash, password) {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	if u.Disabled {
		return auth.User{}, auth.ErrDisabled
	}
	grants := parseAll(u.AllGrants())
	grants = append(grants, grantsFor(s.Groups, u.Name, nil)...)
	if len(grants) == 0 {
		return auth.User{}, fmt.Errorf("%w (no grant of their own and in no group that has one)", auth.ErrNoAccess)
	}
	return auth.NewUser(u.Name, grants), nil
}

// Where names the settings store; empty means users last until a restart.
func (m *Manager) Where() string { return m.keeper.Where() }
