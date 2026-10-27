package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalidCredentials is a wrong name or password; which of the two
	// is not told.
	ErrInvalidCredentials = errors.New("wrong user name or password")
	// ErrNoAccess is someone the directory knows but no rule lets in.
	ErrNoAccess = errors.New("your account is in none of the groups allowed to use Kartal Gözü")
	// ErrDisabled is an account an admin turned off in the UI.
	ErrDisabled = errors.New("your account is disabled; ask an admin to turn it back on")
)

// Sessions are sign-ins made with a password: each gets a random token
// that stands for the user until it expires or the user signs out. They
// live in memory, so a restarted server asks everyone to sign in again.
type Sessions struct {
	ttl time.Duration
	now func() time.Time
	mu  sync.Mutex
	all map[string]session
}

type session struct {
	user    User
	created time.Time
	expires time.Time
}

// SessionInfo is a live session as admins see it: never the token, only an
// ID derived from it, enough to end that one session.
type SessionInfo struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Grants    []string  `json:"grants"`
	Directory bool      `json:"directory"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

// SessionID is the ID admins see for a session token.
func SessionID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// sessionPrefix marks session tokens, so they are easy to tell from the
// tokens in KARTAL_USERS.
const sessionPrefix = "kgs_"

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, now: time.Now, all: map[string]session{}}
}

// Create starts a session for u.
func (s *Sessions) Create(u User) (string, time.Time) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := sessionPrefix + hex.EncodeToString(b)
	now := s.now()
	expires := now.Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, ses := range s.all {
		if now.After(ses.expires) {
			delete(s.all, t)
		}
	}
	s.all[token] = session{user: u, created: now, expires: expires}
	return token, expires
}

// List returns the live sessions, the newest first.
func (s *Sessions) List() []SessionInfo {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SessionInfo, 0, len(s.all))
	for t, ses := range s.all {
		if now.After(ses.expires) {
			continue
		}
		grants := []string{}
		for _, g := range ses.user.grants() {
			grants = append(grants, g.String())
		}
		out = append(out, SessionInfo{ID: SessionID(t), User: ses.user.Name, Role: ses.user.Role.String(), Grants: grants,
			Directory: ses.user.Directory != nil, Created: ses.created.UTC(), Expires: ses.expires.UTC()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.After(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// EndID signs out the session with an ID from List; it returns its user.
func (s *Sessions) EndID(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, ses := range s.all {
		if SessionID(t) == id {
			delete(s.all, t)
			return ses.user.Name, true
		}
	}
	return "", false
}

// EndWhere signs out every session whose user f picks, as when a group
// they are in changes; it returns how many there were.
func (s *Sessions) EndWhere(f func(User) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for t, ses := range s.all {
		if f(ses.user) {
			delete(s.all, t)
			n++
		}
	}
	return n
}

// Lookup returns the user of a live session. A token is 256 random bits,
// so looking it up in a map gives nothing away.
func (s *Sessions) Lookup(token string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ses, ok := s.all[token]
	if !ok {
		return User{}, false
	}
	if s.now().After(ses.expires) {
		delete(s.all, token)
		return User{}, false
	}
	return ses.user, true
}

// End signs a session out; it reports whether there was one.
func (s *Sessions) End(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.all[token]
	delete(s.all, token)
	return ok
}

// EndUser signs every session of a user out, as when their account goes or
// their role changes; it returns how many there were.
func (s *Sessions) EndUser(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for t, ses := range s.all {
		if strings.EqualFold(ses.user.Name, name) {
			delete(s.all, t)
			n++
		}
	}
	return n
}

// EndOthers signs a user's sessions out but the one of keep, as when they
// changed their own password and a session someone else holds must end.
func (s *Sessions) EndOthers(name, keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for t, ses := range s.all {
		if t != keep && strings.EqualFold(ses.user.Name, name) {
			delete(s.all, t)
			n++
		}
	}
	return n
}
