package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	// ErrInvalidCredentials is a wrong name or password; which of the two
	// is not told.
	ErrInvalidCredentials = errors.New("wrong user name or password")
	// ErrNoAccess is someone the directory knows but no rule lets in.
	ErrNoAccess = errors.New("your account is in none of the groups allowed to use Kartal Gözü")
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
	expires time.Time
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
	s.all[token] = session{user: u, expires: expires}
	return token, expires
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
