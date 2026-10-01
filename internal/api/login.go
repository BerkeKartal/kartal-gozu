package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

// Login checks a user name and password, in practice against a directory
// such as Active Directory.
type Login interface {
	Login(ctx context.Context, user, password string) (auth.User, error)
}

// routeLogin adds signing in with a password, when a Login is set.
func (s *Server) routeLogin(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/login", s.loginMethods)
	mux.HandleFunc("POST /api/v1/login", s.login)
	mux.HandleFunc("POST /api/v1/logout", s.require(auth.Viewer, s.logout))
}

// lookup finds the user a token stands for: a session, or a token of
// KARTAL_USERS. With password sign-in on, nobody gets in without either.
func (s *Server) lookup(token string) (auth.User, bool) {
	if s.sessions != nil && strings.HasPrefix(token, "kgs_") {
		return s.sessions.Lookup(token)
	}
	if s.cfg.Login != nil && s.users.Open() {
		return auth.User{}, false
	}
	return s.users.Lookup(token)
}

// loginMethods tells the sign-in page what to offer.
func (s *Server) loginMethods(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"password": s.cfg.Login != nil})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Login == nil {
		writeError(w, http.StatusNotFound, "signing in with a password is not set up on this server")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body, `{"username": "...", "password": "..."}`) {
		return
	}
	name := accountKey(body.Username)
	now := s.now()
	if wait := s.throttle.wait(name, now); wait > 0 {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-ins; try again in %d minutes", int(wait.Minutes())+1))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	u, err := s.cfg.Login.Login(ctx, body.Username, body.Password)
	signIn := AuditEntry{Time: now.UTC(), User: strings.TrimSpace(body.Username), Action: "sign-in", Object: "password", OK: err == nil}
	if err != nil {
		signIn.Error = err.Error()
	} else {
		signIn.Role = u.Role.String()
	}
	s.audit.add(signIn)
	s.log.Info("audit", "user", signIn.User, "action", signIn.Action, "ok", signIn.OK, "error", signIn.Error)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.throttle.failed(name, now)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, auth.ErrNoAccess):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case err != nil:
		s.log.Warn("sign-in: the directory did not answer", "err", err)
		writeError(w, http.StatusBadGateway, "the directory could not check the password; try again later")
		return
	}
	s.throttle.succeeded(name)
	token, expires := s.sessions.Create(u)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "name": u.Name, "role": u.Role.String(), "expires": expires.UTC()})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.sessions != nil {
		s.sessions.End(bearerToken(r))
	}
	w.WriteHeader(http.StatusNoContent)
}

// throttle slows down password guessing: a name with too many wrong
// passwords is refused for a while, and the server as a whole tries only so
// many wrong passwords a minute, which also keeps a guesser from locking
// people's directory accounts.
type throttle struct {
	mu     sync.Mutex
	byName map[string][]time.Time
	all    []time.Time
}

const (
	nameFailures = 5
	nameWindow   = 15 * time.Minute
	allFailures  = 30
	allWindow    = time.Minute
)

func recent(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= window {
		i++
	}
	return ts[i:]
}

// wait is how long signing in as name must wait; zero means go ahead.
func (t *throttle) wait(name string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.all = recent(t.all, now, allWindow)
	if len(t.all) >= allFailures {
		return allWindow - now.Sub(t.all[0])
	}
	fails := recent(t.byName[name], now, nameWindow)
	if len(fails) == 0 {
		delete(t.byName, name)
		return 0
	}
	t.byName[name] = fails
	if len(fails) >= nameFailures {
		return nameWindow - now.Sub(fails[0])
	}
	return 0
}

func (t *throttle) failed(name string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byName == nil {
		t.byName = map[string][]time.Time{}
	}
	t.byName[name] = append(t.byName[name], now)
	t.all = append(t.all, now)
}

func (t *throttle) succeeded(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byName, name)
}

// accountKey is the account a sign-in is for, however its name was written,
// so that the limits count every spelling together: "EXAMPLE\Ayse" and
// "ayse@example.org" are both "ayse".
func accountKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(name, "@"); i > 0 {
		name = name[:i]
	}
	return name
}
