// Package registry is Kartal Gözü's image registry: the OCI Distribution
// API that docker, containerd, helm and oras push to and pull from, the
// token service they sign in with, and an API for kartal-server, which
// shows and manages what the registry holds.
//
// Who may do what is kartal-server's to say: the registry asks it, through
// an Authorizer, which role someone has in each project, and the role
// decides the actions (viewer pulls; operator also pushes and deletes).
// Anyone may pull from a public project, without signing in.
package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// Identity is who signed in, with their role in each project asked about.
// Admin is a registry-wide admin, who has every role everywhere.
type Identity struct {
	Subject string               `json:"subject"`
	Roles   map[string]auth.Role `json:"roles"`
	Admin   bool                 `json:"admin"`
}

// Role is the identity's role in a project.
func (id Identity) Role(project string) auth.Role {
	if id.Admin {
		return auth.Admin
	}
	return id.Roles[project]
}

// ErrBadCredentials is a name and a secret that do not sign anyone in.
var ErrBadCredentials = errors.New("invalid user name or password")

// Authorizer checks credentials and tells their owner's roles.
type Authorizer interface {
	// Authorize checks a name and a secret (a password, or a token of a
	// user or a robot account), and tells the role its owner has in each of
	// the projects. Wrong credentials are ErrBadCredentials.
	Authorize(ctx context.Context, username, secret string, projects []string) (Identity, error)
}

// Config sets a registry up.
type Config struct {
	Store blobstore.Store
	DB    *meta.DB
	Auth  Authorizer
	// PublicURL is where clients reach the registry, such as
	// https://registry.example.org; the token service is below it. Without
	// it, it is worked out from each request.
	PublicURL string
	// Service names the registry in tokens.
	Service string
	// TokenTTL is how long a token lasts (5 minutes when zero).
	TokenTTL time.Duration
	// Zone is the time zone the jobs' schedules are read in;
	// cron.DefaultZone when nil.
	Zone *time.Location
	// Running tells what the clusters run, which retention keeps; without
	// it retention deletes nothing.
	Running ImageSource
	// SourcesKey seals the passwords of the sources replication copies
	// from (SourcesKey makes one); without it there are no sources.
	SourcesKey []byte
	// RemoteHTTP replaces the sources' clients, for tests.
	RemoteHTTP *http.Client
	// Scanner scans images for known vulnerabilities; without it nothing
	// is scanned. Its reports are kept in ScanDir. It pulls from
	// ScanAddress (such as http://kartal-registry:5000), or PublicURL;
	// ScanWorkers scans run at once (2 when zero).
	Scanner     Scanner
	ScanDir     string
	ScanAddress string
	ScanWorkers int
	Log         *slog.Logger
}

// Server is a registry.
type Server struct {
	cfg Config
	now func() time.Time

	mu     sync.Mutex
	tokens map[string]*grant
	// uploads tie an upload to the repository it was started in.
	uploads map[string]string
	// tickets are the scans' passwords: what each lets the scanner pull.
	tickets map[string]ticket

	// scanMu guards the scans' queue, and which images wait or are being
	// scanned (scanPending); scanWake wakes a worker.
	scanMu      sync.Mutex
	scanQueue   []queued
	scanPending map[string]bool
	scanWake    chan struct{}
	// vulnCache keeps, by digest, what the pull policy needs of images'
	// reports.
	vulnMu    sync.Mutex
	vulnCache map[string][]vulnRef

	// gcMu lets one garbage collection run at a time.
	gcMu sync.Mutex

	jobMu  sync.Mutex
	jobCtx context.Context
	// running are the jobs running, by kind (and rule): their IDs.
	running map[string]string
	// Of the running jobs, by ID: how to stop them, who did, and how far
	// they got.
	cancels     map[string]context.CancelFunc
	cancelledBy map[string]string
	// replicating holds a place for each replication running.
	replicating chan struct{}
	jobProgress map[string]meta.JobProgress
}

// grant is what a token allows.
type grant struct {
	subject string
	// access is by "repository:<name>": the actions allowed.
	access map[string]map[string]bool
	// catalog are the projects whose repositories _catalog lists; nil when
	// the token was not given for the catalog.
	catalog map[string]bool
	expires time.Time
	// scanner is the scanner pulling to scan: its pulls are not counted,
	// and no project's policy stops them.
	scanner bool
}

// New makes a registry.
func New(cfg Config) *Server {
	if cfg.Service == "" {
		cfg.Service = "kartal-registry"
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{cfg: cfg, now: time.Now, tokens: map[string]*grant{}, uploads: map[string]string{}, running: map[string]string{},
		cancels: map[string]context.CancelFunc{}, cancelledBy: map[string]string{}, replicating: make(chan struct{}, maxReplications), jobProgress: map[string]meta.JobProgress{},
		tickets: map[string]ticket{}, scanPending: map[string]bool{}, scanWake: make(chan struct{}, 1), vulnCache: map[string][]vulnRef{}}
}

// maxReplications is how many replications run at once.
const maxReplications = 4

// ---------------------------------------------------------------- errors

// apiError is an error the way the Distribution spec writes them.
type apiError struct {
	status  int
	code    string
	message string
	detail  any
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

func errorf(status int, code, format string, a ...any) *apiError {
	return &apiError{status: status, code: code, message: fmt.Sprintf(format, a...)}
}

func writeError(w http.ResponseWriter, e *apiError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	type item struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Detail  any    `json:"detail,omitempty"`
	}
	json.NewEncoder(w).Encode(map[string][]item{"errors": {{Code: e.code, Message: e.message, Detail: e.detail}}})
}

// ---------------------------------------------------------------- names

var (
	component = `[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*`
	nameRE    = regexp.MustCompile(`^` + component + `(?:/` + component + `)+$`)
	tagRE     = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	projectRE = regexp.MustCompile(`^` + component + `$`)
)

// ValidName tells whether a repository name is taken: a project and at
// least one more part, as the Distribution spec writes them.
func ValidName(name string) bool { return len(name) <= 255 && nameRE.MatchString(name) }

// ValidProject tells whether a project name is taken.
func ValidProject(name string) bool { return len(name) <= 64 && projectRE.MatchString(name) }

// ValidTag tells whether a tag is taken.
func ValidTag(tag string) bool { return tagRE.MatchString(tag) }

// target is what a request below /v2/ is about.
type target struct {
	name string // the repository; empty for the catalog and /v2/ itself
	kind string // "", "catalog", "blobs", "uploads", "manifests", "tags", "referrers"
	ref  string // a digest, an upload, a tag
}

// parse reads the path below /v2/. A repository's name holds slashes, so
// the kind is found from the end.
func parse(path string) (target, bool) {
	rest := strings.TrimPrefix(path, "/v2/")
	switch rest {
	case "", "/":
		return target{}, true
	case "_catalog":
		return target{kind: "catalog"}, true
	}
	if strings.HasSuffix(rest, "/tags/list") {
		return target{name: strings.TrimSuffix(rest, "/tags/list"), kind: "tags"}, true
	}
	if strings.HasSuffix(rest, "/blobs/uploads") {
		return target{name: strings.TrimSuffix(rest, "/blobs/uploads"), kind: "uploads"}, true
	}
	for _, k := range []struct{ sep, kind string }{
		{"/blobs/uploads/", "uploads"}, {"/blobs/", "blobs"}, {"/manifests/", "manifests"}, {"/referrers/", "referrers"},
	} {
		if i := strings.LastIndex(rest, k.sep); i > 0 {
			ref := rest[i+len(k.sep):]
			if strings.Contains(ref, "/") {
				continue
			}
			return target{name: rest[:i], kind: k.kind, ref: ref}, true
		}
	}
	return target{}, false
}

// ---------------------------------------------------------------- tokens

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// scope is one access a client asks for: "repository:shop/web:pull,push".
type scope struct {
	typ, name string
	actions   []string
}

func parseScopes(values []string) []scope {
	var out []scope
	for _, v := range values {
		for _, s := range strings.Fields(v) {
			first := strings.Index(s, ":")
			last := strings.LastIndex(s, ":")
			if first < 0 || last <= first {
				continue
			}
			typ := s[:first]
			// "repository(plugin)" is an old way of saying repository.
			if i := strings.Index(typ, "("); i > 0 {
				typ = typ[:i]
			}
			out = append(out, scope{typ: typ, name: s[first+1 : last], actions: strings.Split(s[last+1:], ",")})
		}
	}
	return out
}

// allowed are the actions a role (or a public project) lets someone take
// in a repository.
func allowed(role auth.Role, public bool) map[string]bool {
	out := map[string]bool{}
	if role >= auth.Viewer || public {
		out["pull"] = true
	}
	if role >= auth.Operator {
		out["push"], out["delete"] = true, true
	}
	return out
}

// tokenHandler is the token service: it checks the credentials a client
// sends (Basic, or a password grant) and gives a token for the scopes
// asked, holding the actions allowed in each.
func (s *Server) tokenHandler(w http.ResponseWriter, r *http.Request) {
	var user, secret string
	var hasCreds bool
	scopes := r.URL.Query()["scope"]
	switch r.Method {
	case http.MethodGet:
		user, secret, hasCreds = r.BasicAuth()
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeError(w, errorf(http.StatusBadRequest, "UNSUPPORTED", "the form cannot be read"))
			return
		}
		if gt := r.PostForm.Get("grant_type"); gt != "password" {
			writeError(w, errorf(http.StatusBadRequest, "UNSUPPORTED", "grant_type %q is not supported; use password", gt))
			return
		}
		user, secret, hasCreds = r.PostForm.Get("username"), r.PostForm.Get("password"), true
		scopes = append(scopes, r.PostForm["scope"]...)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET or POST"))
		return
	}
	asked := parseScopes(scopes)
	projectSet := map[string]bool{}
	catalog := false
	for _, sc := range asked {
		switch {
		case sc.typ == "repository" && ValidName(sc.name):
			projectSet[meta.ProjectOf(sc.name)] = true
		case sc.typ == "registry" && sc.name == "catalog":
			catalog = true
		}
	}
	if catalog {
		for _, p := range s.cfg.DB.Projects() {
			projectSet[p.Name] = true
		}
	}
	projects := make([]string, 0, len(projectSet))
	for p := range projectSet {
		projects = append(projects, p)
	}
	sort.Strings(projects)

	// The scanner signs in with a scan's password, which pulls the one
	// repository that scan is of; kartal-server is not asked.
	if hasCreds && user == ScannerUser {
		t, ok := s.scanTicket(secret)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="kartal-registry"`)
			writeError(w, errorf(http.StatusUnauthorized, "UNAUTHORIZED", "the scan's password is not valid, or no longer"))
			return
		}
		g := &grant{subject: ScannerUser, access: map[string]map[string]bool{}, expires: s.now().Add(s.cfg.TokenTTL), scanner: true}
		for _, sc := range asked {
			if sc.typ == "repository" && sc.name == t.repo {
				for _, a := range sc.actions {
					if a == "pull" || a == "*" {
						g.access["repository:"+t.repo] = map[string]bool{"pull": true}
					}
				}
			}
		}
		s.issue(w, g)
		return
	}

	var id Identity
	if hasCreds {
		var err error
		id, err = s.cfg.Auth.Authorize(r.Context(), user, secret, projects)
		if errors.Is(err, ErrBadCredentials) {
			s.cfg.Log.Info("registry sign-in refused", "user", user)
			w.Header().Set("WWW-Authenticate", `Basic realm="kartal-registry"`)
			writeError(w, errorf(http.StatusUnauthorized, "UNAUTHORIZED", "incorrect user name or password"))
			return
		}
		if err != nil {
			s.cfg.Log.Warn("registry sign-in could not be checked", "user", user, "err", err)
			writeError(w, errorf(http.StatusServiceUnavailable, "UNAVAILABLE", "the sign-in cannot be checked now; try again"))
			return
		}
	}
	g := &grant{subject: id.Subject, access: map[string]map[string]bool{}, expires: s.now().Add(s.cfg.TokenTTL)}
	for _, sc := range asked {
		if sc.typ != "repository" || !ValidName(sc.name) {
			continue
		}
		project := meta.ProjectOf(sc.name)
		p, exists := s.cfg.DB.Project(project)
		can := allowed(id.Role(project), exists && p.Public)
		key := "repository:" + sc.name
		if g.access[key] == nil {
			g.access[key] = map[string]bool{}
		}
		for _, a := range sc.actions {
			switch {
			case a == "*":
				for k := range can {
					g.access[key][k] = true
				}
			case can[a]:
				g.access[key][a] = true
			}
		}
	}
	if catalog {
		g.catalog = map[string]bool{}
		for _, p := range s.cfg.DB.Projects() {
			if id.Role(p.Name) >= auth.Viewer || p.Public {
				g.catalog[p.Name] = true
			}
		}
	}
	s.issue(w, g)
}

// issue gives a token for a grant.
func (s *Server) issue(w http.ResponseWriter, g *grant) {
	tok := newToken()
	s.mu.Lock()
	now := s.now()
	if len(s.tokens) > 10000 {
		for k, v := range s.tokens {
			if now.After(v.expires) {
				delete(s.tokens, k)
			}
		}
	}
	s.tokens[tok] = g
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"token": tok, "access_token": tok, "expires_in": int(s.cfg.TokenTTL.Seconds()),
		"issued_at": now.UTC().Format(time.RFC3339),
	})
}

// grantOf is the token a request carries, if it is valid.
func (s *Server) grantOf(r *http.Request) *grant {
	h := r.Header.Get("Authorization")
	if len(h) <= 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.tokens[strings.TrimSpace(h[7:])]
	if g == nil {
		return nil
	}
	if s.now().After(g.expires) {
		delete(s.tokens, strings.TrimSpace(h[7:]))
		return nil
	}
	return g
}

// realm is where clients get tokens.
func (s *Server) realm(r *http.Request) string {
	// The scanner, which may reach the registry by another address, gets
	// its tokens there.
	if realm := s.scanRealm(r.Host); realm != "" {
		return realm
	}
	if s.cfg.PublicURL != "" {
		return strings.TrimSuffix(s.cfg.PublicURL, "/") + "/token"
	}
	proto := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		proto = "https"
	}
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = strings.TrimSpace(strings.Split(fh, ",")[0])
	}
	return proto + "://" + host + "/token"
}

// challenge asks the client to get a token for a scope.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, scope string) {
	v := fmt.Sprintf(`Bearer realm=%q,service=%q`, s.realm(r), s.cfg.Service)
	if scope != "" {
		v += fmt.Sprintf(`,scope=%q`, scope)
	}
	w.Header().Set("WWW-Authenticate", v)
	writeError(w, errorf(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required"))
}

// may checks an action in a repository: the token's, or a pull from a
// public project, which needs none. It answers the request itself when the
// action is not allowed.
func (s *Server) may(w http.ResponseWriter, r *http.Request, g *grant, repo, action string) bool {
	if g != nil && g.access["repository:"+repo][action] {
		return true
	}
	if action == "pull" {
		if p, ok := s.cfg.DB.Project(meta.ProjectOf(repo)); ok && p.Public {
			return true
		}
	}
	if g == nil {
		actions := action
		if action == "push" {
			actions = "pull,push"
		}
		s.challenge(w, r, "repository:"+repo+":"+actions)
		return false
	}
	writeError(w, errorf(http.StatusForbidden, "DENIED", "%s is not allowed in %s", action, repo))
	return false
}

func subject(g *grant) string {
	if g == nil {
		return ""
	}
	return g.subject
}

// ---------------------------------------------------------------- the public handler

// Public serves /v2/ and the token service, at a host's root.
func (s *Server) Public() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			s.tokenHandler(w, r)
		case r.URL.Path == "/v2" || strings.HasPrefix(r.URL.Path, "/v2/"):
			w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
			s.v2(w, r)
		case r.URL.Path == "/healthz":
			if err := s.cfg.DB.Healthy(); err != nil {
				http.Error(w, "metadata snapshot failing: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte("ok\n"))
		default:
			writeError(w, errorf(http.StatusNotFound, "NOT_FOUND", "nothing here; the registry is below /v2/"))
		}
	})
}

func (s *Server) v2(w http.ResponseWriter, r *http.Request) {
	t, ok := parse(r.URL.Path)
	if !ok {
		writeError(w, errorf(http.StatusNotFound, "NOT_FOUND", "no such route"))
		return
	}
	g := s.grantOf(r)
	if t.kind == "" {
		// The version check: clients sign in when it asks them to.
		if g == nil {
			s.challenge(w, r, "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}
	if t.kind == "catalog" {
		s.catalog(w, r, g)
		return
	}
	if !ValidName(t.name) {
		writeError(w, errorf(http.StatusBadRequest, "NAME_INVALID", "%q is not a repository name: a project and a name, such as shop/web", t.name))
		return
	}
	switch t.kind {
	case "blobs":
		s.blob(w, r, g, t)
	case "uploads":
		s.upload(w, r, g, t)
	case "manifests":
		s.manifest(w, r, g, t)
	case "tags":
		s.tags(w, r, g, t)
	case "referrers":
		s.referrers(w, r, g, t)
	}
}

// page reads ?n= and ?last=.
func page(r *http.Request) (int, string, *apiError) {
	q := r.URL.Query()
	n := 0
	if v := q.Get("n"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 0 {
			return 0, "", errorf(http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "n must be a number")
		}
	}
	return n, q.Get("last"), nil
}

// next links to the following page.
func next(w http.ResponseWriter, path string, n int, last string) {
	q := url.Values{"n": {strconv.Itoa(n)}, "last": {last}}
	w.Header().Set("Link", fmt.Sprintf(`<%s?%s>; rel="next"`, path, q.Encode()))
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request, g *grant) {
	if r.Method != http.MethodGet {
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET"))
		return
	}
	if g == nil || g.catalog == nil {
		if g == nil {
			s.challenge(w, r, "registry:catalog:*")
			return
		}
		writeError(w, errorf(http.StatusForbidden, "DENIED", "the token was not given for the catalog"))
		return
	}
	n, last, e := page(r)
	if e != nil {
		writeError(w, e)
		return
	}
	limit := n
	if limit > 0 {
		limit++
	}
	repos := s.cfg.DB.Catalog(func(p string) bool { return g.catalog[p] }, last, limit)
	if n > 0 && len(repos) > n {
		repos = repos[:n]
		next(w, "/v2/_catalog", n, repos[n-1])
	}
	if repos == nil {
		repos = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"repositories": repos})
}
