package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The image registry (kartal-registry) is a module of its own: when
// Config.RegistryURL is set, the server says who signs in to it
// (authorize), writes what happens in it to the audit log (events), and
// shows and manages it in the UI, each call checked against the user's
// role in the project, then made on the registry's admin API.

func (s *Server) routeRegistry(mux *http.ServeMux) {
	if s.cfg.RegistryURL == "" {
		return
	}
	mux.HandleFunc("POST /api/v1/registry/authorize", s.registryAuthorize)
	mux.HandleFunc("POST /api/v1/registry/events", s.registryEvents)
	mux.HandleFunc("GET /api/v1/registry/running", s.registryRunning)
	mux.HandleFunc("GET /api/v1/registry", s.signedIn(s.registryInfo))
	mux.HandleFunc("GET /api/v1/registry/projects", s.signedIn(s.registryProjects))
	mux.HandleFunc("POST /api/v1/registry/projects", s.signedIn(s.registryCreateProject))
	mux.HandleFunc("GET /api/v1/registry/projects/{name}", s.signedIn(s.registryGetProject))
	mux.HandleFunc("PUT /api/v1/registry/projects/{name}", s.signedIn(s.registryUpdateProject))
	mux.HandleFunc("DELETE /api/v1/registry/projects/{name}", s.signedIn(s.registryDeleteProject))
	mux.HandleFunc("GET /api/v1/registry/projects/{name}/repositories", s.signedIn(s.registryRepositories))
	mux.HandleFunc("GET /api/v1/registry/repository", s.signedIn(s.registryRepository))
	mux.HandleFunc("DELETE /api/v1/registry/repository", s.signedIn(s.registryDeleteRepository))
	mux.HandleFunc("GET /api/v1/registry/artifact", s.signedIn(s.registryArtifact))
	mux.HandleFunc("DELETE /api/v1/registry/artifact", s.signedIn(s.registryDeleteArtifact))
	mux.HandleFunc("PUT /api/v1/registry/tag", s.signedIn(s.registryPutTag))
	mux.HandleFunc("DELETE /api/v1/registry/tag", s.signedIn(s.registryDeleteTag))
	mux.HandleFunc("GET /api/v1/registry/events", s.signedIn(s.registryEventList))
	mux.HandleFunc("GET /api/v1/registry/jobs", s.signedIn(s.registryAdminRelay))
	mux.HandleFunc("POST /api/v1/registry/jobs", s.signedIn(s.registryStartJob))
	mux.HandleFunc("GET /api/v1/registry/jobs/{id}", s.signedIn(s.registryJob))
	mux.HandleFunc("PUT /api/v1/registry/schedules/{kind}", s.signedIn(s.registrySetSchedule))
	mux.HandleFunc("GET /api/v1/registry/sources", s.signedIn(s.registrySources))
	mux.HandleFunc("POST /api/v1/registry/sources", s.signedIn(s.registrySources))
	mux.HandleFunc("POST /api/v1/registry/sources/test", s.signedIn(s.registrySources))
	mux.HandleFunc("PUT /api/v1/registry/sources/{id}", s.signedIn(s.registrySources))
	mux.HandleFunc("DELETE /api/v1/registry/sources/{id}", s.signedIn(s.registrySources))
	mux.HandleFunc("GET /api/v1/registry/sources/{id}/projects", s.signedIn(s.registrySources))
	mux.HandleFunc("POST /api/v1/registry/sources/{id}/migrate", s.signedIn(s.registrySources))
	mux.HandleFunc("GET /api/v1/registry/rules", s.signedIn(s.registryRules))
	mux.HandleFunc("POST /api/v1/registry/rules", s.signedIn(s.registryRules))
	mux.HandleFunc("PUT /api/v1/registry/rules/{id}", s.signedIn(s.registryRules))
	mux.HandleFunc("DELETE /api/v1/registry/rules/{id}", s.signedIn(s.registryRules))
	mux.HandleFunc("DELETE /api/v1/registry/jobs/{id}", s.signedIn(s.registryCancelJob))
	mux.HandleFunc("GET /api/v1/registry/robots", s.signedIn(s.robotList))
	mux.HandleFunc("POST /api/v1/registry/robots", s.signedIn(s.robotAdd))
	mux.HandleFunc("PUT /api/v1/registry/robots/{name}", s.signedIn(s.robotUpdate))
	mux.HandleFunc("POST /api/v1/registry/robots/{name}/rotate", s.signedIn(s.robotRotate))
	mux.HandleFunc("DELETE /api/v1/registry/robots/{name}", s.signedIn(s.robotRemove))
	mux.HandleFunc("GET /api/v1/registry/stores", s.signedIn(s.registryStores))
	mux.HandleFunc("POST /api/v1/registry/stores", s.signedIn(s.registryStores))
	mux.HandleFunc("POST /api/v1/registry/stores/test", s.signedIn(s.registryStores))
	mux.HandleFunc("PUT /api/v1/registry/stores/{name}", s.signedIn(s.registryStores))
	mux.HandleFunc("DELETE /api/v1/registry/stores/{name}", s.signedIn(s.registryStores))
	s.routeRegistryScans(mux)
}

// registrySecret tells whether a call carries the secret the registry and
// the server share.
func (s *Server) registrySecret(r *http.Request) bool {
	tok := bearerToken(r)
	return s.cfg.RegistrySecret != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.RegistrySecret)) == 1
}

// ---------------------------------------------------------------- the registry asks

// registryUser signs someone in to the registry: a robot account, a token
// (of KARTAL_USERS, the admin token, or a session) given as the password,
// or a name and password, as the UI's sign-in takes them. The status says
// why not: 401 for wrong credentials, 429 for too many, other for trouble.
func (s *Server) registryUser(ctx context.Context, username, password string) (auth.User, int) {
	username = strings.TrimSpace(username)
	if password == "" {
		return auth.User{}, http.StatusUnauthorized
	}
	name := accountKey(username)
	now := s.now()
	if wait := s.throttle.wait(name, now); wait > 0 {
		return auth.User{}, http.StatusTooManyRequests
	}
	fail := func() (auth.User, int) {
		s.throttle.failed(name, now)
		return auth.User{}, http.StatusUnauthorized
	}
	if strings.HasPrefix(username, accounts.RobotPrefix) {
		if s.cfg.Accounts == nil {
			return fail()
		}
		u, ok := s.cfg.Accounts.CheckRobot(username, password)
		if !ok {
			return fail()
		}
		s.throttle.succeeded(name)
		return u, http.StatusOK
	}
	// A token as the password. An open server (no users at all) lets anyone
	// in as an admin, which must not reach the registry.
	if !s.users.Open() || (s.sessions != nil && strings.HasPrefix(password, "kgs_")) {
		if u, ok := s.lookup(password); ok && (strings.EqualFold(username, u.Name) || username == "token") {
			s.throttle.succeeded(name)
			return u, http.StatusOK
		}
	}
	if s.cfg.Login == nil {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	u, err := s.cfg.Login.Login(ctx, username, password)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrNoAccess), errors.Is(err, auth.ErrDisabled):
		return fail()
	case err != nil:
		s.log.Warn("registry sign-in: the password could not be checked", "user", username, "err", err)
		return auth.User{}, http.StatusBadGateway
	}
	s.throttle.succeeded(name)
	return u, http.StatusOK
}

func (s *Server) registryAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.registrySecret(r) {
		writeError(w, http.StatusUnauthorized, "the registry's shared secret is needed")
		return
	}
	var body registry.AuthorizeRequest
	if !readJSON(w, r, &body, `{"username", "password", "projects"}`) {
		return
	}
	u, status := s.registryUser(r.Context(), body.Username, body.Password)
	if status != http.StatusOK {
		s.log.Info("registry sign-in refused", "user", body.Username, "status", status)
		writeError(w, status, "not signed in")
		return
	}
	ans := registry.AuthorizeAnswer{Subject: u.Name, Roles: map[string]string{}, Admin: u.RegistryAdmin()}
	for _, p := range body.Projects {
		if role := u.RoleInProject(p); role > 0 {
			ans.Roles[p] = role.String()
		}
	}
	writeJSON(w, http.StatusOK, ans)
}

// registryEvents writes what happened in the registry to the audit log.
func (s *Server) registryEvents(w http.ResponseWriter, r *http.Request) {
	if !s.registrySecret(r) {
		writeError(w, http.StatusUnauthorized, "the registry's shared secret is needed")
		return
	}
	var events []meta.Event
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&events); err != nil {
		writeError(w, http.StatusBadRequest, "the body must be a list of events")
		return
	}
	for _, e := range events {
		object := e.Repo
		if object == "" {
			object = e.Project
		}
		switch {
		case e.Tag != "":
			object += ":" + e.Tag
		case e.Digest != "":
			object += "@" + e.Digest
		}
		entry := AuditEntry{Time: e.Time, User: e.User, Action: "registry-" + e.Action, Project: e.Project, Object: object,
			Detail: e.Detail, OK: true, Via: "registry"}
		s.audit.add(entry)
		s.log.Info("audit", "user", entry.User, "action", entry.Action, "project", entry.Project, "object", entry.Object, "detail", entry.Detail)
	}
	w.WriteHeader(http.StatusNoContent)
}

// registryRunning tells the registry what runs, or may run, in each
// cluster: the images of its pods, workloads and CronJobs, which retention
// keeps. A cluster that has sent nothing since the server started is not
// known; the registry takes it at its last word.
func (s *Server) registryRunning(w http.ResponseWriter, r *http.Request) {
	if !s.registrySecret(r) {
		writeError(w, http.StatusUnauthorized, "the registry's shared secret is needed")
		return
	}
	out := []registry.ClusterImages{}
	for _, c := range s.st.Clusters() {
		ci := registry.ClusterImages{Name: c.Name, Digests: []string{}, Refs: []string{}}
		if snap := c.Snapshot; snap != nil {
			ci.Known, ci.At = true, c.LastSeen.UTC()
			digests, refs := map[string]bool{}, map[string]bool{}
			add := func(images ...string) {
				for _, img := range images {
					// Of any host: nodes may pull from the registry by
					// another name than RegistryPublic.
					local, digest := registry.ImageRef(img, "")
					if digest != "" {
						digests[digest] = true
					}
					if local != "" {
						refs[local] = true
					}
				}
			}
			for _, p := range snap.Pods {
				add(p.Images...)
				add(p.ImageIDs...)
			}
			for _, wl := range snap.Workloads {
				add(wl.Images...)
			}
			for _, cj := range snap.CronJobs {
				add(cj.Images...)
			}
			for d := range digests {
				ci.Digests = append(ci.Digests, d)
			}
			for ref := range refs {
				ci.Refs = append(ci.Refs, ref)
			}
			sort.Strings(ci.Digests)
			sort.Strings(ci.Refs)
		}
		out = append(out, ci)
	}
	writeJSON(w, http.StatusOK, map[string]any{"clusters": out})
}

// ---------------------------------------------------------------- the UI asks

// registryCall makes a call on the registry's admin API for the signed-in
// user.
func (s *Server) registryCall(r *http.Request, method, path string, query url.Values, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := strings.TrimSuffix(s.cfg.RegistryURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.RegistrySecret)
	req.Header.Set(registry.UserHeader, userOf(r).Name)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.registryHTTP().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	// More than this is said so, rather than cut into JSON that cannot be
	// read.
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryAnswer+1))
	if err == nil && len(b) > maxRegistryAnswer {
		return 0, nil, fmt.Errorf("the registry's answer to %s is larger than %d MiB", path, maxRegistryAnswer>>20)
	}
	return resp.StatusCode, b, err
}

// maxRegistryAnswer is the most of an answer of the registry the server
// reads: a repository's artifacts, an SBOM.
const maxRegistryAnswer = 64 << 20

func (s *Server) registryHTTP() *http.Client {
	if s.cfg.RegistryHTTP != nil {
		return s.cfg.RegistryHTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// relay answers with the registry's answer, or says it was not reached.
func (s *Server) relay(w http.ResponseWriter, r *http.Request, method, path string, query url.Values, body any) {
	status, b, err := s.registryCall(r, method, path, query, body)
	if err != nil {
		s.log.Warn("the registry could not be reached", "path", path, "err", err)
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(b)
}

// projectView is a project as a user sees it, with their role in it.
type projectView struct {
	meta.ProjectInfo
	Role string `json:"role"`
}

// registryProjectList are the registry's projects, or why not.
func (s *Server) registryProjectList(r *http.Request) ([]meta.ProjectInfo, error) {
	status, b, err := s.registryCall(r, http.MethodGet, "/admin/v1/projects", nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("the registry answered %d", status)
	}
	var out []meta.ProjectInfo
	return out, json.Unmarshal(b, &out)
}

// seesProject tells whether a user may see a project: a role in it, or a public
// project.
func seesProject(u auth.User, p meta.ProjectInfo) bool {
	return u.RoleInProject(p.Name) >= auth.Viewer || p.Public
}

// mayIn checks a role in a project, answering the request itself when
// the user lacks it. Seeing a public project needs no role.
func (s *Server) mayIn(w http.ResponseWriter, r *http.Request, project string, role auth.Role) bool {
	u := userOf(r)
	if u.RoleInProject(project) >= role {
		return true
	}
	if role == auth.Viewer {
		projects, err := s.registryProjectList(r)
		if err != nil {
			writeError(w, http.StatusBadGateway, "the image registry could not be reached")
			return false
		}
		for _, p := range projects {
			if p.Name == project && p.Public {
				return true
			}
		}
	}
	writeError(w, http.StatusForbidden, fmt.Sprintf("this needs the %s role in the registry project %s", role, project))
	return false
}

func (s *Server) registryAdminOnly(w http.ResponseWriter, r *http.Request) bool {
	if userOf(r).RegistryAdmin() {
		return true
	}
	writeError(w, http.StatusForbidden, "only the registry's admins (admin everywhere, or admin@registry:*) may do this")
	return false
}

func (s *Server) registryInfo(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	out := map[string]any{"public": s.cfg.RegistryPublic, "admin": u.RegistryAdmin(), "role": u.RegistryRole().String()}
	status, b, err := s.registryCall(r, http.MethodGet, "/admin/v1/status", nil, nil)
	if err != nil || status != http.StatusOK {
		out["problem"] = "the image registry could not be reached"
	} else {
		// Everyone may know whether images are scanned; the rest is the
		// registry's admins'.
		var st struct {
			Scanner bool `json:"scanner"`
		}
		json.Unmarshal(b, &st)
		out["scanner"] = st.Scanner
		if u.RegistryAdmin() {
			out["status"] = json.RawMessage(b)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) registryProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.registryProjectList(r)
	if err != nil {
		s.log.Warn("the registry could not be reached", "err", err)
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return
	}
	u := userOf(r)
	out := []projectView{}
	for _, p := range projects {
		if seesProject(u, p) {
			out = append(out, projectView{ProjectInfo: p, Role: u.RoleInProject(p.Name).String()})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) registryCreateProject(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	var body struct {
		Name        string   `json:"name"`
		Public      bool     `json:"public"`
		Description string   `json:"description"`
		Immutable   []string `json:"immutable"`
		Quota       int64    `json:"quota"`
		ScanOnPush  bool     `json:"scanOnPush"`
		Store       string   `json:"store,omitempty"`
	}
	if !readJSON(w, r, &body, `{"name", "public", "description", "immutable": ["v*"], "quota": bytes, "scanOnPush", "store"}`) {
		return
	}
	s.relay(w, r, http.MethodPost, "/admin/v1/projects", nil, body)
}

func (s *Server) registryGetProject(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.mayIn(w, r, name, auth.Viewer) {
		return
	}
	status, b, err := s.registryCall(r, http.MethodGet, "/admin/v1/projects/"+url.PathEscape(name), nil, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return
	}
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(b)
		return
	}
	var p meta.ProjectInfo
	if err := json.Unmarshal(b, &p); err != nil {
		writeError(w, http.StatusBadGateway, "the registry's answer could not be read")
		return
	}
	writeJSON(w, http.StatusOK, projectView{ProjectInfo: p, Role: userOf(r).RoleInProject(name).String()})
}

func (s *Server) registryUpdateProject(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.mayIn(w, r, name, auth.Admin) {
		return
	}
	// A field left out stays as it is.
	var body meta.ProjectChange
	if !readJSON(w, r, &body, `{"public", "description", "immutable": ["v*"], "quota": bytes, "scanOnPush", "blockSeverity": "HIGH", "allowlist": ["CVE-..."], "store"}`) {
		return
	}
	// A project's admins set its rules; its room, and where it is kept, are
	// the registry's admins' to give.
	if (body.Quota != nil || body.Store != nil) && !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodPut, "/admin/v1/projects/"+url.PathEscape(name), nil, body)
}

func (s *Server) registryDeleteProject(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodDelete, "/admin/v1/projects/"+url.PathEscape(r.PathValue("name")), nil, nil)
}

func (s *Server) registryRepositories(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.mayIn(w, r, name, auth.Viewer) {
		return
	}
	s.relay(w, r, http.MethodGet, "/admin/v1/projects/"+url.PathEscape(name)+"/repositories", nil, nil)
}

// repoParam reads a repository's name from the query, with its project.
func repoParam(w http.ResponseWriter, r *http.Request, key string) (string, string, bool) {
	repo := r.URL.Query().Get(key)
	if !registry.ValidName(repo) {
		writeError(w, http.StatusBadRequest, key+" must be a repository's name, such as team-a/web")
		return "", "", false
	}
	return repo, meta.ProjectOf(repo), true
}

func (s *Server) registryRepository(w http.ResponseWriter, r *http.Request) {
	repo, project, ok := repoParam(w, r, "name")
	if !ok || !s.mayIn(w, r, project, auth.Viewer) {
		return
	}
	s.relay(w, r, http.MethodGet, "/admin/v1/repository", url.Values{"name": {repo}}, nil)
}

func (s *Server) registryDeleteRepository(w http.ResponseWriter, r *http.Request) {
	repo, project, ok := repoParam(w, r, "name")
	if !ok || !s.mayIn(w, r, project, auth.Operator) {
		return
	}
	s.relay(w, r, http.MethodDelete, "/admin/v1/repository", url.Values{"name": {repo}}, nil)
}

func (s *Server) registryArtifact(w http.ResponseWriter, r *http.Request) {
	repo, project, ok := repoParam(w, r, "repo")
	if !ok || !s.mayIn(w, r, project, auth.Viewer) {
		return
	}
	s.relay(w, r, http.MethodGet, "/admin/v1/artifact", url.Values{"repo": {repo}, "ref": {r.URL.Query().Get("ref")}}, nil)
}

func (s *Server) registryDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	repo, project, ok := repoParam(w, r, "repo")
	if !ok || !s.mayIn(w, r, project, auth.Operator) {
		return
	}
	s.relay(w, r, http.MethodDelete, "/admin/v1/artifact", url.Values{"repo": {repo}, "digest": {r.URL.Query().Get("digest")}}, nil)
}

func (s *Server) registryPutTag(w http.ResponseWriter, r *http.Request) {
	repo, project, ok := repoParam(w, r, "repo")
	if !ok || !s.mayIn(w, r, project, auth.Operator) {
		return
	}
	var body struct {
		Digest string `json:"digest"`
	}
	if !readJSON(w, r, &body, `{"digest": "sha256:..."}`) {
		return
	}
	s.relay(w, r, http.MethodPut, "/admin/v1/tag", url.Values{"repo": {repo}, "tag": {r.URL.Query().Get("tag")}}, body)
}

func (s *Server) registryDeleteTag(w http.ResponseWriter, r *http.Request) {
	repo, project, ok := repoParam(w, r, "repo")
	if !ok || !s.mayIn(w, r, project, auth.Operator) {
		return
	}
	s.relay(w, r, http.MethodDelete, "/admin/v1/tag", url.Values{"repo": {repo}, "tag": {r.URL.Query().Get("tag")}}, nil)
}

func (s *Server) registryEventList(w http.ResponseWriter, r *http.Request) {
	q := url.Values{"limit": {r.URL.Query().Get("limit")}}
	if project := r.URL.Query().Get("project"); project != "" {
		// A project's own people see its log; a public project's is not
		// for everyone.
		if userOf(r).RoleInProject(project) < auth.Viewer {
			writeError(w, http.StatusForbidden, "this needs a role in the registry project "+project)
			return
		}
		q.Set("project", project)
	} else if !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodGet, "/admin/v1/events", q, nil)
}

// ---------------------------------------------------------------- jobs

// registryAdminRelay hands a read of the registry's own (its jobs) to it,
// for its admins.
func (s *Server) registryAdminRelay(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	path := "/admin/v1/jobs"
	if id := r.PathValue("id"); id != "" {
		path += "/" + url.PathEscape(id)
	}
	s.relay(w, r, http.MethodGet, path, r.URL.Query(), nil)
}

func (s *Server) registryStartJob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind    string `json:"kind"`
		DryRun  bool   `json:"dryRun"`
		Project string `json:"project,omitempty"`
		Rule    string `json:"rule,omitempty"`
		Store   string `json:"store,omitempty"`
	}
	if !readJSON(w, r, &body, `{"kind": "gc"|"verify"|"retention"|"replication"|"scan"|"move", "dryRun", "project", "rule", "store"}`) {
		return
	}
	// A project's admins apply its retention rules; the rest is the
	// registry's admins'.
	if body.Kind == registry.JobRetention && body.Project != "" {
		if !s.mayIn(w, r, body.Project, auth.Admin) {
			return
		}
	} else if !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodPost, "/admin/v1/jobs", nil, body)
}

// registryJob is a job, for the registry's admins and, of a job about a
// project, the project's admins.
func (s *Server) registryJob(w http.ResponseWriter, r *http.Request) {
	status, b, err := s.registryCall(r, http.MethodGet, "/admin/v1/jobs/"+url.PathEscape(r.PathValue("id")), nil, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return
	}
	var j meta.Job
	u := userOf(r)
	if status != http.StatusOK || json.Unmarshal(b, &j) != nil ||
		!(u.RegistryAdmin() || (j.Project != "" && u.RoleInProject(j.Project) >= auth.Admin)) {
		if !s.registryAdminOnly(w, r) {
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(b)
}

func (s *Server) registrySetSchedule(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	var body struct {
		Cron    string `json:"cron"`
		Enabled bool   `json:"enabled"`
	}
	if !readJSON(w, r, &body, `{"cron": "0 3 * * *", "enabled"}`) {
		return
	}
	s.relay(w, r, http.MethodPut, "/admin/v1/schedules/"+url.PathEscape(r.PathValue("kind")), nil, body)
}

// ---------------------------------------------------------------- sources

// registrySources hands the registry's admins' calls about the sources
// replication copies from to the registry, as they came: their passwords
// go to it alone, which seals them.
func (s *Server) registrySources(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	var body any
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var raw json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&raw); err != nil {
			writeError(w, http.StatusBadRequest, "the body must be a source, as JSON")
			return
		}
		body = raw
	}
	path := "/admin/v1/sources"
	if id := r.PathValue("id"); id != "" {
		path += "/" + url.PathEscape(id)
	}
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sources/test"):
		path += "/test"
	case strings.HasSuffix(r.URL.Path, "/projects"):
		path += "/projects"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/migrate"):
		path += "/migrate"
	}
	s.relay(w, r, r.Method, path, nil, body)
}

// registryStores hands the registry's admins' calls about its blob stores
// to the registry, as they came: their secret keys go to it alone, which
// seals them.
func (s *Server) registryStores(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	var body any
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var raw json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&raw); err != nil {
			writeError(w, http.StatusBadRequest, "the body must be a blob store, as JSON")
			return
		}
		body = raw
	}
	path := "/admin/v1/stores"
	switch {
	case r.PathValue("name") != "":
		path += "/" + url.PathEscape(r.PathValue("name"))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/stores/test"):
		path += "/test"
	}
	s.relay(w, r, r.Method, path, nil, body)
}

// registryRules hands the registry's admins' calls about replication
// rules to the registry.
func (s *Server) registryRules(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	var body any
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var raw json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&raw); err != nil {
			writeError(w, http.StatusBadRequest, "the body must be a replication rule, as JSON")
			return
		}
		body = raw
	}
	path := "/admin/v1/rules"
	if id := r.PathValue("id"); id != "" {
		path += "/" + url.PathEscape(id)
	}
	s.relay(w, r, r.Method, path, nil, body)
}

// registryCancelJob stops a running job, for the registry's admins.
func (s *Server) registryCancelJob(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodDelete, "/admin/v1/jobs/"+url.PathEscape(r.PathValue("id")), nil, nil)
}

// ---------------------------------------------------------------- robot accounts

func (s *Server) robotsReady(w http.ResponseWriter, r *http.Request) bool {
	if !s.registryAdminOnly(w, r) {
		return false
	}
	if s.cfg.Accounts == nil {
		writeError(w, http.StatusNotFound, "robot accounts are kept with the users the server keeps, which this server has none of")
		return false
	}
	return true
}

func (s *Server) robotAudit(r *http.Request, action, name, detail string, err error) {
	u := userOf(r)
	e := AuditEntry{Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: action, Object: accounts.RobotPrefix + name, Detail: detail, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	s.audit.add(e)
	s.log.Info("audit", "user", e.User, "action", e.Action, "object", e.Object, "detail", e.Detail, "ok", e.OK, "error", e.Error)
}

func (s *Server) robotList(w http.ResponseWriter, r *http.Request) {
	if !s.robotsReady(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Accounts.Robots())
}

func (s *Server) robotError(w http.ResponseWriter, err error) {
	if errors.Is(err, accounts.ErrRobotNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	accountError(w, err)
}

func (s *Server) robotAdd(w http.ResponseWriter, r *http.Request) {
	if !s.robotsReady(w, r) {
		return
	}
	var in accounts.RobotInput
	if !readJSON(w, r, &in, `{"name", "description", "grants", "expires"}`) {
		return
	}
	e, secret, err := s.cfg.Accounts.AddRobot(r.Context(), in, userOf(r).Name)
	s.robotAudit(r, "robot-add", strings.TrimPrefix(in.Name, accounts.RobotPrefix), strings.Join(e.Grants, ", "), err)
	if err != nil {
		s.robotError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"robot": e, "secret": secret})
}

func (s *Server) robotUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.robotsReady(w, r) {
		return
	}
	var in accounts.RobotInput
	if !readJSON(w, r, &in, `{"description", "grants", "expires", "disabled"}`) {
		return
	}
	_, after, err := s.cfg.Accounts.UpdateRobot(r.Context(), r.PathValue("name"), in, userOf(r).Name)
	s.robotAudit(r, "robot-change", r.PathValue("name"), strings.Join(after.Grants, ", "), err)
	if err != nil {
		s.robotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, after)
}

func (s *Server) robotRotate(w http.ResponseWriter, r *http.Request) {
	if !s.robotsReady(w, r) {
		return
	}
	e, secret, err := s.cfg.Accounts.RotateRobot(r.Context(), r.PathValue("name"), userOf(r).Name)
	s.robotAudit(r, "robot-rotate", r.PathValue("name"), "", err)
	if err != nil {
		s.robotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"robot": e, "secret": secret})
}

func (s *Server) robotRemove(w http.ResponseWriter, r *http.Request) {
	if !s.robotsReady(w, r) {
		return
	}
	_, err := s.cfg.Accounts.RemoveRobot(r.Context(), r.PathValue("name"))
	s.robotAudit(r, "robot-remove", r.PathValue("name"), "", err)
	if err != nil {
		s.robotError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
