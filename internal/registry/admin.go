package registry

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// UserHeader names the person on whose behalf kartal-server calls the
// admin API, for the registry's own log.
const UserHeader = "X-Kartal-User"

// Admin serves the API kartal-server shows and manages the registry with.
// Every call needs the secret both share; who may do what was decided by
// kartal-server already.
func (s *Server) Admin(secret string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/status", s.status)
	mux.HandleFunc("GET /admin/v1/projects", s.listProjects)
	mux.HandleFunc("POST /admin/v1/projects", s.createProject)
	mux.HandleFunc("GET /admin/v1/projects/{name}", s.getProject)
	mux.HandleFunc("PUT /admin/v1/projects/{name}", s.updateProject)
	mux.HandleFunc("DELETE /admin/v1/projects/{name}", s.deleteProject)
	mux.HandleFunc("GET /admin/v1/projects/{name}/repositories", s.listRepositories)
	mux.HandleFunc("GET /admin/v1/repository", s.getRepository)
	mux.HandleFunc("DELETE /admin/v1/repository", s.deleteRepository)
	mux.HandleFunc("GET /admin/v1/artifact", s.getArtifact)
	mux.HandleFunc("DELETE /admin/v1/artifact", s.deleteArtifact)
	mux.HandleFunc("PUT /admin/v1/tag", s.putTag)
	mux.HandleFunc("DELETE /admin/v1/tag", s.deleteTag)
	mux.HandleFunc("GET /admin/v1/events", s.events)
	mux.HandleFunc("GET /admin/v1/jobs", s.listJobs)
	mux.HandleFunc("POST /admin/v1/jobs", s.startJob)
	mux.HandleFunc("GET /admin/v1/jobs/{id}", s.getJob)
	mux.HandleFunc("PUT /admin/v1/schedules/{kind}", s.putSchedule)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		tok := ""
		if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
		if secret == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) != 1 {
			adminError(w, http.StatusUnauthorized, "the registry's shared secret is needed")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func adminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func adminError(w http.ResponseWriter, status int, msg string) {
	adminJSON(w, status, map[string]string{"error": msg})
}

func actor(r *http.Request) string { return r.Header.Get(UserHeader) }

func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v); err != nil {
		adminError(w, http.StatusBadRequest, "the body is not the JSON expected: "+err.Error())
		return false
	}
	return true
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	var blobs, size int64
	if err := s.cfg.Store.Walk(func(_ string, n int64, _ time.Time) error {
		blobs++
		size += n
		return nil
	}); err != nil {
		s.cfg.Log.Warn("registry: walking the blobs", "err", err)
	}
	projects := s.cfg.DB.Projects()
	var repos, artifacts int
	for _, p := range projects {
		repos += p.Repositories
		artifacts += p.Artifacts
	}
	out := map[string]any{"projects": len(projects), "repositories": repos, "artifacts": artifacts, "blobs": blobs, "size": size}
	if err := s.cfg.DB.Healthy(); err != nil {
		out["problem"] = "the metadata snapshot fails: " + err.Error()
	}
	adminJSON(w, http.StatusOK, out)
}

func (s *Server) listProjects(w http.ResponseWriter, _ *http.Request) {
	adminJSON(w, http.StatusOK, s.cfg.DB.Projects())
}

type projectInput struct {
	Name        string   `json:"name"`
	Public      bool     `json:"public"`
	Description string   `json:"description"`
	Immutable   []string `json:"immutable"`
	Quota       int64    `json:"quota"`
}

// projectRules checks a project's immutable tags and quota, answering the
// request when they are wrong.
func projectRules(w http.ResponseWriter, immutable []string, quota int64) bool {
	if len(immutable) > 20 {
		adminError(w, http.StatusBadRequest, "at most 20 patterns of immutable tags")
		return false
	}
	for _, p := range immutable {
		if !meta.ValidTagPattern(p) {
			adminError(w, http.StatusBadRequest, fmt.Sprintf("%q is not a pattern of tags, such as v* or release-?.*", p))
			return false
		}
	}
	if quota < 0 {
		adminError(w, http.StatusBadRequest, "a quota is a number of bytes, 0 for no limit")
		return false
	}
	return true
}

// adminDenied answers a change the project's rules refuse, and tells
// whether it did.
func adminDenied(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, meta.ErrImmutable), errors.Is(err, meta.ErrInUse):
		adminError(w, http.StatusConflict, err.Error())
	case errors.Is(err, meta.ErrQuota):
		adminError(w, http.StatusForbidden, err.Error())
	default:
		return false
	}
	return true
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var in projectInput
	if !readBody(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !ValidProject(in.Name) {
		adminError(w, http.StatusBadRequest, "a project name is lowercase letters and digits, which . _ - may join, at most 64")
		return
	}
	if len(in.Description) > 500 {
		adminError(w, http.StatusBadRequest, "the description is longer than 500 characters")
		return
	}
	if !projectRules(w, in.Immutable, in.Quota) {
		return
	}
	if len(in.Immutable) == 0 {
		in.Immutable = nil
	}
	err := s.cfg.DB.CreateProject(meta.Project{Name: in.Name, Public: in.Public, Description: in.Description, Immutable: in.Immutable,
		Quota: in.Quota}, actor(r))
	if errors.Is(err, meta.ErrExists) {
		adminError(w, http.StatusConflict, "a project of that name exists")
		return
	}
	if err != nil {
		s.adminInternal(w, "making a project", err)
		return
	}
	p, _ := s.cfg.DB.Project(in.Name)
	adminJSON(w, http.StatusCreated, p)
}

func (s *Server) adminInternal(w http.ResponseWriter, what string, err error) {
	s.cfg.Log.Error("registry: "+what, "err", err)
	adminError(w, http.StatusInternalServerError, what+" failed: "+err.Error())
}

func (s *Server) projectInfo(name string) (meta.ProjectInfo, bool) {
	for _, p := range s.cfg.DB.Projects() {
		if p.Name == name {
			return p, true
		}
	}
	return meta.ProjectInfo{}, false
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	p, ok := s.projectInfo(r.PathValue("name"))
	if !ok {
		adminError(w, http.StatusNotFound, "no such project")
		return
	}
	adminJSON(w, http.StatusOK, p)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	var in meta.ProjectChange
	if !readBody(w, r, &in) {
		return
	}
	if in.Description != nil && len(*in.Description) > 500 {
		adminError(w, http.StatusBadRequest, "the description is longer than 500 characters")
		return
	}
	var immutable []string
	var quota int64
	if in.Immutable != nil {
		immutable = *in.Immutable
	}
	if in.Quota != nil {
		quota = *in.Quota
	}
	if !projectRules(w, immutable, quota) {
		return
	}
	p, err := s.cfg.DB.UpdateProject(r.PathValue("name"), in, actor(r))
	if errors.Is(err, meta.ErrNoProject) {
		adminError(w, http.StatusNotFound, "no such project")
		return
	}
	if err != nil {
		s.adminInternal(w, "changing a project", err)
		return
	}
	adminJSON(w, http.StatusOK, p)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	err := s.cfg.DB.DeleteProject(r.PathValue("name"), actor(r))
	switch {
	case errors.Is(err, meta.ErrNoProject):
		adminError(w, http.StatusNotFound, "no such project")
	case errors.Is(err, meta.ErrNotEmpty):
		adminError(w, http.StatusConflict, "the project still has repositories; delete them first")
	case err != nil:
		s.adminInternal(w, "deleting a project", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) listRepositories(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.cfg.DB.Project(name); !ok {
		adminError(w, http.StatusNotFound, "no such project")
		return
	}
	repos := s.cfg.DB.Repositories(name)
	if repos == nil {
		repos = []meta.RepoInfo{}
	}
	adminJSON(w, http.StatusOK, repos)
}

// ArtifactSummary is an artifact as lists show it.
type ArtifactSummary struct {
	meta.ArtifactInfo
	// Total is the manifest with everything it refers to that the
	// repository holds: an image's config and layers, an index's images.
	Total int64 `json:"total"`
	// Referrers counts the signatures, SBOMs and other artifacts about it.
	Referrers int `json:"referrers"`
}

// total sums an artifact and what it refers to.
func total(a meta.Artifact, byDigest map[string]meta.Artifact) int64 {
	n := a.Size
	if a.Config != nil {
		n += a.Config.Size
	}
	for _, l := range a.Layers {
		n += l.Size
	}
	for _, m := range a.Manifests {
		if child, ok := byDigest[m.Digest]; ok {
			n += total(child, nil)
		} else {
			n += m.Size
		}
	}
	return n
}

func (s *Server) getRepository(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	arts, ok := s.cfg.DB.Artifacts(name)
	if !ok {
		adminError(w, http.StatusNotFound, "no such repository")
		return
	}
	byDigest := map[string]meta.Artifact{}
	refs := map[string]int{}
	for _, a := range arts {
		byDigest[a.Digest] = a.Artifact
		if a.Subject != "" {
			refs[a.Subject]++
		}
	}
	out := make([]ArtifactSummary, 0, len(arts))
	for _, a := range arts {
		out = append(out, ArtifactSummary{ArtifactInfo: a, Total: total(a.Artifact, byDigest), Referrers: refs[a.Digest]})
	}
	var info meta.RepoInfo
	for _, ri := range s.cfg.DB.Repositories(meta.ProjectOf(name)) {
		if ri.Name == name {
			info = ri
		}
	}
	adminJSON(w, http.StatusOK, map[string]any{"repository": info, "artifacts": out})
}

func (s *Server) deleteRepository(w http.ResponseWriter, r *http.Request) {
	err := s.cfg.DB.DeleteRepository(r.URL.Query().Get("name"), actor(r))
	if adminDenied(w, err) {
		return
	}
	if errors.Is(err, meta.ErrNotFound) {
		adminError(w, http.StatusNotFound, "no such repository")
		return
	}
	if err != nil {
		s.adminInternal(w, "deleting a repository", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ArtifactDetail is everything about one artifact.
type ArtifactDetail struct {
	ArtifactSummary
	// Manifest is the manifest as pushed.
	Manifest json.RawMessage `json:"manifest"`
	// Config is an image's config: its platform, creation, labels and the
	// steps that built it.
	Config *manifest.Config `json:"config,omitempty"`
	// Children are an index's images, as the repository holds them.
	Children []ArtifactSummary `json:"children,omitempty"`
	// ReferrerList are the artifacts whose subject this is.
	ReferrerList []meta.Artifact `json:"referrerList"`
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	repo, ref := q.Get("repo"), q.Get("ref")
	digest, ok := s.cfg.DB.Resolve(repo, ref)
	if !ok {
		adminError(w, http.StatusNotFound, "no such artifact")
		return
	}
	arts, _ := s.cfg.DB.Artifacts(repo)
	byDigest := map[string]meta.Artifact{}
	var info meta.ArtifactInfo
	for _, a := range arts {
		byDigest[a.Digest] = a.Artifact
		if a.Digest == digest {
			info = a
		}
	}
	referrers := s.cfg.DB.Referrers(repo, digest, "")
	if referrers == nil {
		referrers = []meta.Artifact{}
	}
	d := ArtifactDetail{ArtifactSummary: ArtifactSummary{ArtifactInfo: info, Total: total(info.Artifact, byDigest), Referrers: len(referrers)},
		ReferrerList: referrers}
	if f, _, err := s.cfg.Store.Open(digest); err == nil {
		b, err := io.ReadAll(io.LimitReader(f, manifest.MaxSize))
		f.Close()
		if err == nil && json.Valid(b) {
			d.Manifest = b
		}
	}
	if info.Config != nil && manifest.IsImageConfig(info.Config.MediaType) {
		d.Config = s.readConfig(info.Config.Digest)
	}
	for _, m := range info.Manifests {
		if child, ok := byDigest[m.Digest]; ok {
			d.Children = append(d.Children, ArtifactSummary{ArtifactInfo: meta.ArtifactInfo{Artifact: child, Tags: []string{}}, Total: total(child, nil)})
		}
	}
	adminJSON(w, http.StatusOK, d)
}

func (s *Server) deleteArtifact(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !blobstore.ValidDigest(q.Get("digest")) {
		adminError(w, http.StatusBadRequest, "an artifact is deleted by its digest")
		return
	}
	err := s.cfg.DB.DeleteArtifact(q.Get("repo"), q.Get("digest"), actor(r))
	if errors.Is(err, meta.ErrNotFound) {
		adminError(w, http.StatusNotFound, "no such artifact")
		return
	}
	if errors.Is(err, meta.ErrInUse) {
		adminError(w, http.StatusConflict, err.Error()+"; delete the index first")
		return
	}
	if adminDenied(w, err) {
		return
	}
	if err != nil {
		s.adminInternal(w, "deleting an artifact", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putTag(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var in struct {
		Digest string `json:"digest"`
	}
	if !readBody(w, r, &in) {
		return
	}
	if !ValidTag(q.Get("tag")) {
		adminError(w, http.StatusBadRequest, "a tag is letters, digits, _ . -, at most 128, not starting with . or -")
		return
	}
	err := s.cfg.DB.Tag(q.Get("repo"), q.Get("tag"), in.Digest, actor(r))
	if adminDenied(w, err) {
		return
	}
	if errors.Is(err, meta.ErrNotFound) {
		adminError(w, http.StatusNotFound, "no such artifact")
		return
	}
	if err != nil {
		s.adminInternal(w, "tagging", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteTag(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	err := s.cfg.DB.Untag(q.Get("repo"), q.Get("tag"), actor(r))
	if adminDenied(w, err) {
		return
	}
	if errors.Is(err, meta.ErrNotFound) {
		adminError(w, http.StatusNotFound, "no such tag")
		return
	}
	if err != nil {
		s.adminInternal(w, "removing a tag", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ScheduleView is a schedule with when it runs next.
type ScheduleView struct {
	meta.Schedule
	Next *time.Time `json:"next,omitempty"`
}

func (s *Server) scheduleView(sc meta.Schedule) ScheduleView {
	v := ScheduleView{Schedule: sc}
	if next := s.NextRun(sc); !next.IsZero() {
		next = next.UTC()
		v.Next = &next
	}
	return v
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	schedules := []ScheduleView{}
	for _, sc := range s.cfg.DB.Schedules() {
		schedules = append(schedules, s.scheduleView(sc))
	}
	adminJSON(w, http.StatusOK, map[string]any{"jobs": s.cfg.DB.Jobs(limit), "schedules": schedules, "zone": s.zone().String()})
}

func (s *Server) startJob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind   string `json:"kind"`
		DryRun bool   `json:"dryRun"`
	}
	if !readBody(w, r, &in) {
		return
	}
	j, err := s.StartJob(in.Kind, in.DryRun, actor(r))
	switch {
	case errors.Is(err, ErrRunning):
		adminError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrJob):
		adminError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		s.adminInternal(w, "starting a job", err)
	default:
		adminJSON(w, http.StatusAccepted, j)
	}
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	j, ok := s.cfg.DB.Job(r.PathValue("id"))
	if !ok {
		adminError(w, http.StatusNotFound, "no such job")
		return
	}
	adminJSON(w, http.StatusOK, j)
}

func (s *Server) putSchedule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cron    string `json:"cron"`
		Enabled bool   `json:"enabled"`
	}
	if !readBody(w, r, &in) {
		return
	}
	sc, err := s.SetSchedule(r.PathValue("kind"), in.Cron, in.Enabled, actor(r))
	switch {
	case errors.Is(err, ErrJob):
		adminError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrSchedule):
		adminError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		s.adminInternal(w, "setting a schedule", err)
	default:
		adminJSON(w, http.StatusOK, s.scheduleView(sc))
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	var keep func(string) bool
	if p := q.Get("project"); p != "" {
		keep = func(project string) bool { return project == p }
	}
	adminJSON(w, http.StatusOK, s.cfg.DB.Events(keep, limit))
}
