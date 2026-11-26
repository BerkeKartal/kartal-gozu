package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
)

// The registry's scans: anyone who sees a project sees its images'
// vulnerabilities and SBOMs; its operators have images scanned; the
// registry's admins see the scanner and update its databases.

func (s *Server) routeRegistryScans(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/registry/scan", s.signedIn(s.registryScan))
	mux.HandleFunc("GET /api/v1/registry/vulnerabilities", s.signedIn(s.registryVulnerabilities))
	mux.HandleFunc("GET /api/v1/registry/sbom", s.signedIn(s.registrySBOM))
	mux.HandleFunc("GET /api/v1/registry/scanner", s.signedIn(s.registryScanner))
	mux.HandleFunc("POST /api/v1/registry/scanner/db", s.signedIn(s.registryScannerDB))
}

func (s *Server) registryScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Repo   string `json:"repo"`
		Digest string `json:"digest"`
	}
	if !readJSON(w, r, &body, `{"repo": "team-a/web", "digest": "sha256:..."}`) {
		return
	}
	r.URL.RawQuery = url.Values{"repo": {body.Repo}}.Encode()
	_, project, ok := repoParam(w, r, "repo")
	if !ok || !s.mayIn(w, r, project, auth.Operator) {
		return
	}
	s.relay(w, r, http.MethodPost, "/admin/v1/scan", nil, body)
}

// imageParams reads ?repo= and ?digest= for a viewer of the project.
func (s *Server) imageParams(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	repo, project, ok := repoParam(w, r, "repo")
	if !ok {
		return nil, false
	}
	digest := r.URL.Query().Get("digest")
	if !blobstore.ValidDigest(digest) {
		writeError(w, http.StatusBadRequest, "digest must be an image's digest, sha256:...")
		return nil, false
	}
	if !s.mayIn(w, r, project, auth.Viewer) {
		return nil, false
	}
	return url.Values{"repo": {repo}, "digest": {digest}}, true
}

func (s *Server) registryVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q, ok := s.imageParams(w, r)
	if !ok {
		return
	}
	s.relay(w, r, http.MethodGet, "/admin/v1/vulnerabilities", q, nil)
}

// registrySBOM hands an image's SBOM over as a file to keep.
func (s *Server) registrySBOM(w http.ResponseWriter, r *http.Request) {
	q, ok := s.imageParams(w, r)
	if !ok {
		return
	}
	status, b, err := s.registryCall(r, http.MethodGet, "/admin/v1/sbom", q, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(b)
		return
	}
	name := path.Base(q.Get("repo")) + "-" + strings.TrimPrefix(q.Get("digest"), "sha256:")[:12] + ".cdx.json"
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(b)
}

func (s *Server) registryScanner(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodGet, "/admin/v1/scanner", nil, nil)
}

func (s *Server) registryScannerDB(w http.ResponseWriter, r *http.Request) {
	if !s.registryAdminOnly(w, r) {
		return
	}
	s.relay(w, r, http.MethodPost, "/admin/v1/scanner/db", nil, json.RawMessage(`{}`))
}
