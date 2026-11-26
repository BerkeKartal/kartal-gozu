package registry

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

// kartal-server asks what the registry knows of the images the clusters
// run: given as they run them (repo:tag, repo@digest, or a bare digest),
// it answers each one's repository, digest and scan.

// ImageScan is what the registry knows of an image a cluster runs.
type ImageScan struct {
	Repo   string    `json:"repo"`
	Digest string    `json:"digest"`
	Kind   string    `json:"kind"`
	Scan   *ScanView `json:"scan,omitempty"`
	// Critical counts its critical vulnerabilities that its project does
	// not allow: an index's, the most of its images'.
	Critical int `json:"critical"`
}

// maxLookup is how many images one lookup may ask of.
const maxLookup = 20000

// resolveRef finds an image as a cluster names it: its repository and
// digest, or nothing.
func (s *Server) resolveRef(ref string) (string, string) {
	if blobstore.ValidDigest(ref) {
		if holders := s.cfg.DB.Holders(ref); len(holders) > 0 {
			return holders[0], ref
		}
		return "", ""
	}
	if name, digest, ok := strings.Cut(ref, "@"); ok {
		if _, ok := s.cfg.DB.Artifact(name, digest); ok {
			return name, digest
		}
		return "", ""
	}
	i := strings.LastIndexByte(ref, ':')
	if i <= strings.LastIndexByte(ref, '/') {
		return "", ""
	}
	if digest, ok := s.cfg.DB.Resolve(ref[:i], ref[i+1:]); ok {
		return ref[:i], digest
	}
	return "", ""
}

// children are an index's images as its repository holds them.
func (s *Server) children(repo string, a meta.Artifact) map[string]meta.Artifact {
	out := map[string]meta.Artifact{}
	for _, m := range a.Manifests {
		if c, ok := s.cfg.DB.Artifact(repo, m.Digest); ok {
			out[m.Digest] = c
		}
	}
	return out
}

// LookupImage is what the registry knows of an image as a cluster names it.
func (s *Server) LookupImage(ref string) (ImageScan, bool) {
	repo, digest := s.resolveRef(ref)
	if repo == "" {
		return ImageScan{}, false
	}
	a, ok := s.cfg.DB.Artifact(repo, digest)
	if !ok {
		return ImageScan{}, false
	}
	p, _ := s.cfg.DB.Project(meta.ProjectOf(repo))
	kids := s.children(repo, a)
	critical := p
	critical.BlockSeverity = scanner.Critical
	return ImageScan{Repo: repo, Digest: digest, Kind: a.Kind, Scan: s.withPolicy(s.scanView(a, kids), p, a, kids),
		Critical: s.blocked(critical, a, kids)}, true
}

func (s *Server) lookupScans(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Refs []string `json:"refs"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&in); err != nil {
		adminError(w, http.StatusBadRequest, "the body is not the JSON expected: "+err.Error())
		return
	}
	if len(in.Refs) > maxLookup {
		adminError(w, http.StatusBadRequest, "too many images at once")
		return
	}
	out := map[string]ImageScan{}
	for _, ref := range in.Refs {
		if _, done := out[ref]; done {
			continue
		}
		if img, ok := s.LookupImage(ref); ok {
			out[ref] = img
		}
	}
	adminJSON(w, http.StatusOK, map[string]any{"images": out})
}
