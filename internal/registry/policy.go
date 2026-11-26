package registry

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

// A project may refuse pulls of images with vulnerabilities of a severity
// or worse (BlockSeverity), but for those its allowlist names. It goes by
// an image's last scan; one never scanned is let through, and so are the
// scanner's own pulls. Pulling an index is not refused, its images are.

// vulnRef is what the policy needs of a vulnerability.
type vulnRef struct {
	id   string
	rank int
}

// maxVulnCache is how many images' vulnerabilities are kept in memory.
const maxVulnCache = 256

// vulnRefs are an image's vulnerabilities, as its last report lists them.
func (s *Server) vulnRefs(digest string) ([]vulnRef, bool) {
	s.vulnMu.Lock()
	refs, ok := s.vulnCache[digest]
	s.vulnMu.Unlock()
	if ok {
		return refs, true
	}
	res, err := s.readReport(digest)
	if err != nil {
		return nil, false
	}
	refs = make([]vulnRef, 0, len(res.Report.Vulnerabilities))
	for _, v := range res.Report.Vulnerabilities {
		refs = append(refs, vulnRef{id: v.ID, rank: scanner.Rank(v.Severity)})
	}
	s.vulnMu.Lock()
	if len(s.vulnCache) >= maxVulnCache {
		for k := range s.vulnCache {
			delete(s.vulnCache, k)
			break
		}
	}
	s.vulnCache[digest] = refs
	s.vulnMu.Unlock()
	return refs, true
}

// forgetVulns drops what is kept of an image's vulnerabilities, when a
// new report replaces them.
func (s *Server) forgetVulns(digest string) {
	s.vulnMu.Lock()
	delete(s.vulnCache, digest)
	s.vulnMu.Unlock()
}

// Blocking counts an image's vulnerabilities that a project's policy
// refuses its pulls for: of its severity or worse, not allowed.
func (s *Server) Blocking(p meta.Project, digest string) int {
	if p.BlockSeverity == "" {
		return 0
	}
	sc, ok := s.cfg.DB.Scan(digest)
	if !ok || sc.Summary == nil {
		return 0
	}
	n := sc.Summary.AtLeast(p.BlockSeverity)
	if n == 0 || len(p.Allowlist) == 0 {
		return n
	}
	refs, ok := s.vulnRefs(digest)
	if !ok {
		// No report to tell them apart: the summary decides.
		return n
	}
	least := scanner.Rank(p.BlockSeverity)
	n = 0
	for _, v := range refs {
		if v.rank >= least && !p.Allows(v.id) {
			n++
		}
	}
	return n
}

// blocked is how many vulnerabilities refuse an artifact's pulls: an
// image's, or the most of an index's images.
func (s *Server) blocked(p meta.Project, a meta.Artifact, byDigest map[string]meta.Artifact) int {
	switch a.Kind {
	case "image":
		return s.Blocking(p, a.Digest)
	case "index":
		n := 0
		for _, m := range a.Manifests {
			if c, ok := byDigest[m.Digest]; ok && c.Kind == "image" {
				n = max(n, s.Blocking(p, m.Digest))
			}
		}
		return n
	}
	return 0
}

// pullPolicy refuses the pull of an image its project's policy does not
// let through, or is nil.
func (s *Server) pullPolicy(repo string, a meta.Artifact) *apiError {
	if a.Kind != "image" {
		return nil
	}
	p, ok := s.cfg.DB.Project(meta.ProjectOf(repo))
	if !ok {
		return nil
	}
	n := s.Blocking(p, a.Digest)
	if n == 0 {
		return nil
	}
	return errorf(http.StatusPreconditionFailed, "DENIED",
		"%s@%s cannot be pulled: the project %s refuses images with %s or worse vulnerabilities it does not allow, and this one has %d; push a fixed image, or the project's admins may allow them",
		repo, a.Digest, p.Name, strings.ToLower(p.BlockSeverity), n)
}

// vulnIDRE is a vulnerability's ID: CVE-2026-1234, GHSA-xxxx-xxxx-xxxx...
var vulnIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,79}$`)

// maxAllowlist is how many vulnerabilities a project may allow.
const maxAllowlist = 500

// scanPolicy checks and tidies a project's pull policy: the severity in
// capitals, the allowlist without blanks or repeats.
func scanPolicy(severity *string, allowlist *[]string) error {
	if severity != nil {
		*severity = strings.ToUpper(strings.TrimSpace(*severity))
		if r := scanner.Rank(*severity); *severity != "" && r < 1 {
			return fmt.Errorf("%q is not a severity to refuse pulls for: CRITICAL, HIGH, MEDIUM or LOW, or empty for none", *severity)
		}
	}
	if allowlist != nil {
		var out []string
		seen := map[string]bool{}
		for _, id := range *allowlist {
			id = strings.TrimSpace(id)
			if id == "" || seen[strings.ToUpper(id)] {
				continue
			}
			if !vulnIDRE.MatchString(id) {
				return fmt.Errorf("%q is not a vulnerability's ID, such as CVE-2026-1234", id)
			}
			seen[strings.ToUpper(id)] = true
			out = append(out, id)
		}
		if len(out) > maxAllowlist {
			return fmt.Errorf("a project may allow at most %d vulnerabilities", maxAllowlist)
		}
		*allowlist = out
	}
	return nil
}
