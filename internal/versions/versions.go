// Package versions compares the versions the server sees: its own, its
// agents', and the Kubernetes versions the clusters run.
//
// What is newer than them (changes to Kartal Gözü, and the known
// vulnerabilities of a Kubernetes version) is not looked up here: the
// server may have no way out to the internet. The web UI asks GitHub and
// OSV.dev from the browser instead.
package versions

import (
	"regexp"
	"strings"
)

var (
	describeRE = regexp.MustCompile(`-g([0-9a-f]{7,40})$`)
	commitRE   = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	repoRE     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

// Known tells whether a build version says anything: not "dev" or empty.
func Known(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "dev"
}

// Same tells whether two builds are of the same version: "7804c92" and
// "7804c92-dirty", a short and a long commit, or a commit and git
// describe's "v0.2.0-3-g7804c92" are.
func Same(a, b string) bool {
	norm := func(v string) string {
		v, _ = strings.CutSuffix(strings.ToLower(strings.TrimSpace(v)), "-dirty")
		if m := describeRE.FindStringSubmatch(v); m != nil {
			return m[1]
		}
		return v
	}
	x, y := norm(a), norm(b)
	if x == y {
		return true
	}
	if commitRE.MatchString(x) && commitRE.MatchString(y) {
		return strings.HasPrefix(x, y) || strings.HasPrefix(y, x)
	}
	return false
}

// KubeVersion is the upstream Kubernetes release a reported version stands
// for: "v1.33.11", "v1.33.11+k3s1" and "v1.33.11-eks-1a2b3c" are "1.33.11".
// It is empty when the text is no version.
func KubeVersion(reported string) string {
	s := strings.TrimPrefix(strings.TrimSpace(reported), "v")
	if i := strings.IndexAny(s, "+-"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return ""
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return ""
		}
	}
	return s
}

// ValidRepo tells whether a repository name is GitHub's "owner/name".
func ValidRepo(repo string) bool { return repoRE.MatchString(repo) }
