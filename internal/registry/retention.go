package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// Retention deletes the artifacts a project's rules pick and none keeps,
// but never one that runs, or may run, in a cluster, nor one with an
// immutable tag. kartal-server tells what the clusters run; a cluster that
// says nothing now (its agent is down) is taken at its last word, which
// the registry keeps.

// The ways a rule keeps artifacts.
const (
	KeepLatestPushed = "latestPushed"
	KeepLatestPulled = "latestPulled"
	KeepPushedWithin = "pushedWithin"
	KeepPulledWithin = "pulledWithin"
	KeepAlways       = "always"
)

// ClusterImages are the images a cluster runs or may run (its pods',
// workloads' and CronJobs'): their digests, and, of this registry, the
// repositories with their tags or digests (team-a/web:1.0,
// team-a/web@sha256:...). Known is false for a cluster that has said
// nothing since kartal-server started.
type ClusterImages struct {
	Name    string    `json:"name"`
	Known   bool      `json:"known"`
	At      time.Time `json:"at,omitempty"`
	Digests []string  `json:"digests"`
	Refs    []string  `json:"refs"`
}

// ImageSource tells what the clusters run.
type ImageSource interface {
	Running(ctx context.Context) ([]ClusterImages, error)
}

var digestIn = regexp.MustCompile(`sha256:[a-f0-9]{64}`)

// normalHost is a registry's host as references name it.
func normalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	h = strings.TrimSuffix(h, "/")
	return strings.TrimSuffix(h, ":443")
}

// ImageRef reads an image as a pod names it (or a kubelet's imageID): the
// digest it pins, if any, and, when it is of the registry at host, its
// repository with its tag, latest by default, or digest.
func ImageRef(ref, host string) (local, digest string) {
	if all := digestIn.FindAllString(ref, -1); len(all) > 0 {
		digest = all[len(all)-1]
	}
	if i := strings.Index(ref, "://"); i >= 0 {
		ref = ref[i+3:]
	}
	first, rest, ok := strings.Cut(ref, "/")
	if !ok || host == "" || normalHost(first) != normalHost(host) || !(strings.ContainsAny(first, ".:") || first == "localhost") {
		return "", digest
	}
	name, pinned, _ := strings.Cut(rest, "@")
	tag := "latest"
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name, tag = name[:i], name[i+1:]
	}
	if !ValidName(name) || !ValidTag(tag) {
		return "", digest
	}
	// A digest pins the image, whatever the tag says.
	if pinned != "" {
		if digest == "" {
			return "", ""
		}
		return name + "@" + digest, digest
	}
	return name + ":" + tag, digest
}

// ValidRetention checks a project's rules.
func ValidRetention(rules []meta.RetentionRule) error {
	if len(rules) > 20 {
		return errors.New("at most 20 retention rules")
	}
	for i, r := range rules {
		n := i + 1
		if r.Repositories != "" && r.Repositories != "**" {
			if _, err := path.Match(r.Repositories, ""); err != nil || len(r.Repositories) > 200 {
				return fmt.Errorf("rule %d: %q is not a pattern of repositories, such as web or charts/*", n, r.Repositories)
			}
		}
		if r.Tags != "" && r.Tags != "**" && !meta.ValidTagPattern(r.Tags) {
			return fmt.Errorf("rule %d: %q is not a pattern of tags, such as v* or **", n, r.Tags)
		}
		if r.Tags == "" && !r.Untagged {
			return fmt.Errorf("rule %d picks nothing: give it a pattern of tags, or the untagged", n)
		}
		switch r.Keep {
		case KeepLatestPushed, KeepLatestPulled:
			if r.Count < 1 || r.Count > 10000 {
				return fmt.Errorf("rule %d: how many it keeps is between 1 and 10000", n)
			}
		case KeepPushedWithin, KeepPulledWithin:
			if r.Days < 1 || r.Days > 36500 {
				return fmt.Errorf("rule %d: the days are between 1 and 36500", n)
			}
		case KeepAlways:
		default:
			return fmt.Errorf("rule %d: keep is latestPushed, latestPulled, pushedWithin, pulledWithin or always, not %q", n, r.Keep)
		}
	}
	return nil
}

func patternMatch(pattern, s string) bool {
	if pattern == "" || pattern == "**" {
		return true
	}
	ok, _ := path.Match(pattern, s)
	return ok
}

// picks tells whether a rule picks an artifact.
func picks(r meta.RetentionRule, a meta.ArtifactInfo) bool {
	if len(a.Tags) == 0 {
		return r.Untagged
	}
	if r.Tags == "" {
		return false
	}
	for _, t := range a.Tags {
		if r.Tags == "**" || patternMatch(r.Tags, t) {
			return true
		}
	}
	return false
}

func lastPull(a meta.ArtifactInfo) time.Time {
	if a.LastPull == nil {
		return time.Time{}
	}
	return *a.LastPull
}

// retain decides for one repository: what its rules pick, and which of
// those none keeps. The artifacts about others (signatures, SBOMs) and the
// images an index lists follow them, and are not picked themselves.
func retain(rules []meta.RetentionRule, rel string, arts []meta.ArtifactInfo, now time.Time) (picked, kept map[string]bool) {
	listed := map[string]bool{}
	for _, a := range arts {
		for _, m := range a.Manifests {
			listed[m.Digest] = true
		}
	}
	var candidates []meta.ArtifactInfo
	for _, a := range arts {
		if a.Subject == "" && !listed[a.Digest] {
			candidates = append(candidates, a)
		}
	}
	picked, kept = map[string]bool{}, map[string]bool{}
	for _, r := range rules {
		if !patternMatch(r.Repositories, rel) {
			continue
		}
		var sel []meta.ArtifactInfo
		for _, a := range candidates {
			if picks(r, a) {
				sel = append(sel, a)
				picked[a.Digest] = true
			}
		}
		switch r.Keep {
		case KeepLatestPushed:
			sort.SliceStable(sel, func(i, j int) bool { return sel[i].Pushed.After(sel[j].Pushed) })
			for i := 0; i < len(sel) && i < r.Count; i++ {
				kept[sel[i].Digest] = true
			}
		case KeepLatestPulled:
			sort.SliceStable(sel, func(i, j int) bool { return lastPull(sel[i]).After(lastPull(sel[j])) })
			for i := 0; i < len(sel) && i < r.Count; i++ {
				kept[sel[i].Digest] = true
			}
		case KeepPushedWithin, KeepPulledWithin:
			since := now.AddDate(0, 0, -r.Days)
			for _, a := range sel {
				at := a.Pushed
				if r.Keep == KeepPulledWithin {
					at = lastPull(a)
				}
				if at.After(since) {
					kept[a.Digest] = true
				}
			}
		case KeepAlways:
			for _, a := range sel {
				kept[a.Digest] = true
			}
		}
	}
	return picked, kept
}

// RetentionReport is what retention did, or, in a dry run, would do.
type RetentionReport struct {
	DryRun  bool      `json:"dryRun"`
	Project string    `json:"project,omitempty"`
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	// Projects are those with rules; Picked the artifacts their rules
	// picked, Kept those some rule kept.
	Projects int `json:"projects"`
	Picked   int `json:"picked"`
	Kept     int `json:"kept"`
	// Protected are those no rule kept that stay as they run in a cluster
	// or have an immutable tag.
	Protected int `json:"protected"`
	// Deleted are those deleted; Removed says which (the first 500).
	Deleted int       `json:"deleted"`
	Removed []Removal `json:"removed"`
	// Unknown are the clusters taken at their last word, or for running
	// nothing, as they said nothing now.
	Unknown []string `json:"unknown,omitempty"`
}

// Removal is an artifact retention deleted.
type Removal struct {
	Repo   string    `json:"repo"`
	Digest string    `json:"digest"`
	Tags   []string  `json:"tags"`
	Pushed time.Time `json:"pushed"`
}

func (r RetentionReport) String() string {
	verb := "deleted"
	if r.DryRun {
		verb = "would delete"
	}
	return fmt.Sprintf("%d artifacts picked, %d kept, %d protected; %s %d", r.Picked, r.Kept, r.Protected, verb, r.Deleted)
}

// clusterImages are the digests and references that run in the clusters, as each
// says now or said last.
func (s *Server) clusterImages(ctx context.Context) (map[string]bool, map[string]bool, []string, error) {
	if s.cfg.Running == nil {
		return nil, nil, nil, errors.New("nothing tells the registry what runs in the clusters, so it deletes nothing")
	}
	now, err := s.cfg.Running.Running(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("what runs in the clusters could not be known: %w", err)
	}
	for _, c := range now {
		if c.Known {
			if err := s.cfg.DB.SetRunning(c.Name, meta.RunningImages{At: c.At, Digests: c.Digests, Refs: c.Refs}); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	// The clusters there are: those that said nothing now count as they
	// said last; one no longer there counts for nothing.
	digests, refs := map[string]bool{}, map[string]bool{}
	var unknown []string
	last := s.cfg.DB.Running()
	for _, c := range now {
		if !c.Known {
			unknown = append(unknown, c.Name)
		}
		ri := last[c.Name]
		for _, d := range ri.Digests {
			digests[d] = true
		}
		for _, r := range ri.Refs {
			refs[r] = true
		}
	}
	sort.Strings(unknown)
	return digests, refs, unknown, nil
}

// Retention applies the projects' rules, of one project or of all.
func (s *Server) Retention(ctx context.Context, project string, dryRun bool, user string) (RetentionReport, error) {
	start := time.Now()
	rep := RetentionReport{DryRun: dryRun, Project: project, Started: s.now().UTC(), Removed: []Removal{}}
	var projects []meta.Project
	for _, p := range s.cfg.DB.Projects() {
		if (project == "" || p.Name == project) && len(p.Retention) > 0 {
			projects = append(projects, p.Project)
		}
	}
	rep.Projects = len(projects)
	// Without rules there is nothing to decide, nor to ask.
	if len(projects) == 0 {
		rep.Seconds = time.Since(start).Seconds()
		return rep, nil
	}
	digests, refs, unknown, err := s.clusterImages(ctx)
	rep.Unknown = unknown
	if err != nil {
		return rep, err
	}
	now := s.now()
	for _, p := range projects {
		for _, ri := range s.cfg.DB.Repositories(p.Name) {
			if err := ctx.Err(); err != nil {
				return rep, err
			}
			if err := s.retainIn(p, ri.Name, digests, refs, now, dryRun, user, &rep); err != nil {
				return rep, err
			}
		}
	}
	rep.Seconds = time.Since(start).Seconds()
	return rep, nil
}

// retainIn applies the rules to a repository. Deleting an index lets the
// images it listed be picked, so it looks again, a few times at most.
func (s *Server) retainIn(p meta.Project, repo string, digests, refs map[string]bool, now time.Time, dryRun bool, user string,
	rep *RetentionReport) error {
	rel := strings.TrimPrefix(repo, p.Name+"/")
	seen := map[string]bool{}
	for pass := 0; pass < 3; pass++ {
		arts, ok := s.cfg.DB.Artifacts(repo)
		if !ok {
			return nil
		}
		picked, kept := retain(p.Retention, rel, arts, now)
		byDigest := map[string]meta.ArtifactInfo{}
		for _, a := range arts {
			byDigest[a.Digest] = a
		}
		runs := func(a meta.ArtifactInfo) bool {
			if digests[a.Digest] || refs[repo+"@"+a.Digest] {
				return true
			}
			for _, t := range a.Tags {
				if refs[repo+":"+t] {
					return true
				}
			}
			for _, m := range a.Manifests {
				if digests[m.Digest] || refs[repo+"@"+m.Digest] {
					return true
				}
			}
			return false
		}
		fixed := func(a meta.ArtifactInfo) bool {
			for _, t := range a.Tags {
				for _, pat := range p.Immutable {
					if ok, _ := path.Match(pat, t); ok {
						return true
					}
				}
			}
			return false
		}
		var gone []meta.ArtifactInfo
		for dg := range picked {
			if seen[dg] {
				continue
			}
			seen[dg] = true
			rep.Picked++
			a := byDigest[dg]
			switch {
			case kept[dg]:
				rep.Kept++
			case runs(a) || fixed(a):
				rep.Protected++
			default:
				gone = append(gone, a)
			}
		}
		sort.Slice(gone, func(i, j int) bool { return gone[i].Pushed.Before(gone[j].Pushed) })
		deletedIndex := false
		for _, a := range gone {
			if !dryRun {
				err := s.cfg.DB.DeleteArtifact(repo, a.Digest, user)
				if errors.Is(err, meta.ErrInUse) || errors.Is(err, meta.ErrImmutable) || errors.Is(err, meta.ErrNotFound) {
					rep.Protected++
					continue
				}
				if err != nil {
					return err
				}
				deletedIndex = deletedIndex || len(a.Manifests) > 0
			}
			rep.Deleted++
			if len(rep.Removed) < 500 {
				rep.Removed = append(rep.Removed, Removal{Repo: repo, Digest: a.Digest, Tags: a.Tags, Pushed: a.Pushed})
			}
		}
		if !deletedIndex {
			return nil
		}
	}
	return nil
}

// Running asks kartal-server what the clusters run.
func (a *ServerAuth) Running(ctx context.Context) ([]ClusterImages, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(a.URL, "/")+"/api/v1/registry/running", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Secret)
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("kartal-server answered %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Clusters []ClusterImages `json:"clusters"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Clusters, nil
}
