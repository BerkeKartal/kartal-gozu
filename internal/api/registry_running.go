package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// What Kartal Gözü knows that a registry alone does not: which of its
// images run where. The server matches the images the clusters' pods run
// with what the registry's scans found, for a page of the vulnerable
// images that run, and for an alert when one has a critical vulnerability
// its project does not allow.

// podImages are the images one pod runs, as the registry names them.
type podImages struct {
	cluster, namespace, workload string
	refs                         []string
}

// runningImages are the images the clusters' pods run, of the pods keep
// lets through. What a container was pulled by (its image ID, a digest)
// names its image best; a pod's images by tag count only for repositories
// none of its image IDs is of, and only of this registry's host, since a
// tag elsewhere may be another image.
func (s *Server) runningImages(keep func(cluster, namespace string) bool) []podImages {
	var out []podImages
	for _, c := range s.st.Clusters() {
		snap := c.Snapshot
		if snap == nil {
			continue
		}
		for _, p := range snap.Pods {
			if p.Phase == "Succeeded" || p.Phase == "Failed" || (keep != nil && !keep(c.Name, p.Namespace)) {
				continue
			}
			pi := podImages{cluster: c.Name, namespace: p.Namespace, workload: p.Owner}
			if pi.workload == "" {
				pi.workload = "Pod/" + p.Name
			}
			seen, covered := map[string]bool{}, map[string]bool{}
			add := func(ref string) {
				if ref != "" && !seen[ref] {
					seen[ref] = true
					pi.refs = append(pi.refs, ref)
				}
			}
			for _, id := range p.ImageIDs {
				local, digest := registry.ImageRef(id, "")
				switch {
				case strings.Contains(local, "@"):
					covered[strings.SplitN(local, "@", 2)[0]] = true
					add(local)
				case digest != "":
					add(digest)
				}
			}
			if s.cfg.RegistryPublic != "" {
				for _, img := range p.Images {
					local, _ := registry.ImageRef(img, s.cfg.RegistryPublic)
					name := local
					if i := strings.IndexAny(local, "@"); i >= 0 {
						name = local[:i]
					} else if i := strings.LastIndexByte(local, ':'); i >= 0 {
						name = local[:i]
					}
					if local != "" && !covered[name] {
						add(local)
					}
				}
			}
			if len(pi.refs) > 0 {
				out = append(out, pi)
			}
		}
	}
	return out
}

// lookupImages asks the registry what it knows of the images; user is who
// asks, for its log.
func (s *Server) lookupImages(ctx context.Context, refs []string, user string) (map[string]registry.ImageScan, error) {
	out := map[string]registry.ImageScan{}
	if len(refs) == 0 {
		return out, nil
	}
	b, err := json.Marshal(map[string][]string{"refs": refs})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.cfg.RegistryURL, "/")+"/admin/v1/scans/lookup", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.RegistrySecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(registry.UserHeader, user)
	resp, err := s.registryHTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("the registry answered %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var body struct {
		Images map[string]registry.ImageScan `json:"images"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&body); err != nil {
		return nil, err
	}
	if body.Images != nil {
		out = body.Images
	}
	return out, nil
}

// RunningImage is an image of the registry that a workload runs.
type RunningImage struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
	// Pods are how many of its pods run it.
	Pods int `json:"pods"`
	registry.ImageScan
}

// runningVulnerable matches what runs with what the registry knows of it,
// one row a workload and image.
func (s *Server) runningVulnerable(ctx context.Context, keep func(cluster, namespace string) bool, user string) ([]RunningImage, error) {
	pods := s.runningImages(keep)
	var refs []string
	seen := map[string]bool{}
	for _, p := range pods {
		for _, ref := range p.refs {
			if !seen[ref] {
				seen[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	images, err := s.lookupImages(ctx, refs, user)
	if err != nil {
		return nil, err
	}
	rows := map[string]*RunningImage{}
	for _, p := range pods {
		// A pod's refs may name the same image twice (by digest and by tag).
		mine := map[string]bool{}
		for _, ref := range p.refs {
			img, ok := images[ref]
			if !ok || mine[img.Repo+"@"+img.Digest] {
				continue
			}
			mine[img.Repo+"@"+img.Digest] = true
			key := strings.Join([]string{p.cluster, p.namespace, p.workload, img.Repo, img.Digest}, "\x00")
			if rows[key] == nil {
				rows[key] = &RunningImage{Cluster: p.cluster, Namespace: p.namespace, Workload: p.workload, ImageScan: img}
			}
			rows[key].Pods++
		}
	}
	out := make([]RunningImage, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	worst := func(r RunningImage) [3]int {
		if r.Scan == nil || r.Scan.Summary == nil {
			return [3]int{r.Critical, -1, -1}
		}
		return [3]int{r.Critical, r.Scan.Summary.Critical, r.Scan.Summary.High}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := worst(out[i]), worst(out[j])
		if a != b {
			for k := range a {
				if a[k] != b[k] {
					return a[k] > b[k]
				}
			}
		}
		x, y := out[i], out[j]
		return x.Cluster+"\x00"+x.Namespace+"\x00"+x.Workload+"\x00"+x.Repo < y.Cluster+"\x00"+y.Namespace+"\x00"+y.Workload+"\x00"+y.Repo
	})
	return out, nil
}

// registryRunningVulnerable is the page of the registry's images that run
// where the user may see, of the projects they may see.
func (s *Server) registryRunningVulnerable(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	projects, err := s.registryProjectList(r)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return
	}
	sees := map[string]bool{}
	for _, p := range projects {
		sees[p.Name] = seesProject(u, p)
	}
	rows, err := s.runningVulnerable(r.Context(), func(cluster, ns string) bool { return u.RoleIn(cluster, ns) >= auth.Viewer }, u.Name)
	if err != nil {
		s.log.Warn("asking the registry about running images", "err", err)
		writeError(w, http.StatusBadGateway, "the image registry could not be asked about the images that run")
		return
	}
	kept := []RunningImage{}
	for _, row := range rows {
		if sees[meta.ProjectOf(row.Repo)] {
			kept = append(kept, row)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": kept})
}

// vulnerableRunningAlerts are the images with critical vulnerabilities
// their projects do not allow that some workload runs: one alert an
// image, saying where.
func (s *Server) vulnerableRunningAlerts(ctx context.Context) ([]alert.Alert, error) {
	rows, err := s.runningVulnerable(ctx, nil, "kartal-server")
	if err != nil {
		s.log.Warn("asking the registry about running images", "err", err)
		return nil, err
	}
	type found struct {
		critical int
		places   []string
	}
	byImage := map[string]*found{}
	var order []string
	for _, r := range rows {
		if r.Critical == 0 {
			continue
		}
		key := r.Repo + "@" + r.Digest
		if byImage[key] == nil {
			byImage[key] = &found{critical: r.Critical}
			order = append(order, key)
		}
		byImage[key].places = append(byImage[key].places, r.Cluster+"/"+r.Namespace+" "+r.Workload)
	}
	var out []alert.Alert
	for _, key := range order {
		f := byImage[key]
		where := f.places
		more := ""
		if len(where) > 5 {
			more = fmt.Sprintf(" and %d more", len(where)-5)
			where = where[:5]
		}
		repo, digest, _ := strings.Cut(key, "@")
		out = append(out, alert.Alert{Kind: alert.RegistryVulnerableRunning, Severity: "warning",
			Object: repo + "@" + strings.TrimPrefix(digest, "sha256:")[:12],
			Detail: fmt.Sprintf("%d critical vulnerabilities its project does not allow; runs in %s%s", f.critical, strings.Join(where, ", "), more)})
	}
	return out, nil
}
