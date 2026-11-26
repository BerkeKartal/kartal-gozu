package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The image registry's problems become alerts, notified as any other: it
// cannot be reached, it cannot save its metadata, a job of it failed, its
// blobs are damaged, a project is near its quota, an image that runs has
// critical vulnerabilities.

// registryWatchEvery is how often the server looks at the registry.
const registryWatchEvery = time.Minute

// lastAlerts keeps what each look at the registry last found: a look that
// fails once (a timeout, a restart) keeps its alerts as they were, rather
// than resolving them and telling of them again a minute later.
type lastAlerts struct {
	mu    sync.Mutex
	found map[string][]alert.Alert
}

// of is what a look found now, or what it last found when it failed.
func (l *lastAlerts) of(look string, found []alert.Alert, err error) []alert.Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.found == nil {
		l.found = map[string][]alert.Alert{}
	}
	if err != nil {
		return l.found[look]
	}
	l.found[look] = found
	return found
}

func (s *Server) watchRegistry(ctx context.Context) {
	t := time.NewTicker(registryWatchEvery)
	defer t.Stop()
	for {
		s.cfg.Alerts.ObserveRegistry(s.registryAlerts(ctx), s.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// registryGet reads the registry's admin API as the server itself.
func (s *Server) registryGet(ctx context.Context, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.cfg.RegistryURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.RegistrySecret)
	req.Header.Set(registry.UserHeader, "kartal-server")
	resp, err := s.registryHTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s answered %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

// registryAlerts are the registry's problems now.
func (s *Server) registryAlerts(ctx context.Context) []alert.Alert {
	const object = "kartal-registry"
	var status struct {
		Problem string `json:"problem"`
		Scanner bool   `json:"scanner"`
	}
	if err := s.registryGet(ctx, "/admin/v1/status", &status); err != nil {
		return []alert.Alert{{Kind: alert.RegistryUnreachable, Severity: "critical", Object: object, Detail: err.Error()}}
	}
	var out []alert.Alert
	if status.Problem != "" {
		out = append(out, alert.Alert{Kind: alert.RegistryMetadata, Severity: "critical", Object: object, Detail: status.Problem})
	}
	var projects []meta.ProjectInfo
	err := s.registryGet(ctx, "/admin/v1/projects", &projects)
	var quota []alert.Alert
	for _, p := range projects {
		if p.Quota <= 0 || p.Size*100 < p.Quota*90 {
			continue
		}
		sev := "warning"
		if p.Size >= p.Quota {
			sev = "critical"
		}
		quota = append(quota, alert.Alert{Kind: alert.RegistryQuota, Severity: sev, Object: p.Name,
			Detail: fmt.Sprintf("%s of %s (%d%%)", meta.HumanBytes(p.Size), meta.HumanBytes(p.Quota), p.Size*100/p.Quota)})
	}
	out = append(out, s.regAlerts.of("quota", quota, err)...)
	// The blob stores: full, or in trouble.
	var stores []registry.StoreView
	err = s.registryGet(ctx, "/admin/v1/stores", &stores)
	var storeAlerts []alert.Alert
	for _, st := range stores {
		if st.Problem != "" {
			storeAlerts = append(storeAlerts, alert.Alert{Kind: alert.RegistryStoreProblem, Severity: "critical", Object: st.Name, Detail: st.Problem})
		}
		if st.Quota > 0 && st.Size*100 >= st.Quota*90 {
			sev := "warning"
			if st.Size >= st.Quota {
				sev = "critical"
			}
			storeAlerts = append(storeAlerts, alert.Alert{Kind: alert.RegistryStoreFull, Severity: sev, Object: st.Name,
				Detail: fmt.Sprintf("%s of %s (%d%%)", meta.HumanBytes(st.Size), meta.HumanBytes(st.Quota), st.Size*100/st.Quota)})
		}
	}
	out = append(out, s.regAlerts.of("stores", storeAlerts, err)...)
	var jobs struct {
		Jobs []meta.Job `json:"jobs"`
	}
	err = s.registryGet(ctx, "/admin/v1/jobs?limit=1000&brief=true", &jobs)
	var failed []alert.Alert
	if err == nil {
		// What counts is how each kind of job, of each project, last ended.
		seen := map[string]bool{}
		for _, j := range jobs.Jobs {
			key := j.Kind + "\x00" + j.Project + "\x00" + j.Rule
			if j.Status == meta.JobRunning || seen[key] {
				continue
			}
			seen[key] = true
			what := j.Kind
			switch {
			case j.RuleName != "":
				what += " " + j.RuleName
			case j.Project != "":
				what += " of " + j.Project
			}
			if j.Status == meta.JobFailed {
				failed = append(failed, alert.Alert{Kind: alert.RegistryJobFailed, Severity: "warning", Object: what, Detail: j.Error})
			}
			switch {
			case j.Alarm != "" && j.Kind == registry.JobVerify:
				failed = append(failed, alert.Alert{Kind: alert.RegistryDamaged, Severity: "critical", Object: object, Detail: j.Alarm})
			case j.Alarm != "":
				failed = append(failed, alert.Alert{Kind: alert.RegistryJobFailed, Severity: "warning", Object: what, Detail: j.Alarm})
			}
		}
	}
	out = append(out, s.regAlerts.of("jobs", failed, err)...)
	// What runs with critical vulnerabilities, where images are scanned.
	if status.Scanner {
		vuln, err := s.vulnerableRunningAlerts(ctx)
		out = append(out, s.regAlerts.of("vulnerable", vuln, err)...)
	}
	return out
}
