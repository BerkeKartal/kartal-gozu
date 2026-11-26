package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The image registry's problems become alerts, notified as any other: it
// cannot be reached, it cannot save its metadata, a job of it failed, its
// blobs are damaged, a project is near its quota.

// registryWatchEvery is how often the server looks at the registry.
const registryWatchEvery = time.Minute

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
	}
	if err := s.registryGet(ctx, "/admin/v1/status", &status); err != nil {
		return []alert.Alert{{Kind: alert.RegistryUnreachable, Severity: "critical", Object: object, Detail: err.Error()}}
	}
	var out []alert.Alert
	if status.Problem != "" {
		out = append(out, alert.Alert{Kind: alert.RegistryMetadata, Severity: "critical", Object: object, Detail: status.Problem})
	}
	var projects []meta.ProjectInfo
	if err := s.registryGet(ctx, "/admin/v1/projects", &projects); err == nil {
		for _, p := range projects {
			if p.Quota <= 0 || p.Size*100 < p.Quota*90 {
				continue
			}
			sev := "warning"
			if p.Size >= p.Quota {
				sev = "critical"
			}
			out = append(out, alert.Alert{Kind: alert.RegistryQuota, Severity: sev, Object: p.Name,
				Detail: fmt.Sprintf("%s of %s (%d%%)", meta.HumanBytes(p.Size), meta.HumanBytes(p.Quota), p.Size*100/p.Quota)})
		}
	}
	var jobs struct {
		Jobs []meta.Job `json:"jobs"`
	}
	if err := s.registryGet(ctx, "/admin/v1/jobs?limit=200", &jobs); err == nil {
		// What counts is how each kind of job, of each project, last ended.
		seen := map[string]bool{}
		for _, j := range jobs.Jobs {
			key := j.Kind + "\x00" + j.Project
			if j.Status == meta.JobRunning || seen[key] {
				continue
			}
			seen[key] = true
			what := j.Kind
			if j.Project != "" {
				what += " of " + j.Project
			}
			if j.Status == meta.JobFailed {
				out = append(out, alert.Alert{Kind: alert.RegistryJobFailed, Severity: "warning", Object: what, Detail: j.Error})
			}
			if j.Alarm != "" {
				out = append(out, alert.Alert{Kind: alert.RegistryDamaged, Severity: "critical", Object: object, Detail: j.Alarm})
			}
		}
	}
	return out
}
