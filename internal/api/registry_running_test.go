package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
)

// mcpOf calls the server's MCP endpoint, and answers the result.
func (e *regEnv) mcpOf(token, method string, params any) json.RawMessage {
	e.t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest("POST", e.api.URL+"/api/v1/mcp", strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var a struct {
		Result json.RawMessage `json:"result"`
		Error  any             `json:"error"`
	}
	if json.NewDecoder(resp.Body).Decode(&a) != nil || a.Error != nil {
		e.t.Fatalf("%s: %d %v", method, resp.StatusCode, a.Error)
	}
	return a.Result
}

func (e *regEnv) toolNames(token string) map[string]bool {
	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	json.Unmarshal(e.mcpOf(token, "tools/list", map[string]any{}), &res)
	out := map[string]bool{}
	for _, tl := range res.Tools {
		out[tl.Name] = true
	}
	return out
}

func (e *regEnv) tool(token, name string, args map[string]any) (string, bool) {
	var res toolResult
	json.Unmarshal(e.mcpOf(token, "tools/call", map[string]any{"name": name, "arguments": args}), &res)
	if len(res.Content) != 1 {
		e.t.Fatalf("%s: %+v", name, res)
	}
	return res.Content[0].Text, res.IsError
}

func TestRunningVulnerableImages(t *testing.T) {
	e := newRegEnv(t, func(c *registry.Config) {
		c.Scanner, c.ScanDir, c.ScanAddress = cannedScanner{}, t.TempDir(), "http://kartal-registry:5000"
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.reg.Start(ctx)
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"team-a"}`); code != 201 {
		t.Fatalf("make a project: %d %s", code, b)
	}
	tok, _ := e.token("dev", regTeamTok, "repository:team-a/web:pull,push")
	d := e.pushTiny("team-a/web", "1.0", tok)
	if code, b := e.call("POST", "/api/v1/registry/scan", regTeamTok, `{"repo":"team-a/web","digest":"`+d+`"}`); code != 202 {
		t.Fatalf("scan: %d %s", code, b)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, b := e.call("GET", "/api/v1/registry/vulnerabilities?repo=team-a/web&ref=1.0", regViewTok, ""); strings.Contains(string(b), "CVE-2026-1000") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan did not end")
		}
	}
	image := "registry.example.org/team-a/web"
	snap := &protocol.Snapshot{Pods: []protocol.Pod{
		{Namespace: "shop", Name: "web-1", Owner: "Deployment/web", Phase: "Running", Images: []string{image + ":1.0"}, ImageIDs: []string{image + "@" + d}},
		{Namespace: "shop", Name: "web-2", Owner: "Deployment/web", Phase: "Running", Images: []string{image + ":1.0"}, ImageIDs: []string{image + "@" + d}},
		// Of another host, by tag: maybe another image; not this one.
		{Namespace: "other", Name: "x", Phase: "Running", Images: []string{"docker.io/team-a/web:1.0"}},
		// Pending, by tag of this registry.
		{Namespace: "batch", Name: "new-1", Phase: "Pending", Images: []string{image + ":1.0"}},
		// Done: it runs no more.
		{Namespace: "batch", Name: "old-1", Phase: "Succeeded", ImageIDs: []string{image + "@" + d}},
	}}
	if err := e.st.PutSnapshot("demo", snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Images []RunningImage `json:"images"`
	}
	code, b := e.call("GET", "/api/v1/registry/running-vulnerabilities", bossTok, "")
	if json.Unmarshal(b, &out); code != 200 || len(out.Images) != 2 {
		t.Fatalf("running: %d %s", code, b)
	}
	// As bad as each other, they come by cluster and namespace.
	pending, web := out.Images[0], out.Images[1]
	if web.Cluster != "demo" || web.Namespace != "shop" || web.Workload != "Deployment/web" || web.Pods != 2 || web.Repo != "team-a/web" ||
		web.Digest != d || web.Critical != 1 || web.Scan == nil || web.Scan.Summary == nil || web.Scan.Summary.Medium != 1 {
		t.Errorf("web: %+v", web)
	}
	if pending.Namespace != "batch" || pending.Workload != "Pod/new-1" || pending.Digest != d {
		t.Errorf("pending: %+v", pending)
	}
	// One sees what runs where they may look, of the projects they may see.
	for _, tok := range []string{clusterTok, regTeamTok} {
		if code, b := e.call("GET", "/api/v1/registry/running-vulnerabilities", tok, ""); code != 200 || strings.Contains(string(b), "team-a/web") {
			t.Errorf("%s sees: %d %s", tok, code, b)
		}
	}

	// A critical vulnerability that runs is an alert, for the project's
	// people and the registry's admins.
	var vuln alert.Alert
	for _, a := range e.srv.registryAlerts(ctx) {
		if a.Kind == alert.RegistryVulnerableRunning {
			vuln = a
		}
	}
	if vuln.Object != "team-a/web@"+d[7:19] || vuln.Severity != "warning" || !strings.Contains(vuln.Detail, "1 critical") ||
		!strings.Contains(vuln.Detail, "demo/shop Deployment/web") {
		t.Fatalf("the alert: %+v", vuln)
	}
	lead, _ := auth.ParseGrant("viewer@registry:team-a")
	ops, _ := auth.ParseGrant("admin@*/*")
	if !alertVisible(auth.NewUser("lead", []auth.Grant{lead}), vuln) || alertVisible(auth.NewUser("ops", []auth.Grant{ops}), vuln) {
		t.Error("who sees the alert")
	}
	// Allowed by the project, it is no longer one.
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, `{"allowlist":["CVE-2026-1000"]}`); code != 200 {
		t.Fatalf("allow: %d %s", code, b)
	}
	for _, a := range e.srv.registryAlerts(ctx) {
		if a.Kind == alert.RegistryVulnerableRunning {
			t.Errorf("an allowed vulnerability alerts: %+v", a)
		}
	}

	// The registry's tools, for those with a role in the registry.
	if names := e.toolNames(regTeamTok); !names["list_registry_projects"] || !names["image_vulnerabilities"] || !names["scan_image"] ||
		names["registry_jobs"] || names["list_clusters"] {
		t.Errorf("a registry operator's tools: %v", names)
	}
	if names := e.toolNames(clusterTok); names["list_registry_projects"] || !names["list_clusters"] {
		t.Errorf("a cluster admin's tools: %v", names)
	}
	if names := e.toolNames(bossTok); !names["run_registry_job"] || !names["running_vulnerabilities"] || !names["list_clusters"] {
		t.Errorf("the admin's tools: %v", names)
	}
	text, failed := e.tool(regViewTok, "image_vulnerabilities", map[string]any{"repository": "team-a/web", "reference": "1.0", "severity": "high"})
	if failed || !strings.Contains(text, "CVE-2026-1000") || strings.Contains(text, "CVE-2026-1001") {
		t.Errorf("image_vulnerabilities: %s", text)
	}
	if text, failed := e.tool(regViewTok, "scan_image", map[string]any{"repository": "team-a/web", "digest": d}); !failed || !strings.Contains(text, "operator role") {
		t.Errorf("a viewer's scan: %s", text)
	}
	if text, failed := e.tool(regViewTok, "list_artifacts", map[string]any{"repository": "team-a/web"}); failed || !strings.Contains(text, d) {
		t.Errorf("list_artifacts: %s", text)
	}
	if text, failed := e.tool(regViewTok, "list_artifacts", map[string]any{}); !failed || !strings.Contains(text, "give a repository") {
		t.Errorf("list_artifacts without one: %s", text)
	}
	if text, failed := e.tool(bossTok, "running_vulnerabilities", map[string]any{}); failed || !strings.Contains(text, "Deployment/web") {
		t.Errorf("running_vulnerabilities: %s", text)
	}
}

func TestLookupImage(t *testing.T) {
	e := newRegEnv(t)
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"team-a"}`); code != 201 {
		t.Fatalf("make a project: %d %s", code, b)
	}
	tok, _ := e.token("dev", regTeamTok, "repository:team-a/web:pull,push")
	d := e.pushTiny("team-a/web", "1.0", tok)
	for _, ref := range []string{"team-a/web:1.0", "team-a/web@" + d, d} {
		if img, ok := e.reg.LookupImage(ref); !ok || img.Repo != "team-a/web" || img.Digest != d || img.Kind != "image" {
			t.Errorf("%s: %+v %v", ref, img, ok)
		}
	}
	for _, ref := range []string{"team-a/web:2.0", "team-a/api:1.0", "team-a/web@sha256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("0", 64), "team-a/web", ""} {
		if img, ok := e.reg.LookupImage(ref); ok {
			t.Errorf("%s: %+v", ref, img)
		}
	}
}

// A look at the registry that fails keeps the alerts it last found.
func TestRegistryAlertsSurviveAFailedLook(t *testing.T) {
	var l lastAlerts
	a := []alert.Alert{{Kind: alert.RegistryQuota, Object: "team-a"}}
	if got := l.of("quota", a, nil); len(got) != 1 {
		t.Fatalf("found: %+v", got)
	}
	if got := l.of("quota", nil, context.DeadlineExceeded); len(got) != 1 || got[0].Object != "team-a" {
		t.Errorf("a failed look: %+v", got)
	}
	if got := l.of("jobs", nil, context.DeadlineExceeded); len(got) != 0 {
		t.Errorf("another look: %+v", got)
	}
	if got := l.of("quota", nil, nil); len(got) != 0 {
		t.Errorf("all well again: %+v", got)
	}
}
