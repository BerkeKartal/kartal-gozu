package registry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

func setPolicy(t *testing.T, e *env, project, body string) {
	t.Helper()
	if a := e.do("PUT", "/admin/v1/projects/"+project, "admin-secret", []byte(body)); a.code != 200 {
		t.Fatalf("policy %s: %d %s", body, a.code, a.body)
	}
}

func TestPullPolicy(t *testing.T) {
	e, f := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/clean:pull,push")
	d, _ := e.pushImage("shop/web", "1.0", ci, "amd64")
	other, _ := e.pushImage("shop/web", "2.0", ci, "arm64")
	clean, _ := e.pushImage("shop/clean", "1.0", ci, "amd64")
	if _, err := e.reg.QueueScan("shop/web", d, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.QueueScan("shop/clean", clean, "root"); err != nil {
		t.Fatal(err)
	}
	e.scanned(d)
	e.scanned(clean)
	pull := func(repo, ref string) answer {
		return e.do("GET", "/v2/"+repo+"/manifests/"+ref, ci, nil, "Accept", manifest.OCIManifest)
	}
	// No policy: everything is pulled.
	if a := pull("shop/web", "1.0"); a.code != 200 {
		t.Fatalf("without a policy: %d", a.code)
	}
	// High or worse refused: the critical one stops it.
	setPolicy(t, e, "shop", `{"blockSeverity":"high"}`)
	if p, _ := e.db.Project("shop"); p.BlockSeverity != "HIGH" {
		t.Errorf("the severity was kept as %q", p.BlockSeverity)
	}
	a := pull("shop/web", "1.0")
	if a.code != 412 || a.errCode() != "DENIED" || !strings.Contains(string(a.body), "refuses images with high or worse vulnerabilities it does not allow, and this one has 1") {
		t.Fatalf("refused: %d %s", a.code, a.body)
	}
	pulls := func() int64 { x, _ := e.db.Artifact("shop/web", d); return x.Pulls }
	if pulls() != 1 {
		t.Errorf("a refused pull was counted: %d", pulls())
	}
	// Asking whether it is there is not pulling it.
	if a := e.do("HEAD", "/v2/shop/web/manifests/1.0", ci, nil); a.code != 200 {
		t.Errorf("head: %d", a.code)
	}
	// One never scanned, and one without such vulnerabilities, go through.
	if a := pull("shop/web", other); a.code != 200 {
		t.Errorf("not scanned: %d", a.code)
	}
	if a := pull("shop/clean", "1.0"); a.code != 200 {
		t.Errorf("clean: %d", a.code)
	}
	// The scanner still pulls it to scan it again.
	n := len(f.requests())
	if _, err := e.reg.QueueScan("shop/web", d, "root"); err != nil {
		t.Fatal(err)
	}
	if sc := e.scanned(d); sc.Status != meta.ScanDone || len(f.requests()) != n+1 {
		t.Fatalf("rescan of a refused image: %+v", sc)
	}
	// Allowed by its ID, in any case, it goes through.
	setPolicy(t, e, "shop", `{"allowlist":["cve-2026-0001"," CVE-2026-0001 ",""]}`)
	if p, _ := e.db.Project("shop"); len(p.Allowlist) != 1 {
		t.Errorf("allowlist %v", p.Allowlist)
	}
	if a := pull("shop/web", "1.0"); a.code != 200 {
		t.Errorf("allowed: %d %s", a.code, a.body)
	}
	// Down to low, the low one stops it again, until it is allowed too.
	setPolicy(t, e, "shop", `{"blockSeverity":"LOW"}`)
	if a := pull("shop/web", "1.0"); a.code != 412 {
		t.Errorf("low: %d", a.code)
	}
	var repo struct {
		Artifacts []ArtifactSummary `json:"artifacts"`
	}
	got := e.do("GET", "/admin/v1/repository?name=shop/web", "admin-secret", nil)
	json.Unmarshal(got.body, &repo)
	for _, x := range repo.Artifacts {
		want := 0
		if x.Digest == d {
			want = 1
		}
		if x.Scan == nil || x.Scan.Blocked != want {
			t.Errorf("%s blocked: %+v", x.Digest, x.Scan)
		}
	}
	setPolicy(t, e, "shop", `{"allowlist":["CVE-2026-0001","CVE-2026-0002"]}`)
	if a := pull("shop/web", "1.0"); a.code != 200 {
		t.Errorf("all allowed: %d", a.code)
	}
	// What is not a policy is said so.
	for _, body := range []string{`{"blockSeverity":"UNKNOWN"}`, `{"blockSeverity":"bad"}`, `{"allowlist":["no spaces please"]}`} {
		if a := e.do("PUT", "/admin/v1/projects/shop", "admin-secret", []byte(body)); a.code != 400 {
			t.Errorf("%s: %d", body, a.code)
		}
	}
	// Turned off, nothing is refused.
	setPolicy(t, e, "shop", `{"blockSeverity":"","allowlist":[]}`)
	if p, _ := e.db.Project("shop"); p.BlockSeverity != "" || p.Allowlist != nil {
		t.Errorf("off: %+v", p)
	}
	events := e.db.Events(func(p string) bool { return p == "shop" }, 10)
	if !hasEvent(events, "project-update", "no pulls refused for vulnerabilities; no longer allowed CVE-2026-0001, CVE-2026-0002") {
		t.Errorf("events %+v", events)
	}
}

func TestPullPolicyOfAnIndex(t *testing.T) {
	e, _ := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	amd, _ := e.pushImage("shop/web", "amd", ci, "amd64")
	arm, _ := e.pushImage("shop/web", "arm", ci, "arm64")
	index := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIIndex + `","manifests":[
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + amd + `","size":1,"platform":{"architecture":"amd64","os":"linux"}},
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + arm + `","size":1,"platform":{"architecture":"arm64","os":"linux"}}]}`)
	if a := e.do("PUT", "/v2/shop/web/manifests/1.0", ci, index, "Content-Type", manifest.OCIIndex); a.code != 201 {
		t.Fatalf("index: %d", a.code)
	}
	if _, err := e.reg.QueueScan("shop/web", amd, "root"); err != nil {
		t.Fatal(err)
	}
	e.scanned(amd)
	setPolicy(t, e, "shop", `{"blockSeverity":"CRITICAL"}`)
	// The index is read; the scanned image of it is refused, the other not.
	if a := e.do("GET", "/v2/shop/web/manifests/1.0", ci, nil, "Accept", manifest.OCIIndex); a.code != 200 {
		t.Errorf("the index: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/"+amd, ci, nil); a.code != 412 {
		t.Errorf("amd64: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/"+arm, ci, nil); a.code != 200 {
		t.Errorf("arm64: %d", a.code)
	}
	var d ArtifactDetail
	a := e.do("GET", "/admin/v1/artifact?repo=shop/web&ref=1.0", "admin-secret", nil)
	if json.Unmarshal(a.body, &d) != nil || d.Scan == nil || d.Scan.Blocked != 1 {
		t.Errorf("the index's view: %s", a.body)
	}
}

func TestScanOnPushFromTheStart(t *testing.T) {
	e, _ := newScanEnv(t)
	if a := e.do("POST", "/admin/v1/projects", "admin-secret", []byte(`{"name":"team","scanOnPush":true}`)); a.code != 201 {
		t.Fatalf("create: %d %s", a.code, a.body)
	}
	if p, _ := e.db.Project("team"); !p.ScanOnPush {
		t.Error("a new project's scan on push was lost")
	}
}
