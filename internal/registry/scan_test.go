package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/remote"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

// fakeScanner scans the way kartal-scanner does as far as the registry
// sees: it pulls the image's manifest with the credentials it is given.
// Images of a repository ending in "clean" have no vulnerabilities; the
// others a critical and a low one.
type fakeScanner struct {
	mu      sync.Mutex
	asked   []scanner.Request
	updates int
	// fail are repositories whose scans fail, with why.
	fail map[string]string
	// hold, when set, keeps the scans until it is closed.
	hold chan struct{}
	// also is tried with the scan's credentials after its pull.
	also func(ctx context.Context, c *remote.Client)
}

var fakeDB = time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC)

func (f *fakeScanner) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	f.mu.Lock()
	f.asked = append(f.asked, req)
	hold, also := f.hold, f.also
	f.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return scanner.Result{}, ctx.Err()
		}
	}
	host, rest, _ := strings.Cut(req.Image, "/")
	repo, digest, _ := strings.Cut(rest, "@")
	scheme := "https"
	if req.Insecure {
		scheme = "http"
	}
	c, err := remote.New(remote.Options{URL: scheme + "://" + host, Username: req.Username, Password: req.Password})
	if err != nil {
		return scanner.Result{}, err
	}
	if _, _, got, err := c.Manifest(ctx, repo, digest); err != nil || got != digest {
		return scanner.Result{}, fmt.Errorf("%w: pulling %s: %v", scanner.ErrScanner, req.Image, err)
	}
	if also != nil {
		also(ctx, c)
	}
	f.mu.Lock()
	msg := f.fail[repo]
	f.mu.Unlock()
	if msg != "" {
		return scanner.Result{}, fmt.Errorf("%w: %s", scanner.ErrScanner, msg)
	}
	vulns := []scanner.Vulnerability{
		{ID: "CVE-2026-0001", Package: "openssl", Installed: "3.0.11", Fixed: "3.0.13", Severity: scanner.Critical, Score: 9.8},
		{ID: "CVE-2026-0002", Package: "zlib", Installed: "1.2.13", Severity: scanner.Low},
	}
	if strings.HasSuffix(repo, "clean") {
		vulns = []scanner.Vulnerability{}
	}
	return scanner.Result{Report: scanner.Report{Scanner: "Fake 1.0", DB: &fakeDB, OS: "debian 12.5", Packages: 3, Vulnerabilities: vulns},
		SBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)}, nil
}

func (f *fakeScanner) UpdateDB(ctx context.Context) (scanner.Status, error) {
	f.mu.Lock()
	f.updates++
	f.mu.Unlock()
	return f.Status(ctx)
}

func (f *fakeScanner) Status(context.Context) (scanner.Status, error) {
	return scanner.Status{Scanner: "Fake 1.0", DB: &scanner.DBStatus{UpdatedAt: &fakeDB}, Workers: 2}, nil
}

func (f *fakeScanner) requests() []scanner.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]scanner.Request(nil), f.asked...)
}

func (f *fakeScanner) updated() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates
}

// newScanEnv is an env whose registry has a scanner, pulling from the
// registry's test server.
func newScanEnv(t *testing.T, before ...func(*env)) (*env, *fakeScanner) {
	t.Helper()
	e := newEnv(t)
	f := &fakeScanner{fail: map[string]string{}}
	e.reg.cfg.Scanner, e.reg.cfg.ScanDir, e.reg.cfg.ScanAddress = f, t.TempDir(), e.srv.URL
	for _, fn := range before {
		fn(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.reg.Start(ctx)
	return e, f
}

// scanned waits for an image's scan to end.
func (e *env) scanned(digest string) meta.Scan {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sc, ok := e.db.Scan(digest)
		if ok && (sc.Status == meta.ScanDone || sc.Status == meta.ScanFailed) && !e.reg.pendingScan(digest) {
			return sc
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("the scan of %s: %+v %v", digest, sc, ok)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func scanOnPush(e *env, project string) {
	on := true
	if _, err := e.db.UpdateProject(project, meta.ProjectChange{ScanOnPush: &on}, "root"); err != nil {
		e.t.Fatal(err)
	}
}

func TestScanOnPush(t *testing.T) {
	e, f := newScanEnv(t)
	scanOnPush(e, "shop")
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:infra/db:pull,push")
	d, _ := e.pushImage("shop/web", "1.0", ci, "amd64")
	sc := e.scanned(d)
	if sc.Status != meta.ScanDone || sc.Summary == nil || sc.Summary.Critical != 1 || sc.Summary.Low != 1 || sc.Summary.Fixable != 1 ||
		sc.Scanner != "Fake 1.0" || sc.DB == nil || sc.OS != "debian 12.5" || sc.Packages != 3 || sc.By != "ci" || sc.Scanned == nil {
		t.Fatalf("scan %+v", sc)
	}
	reqs := f.requests()
	host := strings.TrimPrefix(e.srv.URL, "http://")
	if len(reqs) != 1 || reqs[0].Image != host+"/shop/web@"+d || reqs[0].Username != ScannerUser || !reqs[0].Insecure || reqs[0].Password == "" {
		t.Fatalf("asked %+v", reqs)
	}
	// The scanner's pull is not one of people's.
	if a, _ := e.db.Artifact("shop/web", d); a.Pulls != 0 || a.LastPull != nil {
		t.Errorf("the scanner's pull was counted: %+v", a)
	}
	// Its password ended with the scan.
	if _, ok := e.reg.scanTicket(reqs[0].Password); ok {
		t.Error("the scan's password still pulls")
	}
	// Lists show what it found, and the report is there with the SBOM.
	var repo struct {
		Artifacts []ArtifactSummary `json:"artifacts"`
	}
	if a := e.do("GET", "/admin/v1/repository?name=shop/web", "admin-secret", nil); a.code != 200 || json.Unmarshal(a.body, &repo) != nil ||
		len(repo.Artifacts) != 1 || repo.Artifacts[0].Scan == nil || repo.Artifacts[0].Scan.Status != meta.ScanDone ||
		repo.Artifacts[0].Scan.Summary.Critical != 1 {
		t.Fatalf("repository: %d %s", a.code, a.body)
	}
	var vv VulnerabilityView
	if a := e.do("GET", "/admin/v1/vulnerabilities?repo=shop/web&digest="+d, "admin-secret", nil); a.code != 200 || json.Unmarshal(a.body, &vv) != nil ||
		vv.Report == nil || len(vv.Report.Vulnerabilities) != 2 || !vv.SBOM || vv.Scan.Status != meta.ScanDone {
		t.Fatalf("vulnerabilities: %d %s", a.code, a.body)
	}
	if a := e.do("GET", "/admin/v1/sbom?repo=shop/web&digest="+d, "admin-secret", nil); a.code != 200 || !strings.Contains(string(a.body), "CycloneDX") ||
		a.h.Get("Content-Type") != "application/vnd.cyclonedx+json" {
		t.Fatalf("sbom: %d %v %s", a.code, a.h, a.body)
	}
	// The same image by another tag is not scanned again.
	m, _ := e.db.Artifact("shop/web", d)
	raw := e.do("GET", "/v2/shop/web/manifests/"+d, ci, nil, "Accept", manifest.OCIManifest)
	if a := e.do("PUT", "/v2/shop/web/manifests/latest", ci, raw.body, "Content-Type", m.MediaType); a.code != 201 {
		t.Fatalf("tag again: %d %s", a.code, a.body)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(f.requests()); n != 1 {
		t.Errorf("%d scans after pushing the same image again", n)
	}
	// A project that does not scan on push leaves it until someone asks.
	other, _ := e.pushImage("infra/db", "15", ci, "amd64")
	time.Sleep(50 * time.Millisecond)
	if _, ok := e.db.Scan(other); ok {
		t.Fatal("infra scans on push")
	}
	var unscanned struct {
		Artifacts []ArtifactSummary `json:"artifacts"`
	}
	if a := e.do("GET", "/admin/v1/repository?name=infra/db", "admin-secret", nil); json.Unmarshal(a.body, &unscanned) != nil ||
		unscanned.Artifacts[0].Scan == nil || unscanned.Artifacts[0].Scan.Status != "none" {
		t.Errorf("unscanned: %s", a.body)
	}
	if a := e.do("POST", "/admin/v1/scan", "admin-secret", []byte(`{"repo":"infra/db","digest":"`+other+`"}`)); a.code != 202 ||
		!strings.Contains(string(a.body), other) {
		t.Fatalf("scan: %d %s", a.code, a.body)
	}
	if sc := e.scanned(other); sc.Status != meta.ScanDone || sc.Repo != "infra/db" {
		t.Errorf("asked for: %+v", sc)
	}
	// What is not there is said so.
	if a := e.do("POST", "/admin/v1/scan", "admin-secret", []byte(`{"repo":"infra/db","digest":"sha256:`+strings.Repeat("0", 64)+`"}`)); a.code != 404 {
		t.Errorf("no such image: %d %s", a.code, a.body)
	}
	var st ScannerView
	if a := e.do("GET", "/admin/v1/scanner", "admin-secret", nil); a.code != 200 || json.Unmarshal(a.body, &st) != nil || !st.Configured ||
		st.Status == nil || st.Status.Scanner != "Fake 1.0" || st.Address != e.srv.URL {
		t.Fatalf("scanner: %s", a.body)
	}
	// An update of the databases is started, and logged when it ends.
	if a := e.do("POST", "/admin/v1/scanner/db", "admin-secret", []byte(`{}`)); a.code != 202 {
		t.Fatalf("db update: %d %s", a.code, a.body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !hasEvent(e.db.Events(nil, 0), "scanner-db", "Fake 1.0, DB of 2026-11-26 06:00:00") {
		if time.Now().After(deadline) {
			t.Fatalf("updates %d, events %+v", f.updated(), e.db.Events(nil, 3))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if a := e.do("GET", "/admin/v1/status", "admin-secret", nil); !strings.Contains(string(a.body), `"scanner":true`) {
		t.Errorf("status: %s", a.body)
	}
}

func TestScanPasswordPullsOneRepository(t *testing.T) {
	e, f := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/api:pull,push")
	api, _ := e.pushImage("shop/api", "1", ci, "amd64")
	d, _ := e.pushImage("shop/web", "1", ci, "amd64")
	var others []error
	f.also = func(ctx context.Context, c *remote.Client) {
		_, _, _, err := c.Manifest(ctx, "shop/api", api)
		others = append(others, err)
	}
	if _, err := e.reg.QueueScan("shop/web", d, "dev"); err != nil {
		t.Fatal(err)
	}
	e.scanned(d)
	if len(others) != 1 || others[0] == nil {
		t.Fatalf("the scan's password pulled another repository: %v", others)
	}
	// Nor does it push, nor sign in after its scan.
	pw := f.requests()[0].Password
	f.mu.Lock()
	f.hold, f.also = make(chan struct{}), nil
	f.mu.Unlock()
	if _, err := e.reg.QueueScan("shop/api", api, "dev"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(f.requests()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the second scan did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	live := f.requests()[1].Password
	tok := tokenWith(t, e, ScannerUser, live, "repository:shop/api:pull,push", "registry:catalog:*")
	if a := e.do("POST", "/v2/shop/api/blobs/uploads/", tok, nil); a.code != 403 {
		t.Errorf("the scanner pushed: %d", a.code)
	}
	if a := e.do("GET", "/v2/_catalog", tok, nil); a.code != 403 {
		t.Errorf("the scanner listed the catalog: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/api/manifests/"+api, tok, nil); a.code != 200 {
		t.Errorf("the scanner could not pull: %d", a.code)
	}
	close(f.hold)
	e.scanned(api)
	if code := tokenCode(e, ScannerUser, pw); code != 401 {
		t.Errorf("an old scan's password: %d", code)
	}
	if code := tokenCode(e, ScannerUser, live); code != 401 {
		t.Errorf("the ended scan's password: %d", code)
	}
}

// tokenWith gets a token with a name and password.
func tokenWith(t *testing.T, e *env, user, password string, scopes ...string) string {
	t.Helper()
	q := "/token?service=kartal-registry"
	for _, s := range scopes {
		q += "&scope=" + s
	}
	req := httptest.NewRequest("GET", q, nil)
	req.SetBasicAuth(user, password)
	w := httptest.NewRecorder()
	e.reg.Public().ServeHTTP(w, req)
	var body struct {
		Token string `json:"token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	return body.Token
}

func tokenCode(e *env, user, password string) int {
	req := httptest.NewRequest("GET", "/token?service=kartal-registry&scope=repository:shop/api:pull", nil)
	req.SetBasicAuth(user, password)
	w := httptest.NewRecorder()
	e.reg.Public().ServeHTTP(w, req)
	return w.Code
}

func TestScanIndex(t *testing.T) {
	e, _ := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	amd, _ := e.pushImage("shop/web", "1.0-amd64", ci, "amd64")
	arm, _ := e.pushImage("shop/web", "1.0-arm64", ci, "arm64")
	index := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIIndex + `","manifests":[
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + amd + `","size":1,"platform":{"architecture":"amd64","os":"linux"}},
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + arm + `","size":1,"platform":{"architecture":"arm64","os":"linux"}}]}`)
	a := e.do("PUT", "/v2/shop/web/manifests/1.0", ci, index, "Content-Type", manifest.OCIIndex)
	if a.code != 201 {
		t.Fatalf("index: %d %s", a.code, a.body)
	}
	idx := a.h.Get("Docker-Content-Digest")
	images, err := e.reg.QueueScan("shop/web", idx, "dev")
	if err != nil || len(images) != 2 {
		t.Fatalf("queue the index: %v %v", images, err)
	}
	e.scanned(amd)
	e.scanned(arm)
	var d ArtifactDetail
	if a := e.do("GET", "/admin/v1/artifact?repo=shop/web&ref=1.0", "admin-secret", nil); json.Unmarshal(a.body, &d) != nil || d.Scan == nil ||
		d.Scan.Status != meta.ScanDone || d.Scan.Images != 2 || d.Scan.Done != 2 || d.Scan.Summary.Critical != 1 || len(d.Children) != 2 ||
		d.Children[0].Scan == nil || d.Children[0].Scan.Status != meta.ScanDone {
		t.Fatalf("index view: %s", a.body)
	}
	// An index is not scanned as such, nor is what is not an image.
	if a := e.do("GET", "/admin/v1/vulnerabilities?repo=shop/web&digest="+idx, "admin-secret", nil); a.code != 400 {
		t.Errorf("an index's vulnerabilities: %d", a.code)
	}
	empty := e.pushBlob("shop/web", ci, []byte("{}"))
	doc := e.pushBlob("shop/web", ci, []byte(`{"spdxVersion":"SPDX-2.3"}`))
	sbom := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","artifactType":"application/spdx+json",
		"config":{"mediaType":"` + manifest.OCIEmpty + `","digest":"` + empty + `","size":2},
		"layers":[{"mediaType":"application/spdx+json","digest":"` + doc + `","size":26}]}`)
	if a := e.do("PUT", "/v2/shop/web/manifests/"+blobstore.Digest(sbom), ci, sbom, "Content-Type", manifest.OCIManifest); a.code != 201 {
		t.Fatalf("sbom: %d %s", a.code, a.body)
	}
	if _, err := e.reg.QueueScan("shop/web", blobstore.Digest(sbom), "dev"); !errors.Is(err, ErrNotScannable) {
		t.Errorf("an SBOM queued: %v", err)
	}
	if a := e.do("POST", "/admin/v1/scan", "admin-secret", []byte(`{"repo":"shop/web","digest":"`+blobstore.Digest(sbom)+`"}`)); a.code != 400 {
		t.Errorf("an SBOM's scan: %d", a.code)
	}
}

func TestScanAll(t *testing.T) {
	e, f := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/clean:pull,push", "repository:infra/broken:pull,push")
	web, _ := e.pushImage("shop/web", "1", ci, "amd64")
	e.pushImage("shop/clean", "1", ci, "amd64")
	broken, _ := e.pushImage("infra/broken", "1", ci, "amd64")
	f.fail["infra/broken"] = "unable to inspect the image"
	found := false
	for _, sc := range e.db.Schedules() {
		found = found || (sc.Kind == JobScan && sc.Enabled)
	}
	if !found {
		t.Error("no schedule scans every image")
	}
	if _, err := e.reg.StartJob(JobScan, true, "", "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a scan's dry run: %v", err)
	}
	j, err := e.reg.StartJob(JobScan, false, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	j = e.wait(j.ID)
	var rep ScanReport
	json.Unmarshal(j.Report, &rep)
	if j.Status != meta.JobDone || rep.Images != 3 || rep.Scanned != 2 || rep.Failed != 1 || rep.Critical != 1 || rep.High != 0 ||
		rep.Scanner != "Fake 1.0" || len(rep.Failures) != 1 || rep.Failures[0].Digest != broken || !strings.Contains(j.Alarm, "1 of 3 images") {
		t.Fatalf("job %+v report %+v", j, rep)
	}
	if f.updated() != 1 {
		t.Errorf("%d DB updates", f.updated())
	}
	// A failed scan keeps what the last good one found.
	f.fail["shop/web"] = "the network is down"
	if _, err := e.reg.QueueScan("shop/web", web, "root"); err != nil {
		t.Fatal(err)
	}
	if sc := e.scanned(web); sc.Status != meta.ScanFailed || !strings.Contains(sc.Error, "the network is down") || sc.Summary == nil || sc.Summary.Critical != 1 {
		t.Errorf("failed again: %+v", sc)
	}
}

func TestScanAllStopped(t *testing.T) {
	e, f := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/api:pull,push", "repository:shop/db:pull,push")
	var digests []string
	for _, r := range []string{"shop/web", "shop/api", "shop/db"} {
		d, _ := e.pushImage(r, "1", ci, "amd64")
		digests = append(digests, d)
	}
	f.hold = make(chan struct{})
	j, err := e.reg.StartJob(JobScan, false, "", "root")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(f.requests()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the scans did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := e.reg.CancelJob(j.ID, "dev"); err != nil {
		t.Fatal(err)
	}
	j = e.wait(j.ID)
	if j.Status != meta.JobFailed || !strings.Contains(j.Error, "stopped by dev") {
		t.Fatalf("stopped: %+v", j)
	}
	close(f.hold)
	// The two under way end; the one still waiting is taken out, as it
	// was before: never scanned.
	deadline = time.Now().Add(5 * time.Second)
	for e.reg.QueuedScans() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d still queued", e.reg.QueuedScans())
		}
		time.Sleep(10 * time.Millisecond)
	}
	done, none := 0, 0
	for _, d := range digests {
		if sc, ok := e.db.Scan(d); ok && sc.Status == meta.ScanDone {
			done++
		} else if !ok {
			none++
		}
	}
	if done != 2 || none != 1 || len(f.requests()) != 2 {
		t.Errorf("done %d, never scanned %d, scans %d", done, none, len(f.requests()))
	}
}

func TestScansQueuedWhenTheRegistryStoppedRunAgain(t *testing.T) {
	var d string
	e, f := newScanEnv(t, func(e *env) {
		ci := e.token("ci", "repository:shop/web:pull,push")
		d, _ = e.pushImage("shop/web", "1", ci, "amd64")
		was := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		sum := scanner.Summary{High: 3}
		if err := e.db.PutScan(meta.Scan{Digest: d, Repo: "shop/web", Status: meta.ScanScanning, Scanned: &was, Summary: &sum}); err != nil {
			t.Fatal(err)
		}
	})
	if sc := e.scanned(d); sc.Status != meta.ScanDone || sc.Summary.Critical != 1 || len(f.requests()) != 1 {
		t.Fatalf("after the restart: %+v", sc)
	}
}

func TestGCForgetsTheScansOfDeletedImages(t *testing.T) {
	e, _ := newScanEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	d, _ := e.pushImage("shop/web", "1", ci, "amd64")
	if _, err := e.reg.QueueScan("shop/web", d, "root"); err != nil {
		t.Fatal(err)
	}
	e.scanned(d)
	if _, err := os.Stat(e.reg.reportPath(d)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if rep, _ := e.reg.GC(ctx, 0, false, "root"); rep.Scans != 0 {
		t.Fatalf("a held image's scan collected: %+v", rep)
	}
	if err := e.db.DeleteArtifact("shop/web", d, "root"); err != nil {
		t.Fatal(err)
	}
	if rep, _ := e.reg.GC(ctx, 0, true, "root"); rep.Scans != 1 {
		t.Fatalf("dry run: %+v", rep)
	}
	if _, ok := e.db.Scan(d); !ok {
		t.Fatal("a dry run forgot a scan")
	}
	if rep, err := e.reg.GC(ctx, 0, false, "root"); err != nil || rep.Scans != 1 {
		t.Fatalf("gc: %+v %v", rep, err)
	}
	if _, ok := e.db.Scan(d); ok {
		t.Error("the scan is still known")
	}
	if _, err := os.Stat(e.reg.reportPath(d)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the report is still there: %v", err)
	}
}

func TestNoScanner(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	d, _ := e.pushImage("shop/web", "1", ci, "amd64")
	if _, err := e.reg.QueueScan("shop/web", d, "root"); !errors.Is(err, ErrNoScanner) {
		t.Errorf("queue: %v", err)
	}
	if _, err := e.reg.StartJob(JobScan, false, "", "root"); !errors.Is(err, ErrJob) {
		t.Errorf("scan all: %v", err)
	}
	if a := e.do("POST", "/admin/v1/scan", "admin-secret", []byte(`{"repo":"shop/web","digest":"`+d+`"}`)); a.code != 409 {
		t.Errorf("scan: %d", a.code)
	}
	if a := e.do("GET", "/admin/v1/scanner", "admin-secret", nil); !strings.Contains(string(a.body), `"configured":false`) {
		t.Errorf("scanner: %s", a.body)
	}
	if a := e.do("GET", "/admin/v1/repository?name=shop/web", "admin-secret", nil); strings.Contains(string(a.body), `"scan"`) {
		t.Errorf("a registry without a scanner shows scans: %s", a.body)
	}
	if a := e.do("GET", "/admin/v1/vulnerabilities?repo=shop/web&digest="+d, "admin-secret", nil); a.code != 200 ||
		!strings.Contains(string(a.body), `"status":"none"`) {
		t.Errorf("vulnerabilities: %d %s", a.code, a.body)
	}
	if a := e.do("GET", "/admin/v1/sbom?repo=shop/web&digest="+d, "admin-secret", nil); a.code != 404 {
		t.Errorf("sbom: %d", a.code)
	}
}

func TestTheScannerGetsTokensWhereItIs(t *testing.T) {
	e := newEnv(t)
	e.reg.cfg.PublicURL = "https://registry.example.org"
	e.reg.cfg.ScanAddress = "http://kartal-registry:5000"
	for host, want := range map[string]string{
		"kartal-registry:5000": "http://kartal-registry:5000/token",
		"registry.example.org": "https://registry.example.org/token",
	} {
		req := httptest.NewRequest("GET", "/v2/", nil)
		req.Host = host
		w := httptest.NewRecorder()
		e.reg.Public().ServeHTTP(w, req)
		if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="`+want+`"`) {
			t.Errorf("%s: %s", host, got)
		}
	}
}
