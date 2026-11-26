package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary plays Trivy when KARTAL_FAKE_TRIVY is set: it answers
// version, downloads its "databases", scans and converts, writing down how
// it was called in FAKE_TRIVY_LOG.
func TestMain(m *testing.M) {
	if os.Getenv("KARTAL_FAKE_TRIVY") != "" {
		os.Exit(fakeTrivy(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// call is how the fake was called.
type call struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}

func fakeTrivy(args []string) int {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "TRIVY_") || strings.HasPrefix(k, "KARTAL_") {
			env[k] = v
		}
	}
	if f, err := os.OpenFile(os.Getenv("FAKE_TRIVY_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		b, _ := json.Marshal(call{Args: args, Env: env})
		f.Write(append(b, '\n'))
		f.Close()
	}
	flag := func(name string) string {
		for i, a := range args {
			if a == name && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	has := func(name string) bool {
		for _, a := range args {
			if a == name {
				return true
			}
		}
		return false
	}
	cache := flag("--cache-dir")
	fatal := func(msg string) int {
		fmt.Fprintln(os.Stderr, "2026-11-26T10:00:00Z\tINFO\tsomething first")
		fmt.Fprintln(os.Stderr, "2026-11-26T10:00:01Z\tFATAL\tFatal error\t"+msg)
		return 1
	}
	switch {
	case args[0] == "version":
		v := os.Getenv("FAKE_TRIVY_VERSION")
		if v == "" {
			v = "0.69.3"
		}
		out := map[string]any{"Version": v}
		if b, err := os.ReadFile(filepath.Join(cache, "db", "metadata.json")); err == nil {
			out["VulnerabilityDB"] = json.RawMessage(b)
		}
		if b, err := os.ReadFile(filepath.Join(cache, "java-db", "metadata.json")); err == nil {
			out["JavaDB"] = json.RawMessage(b)
		}
		json.NewEncoder(os.Stdout).Encode(out)
	case has("--download-db-only"):
		if os.Getenv("FAKE_TRIVY_DB_FAIL") != "" {
			return fatal("init error: DB error: failed to download vulnerability DB: OCI repository error: connection refused")
		}
		time.Sleep(50 * time.Millisecond)
		os.MkdirAll(filepath.Join(cache, "db"), 0o755)
		os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(`{"Version":2,"UpdatedAt":"2026-11-26T06:00:00Z","NextUpdate":"2026-11-27T06:00:00Z","DownloadedAt":"2026-11-26T09:00:00Z"}`), 0o644)
	case has("--download-java-db-only"):
		os.MkdirAll(filepath.Join(cache, "java-db"), 0o755)
		os.WriteFile(filepath.Join(cache, "java-db", "metadata.json"), []byte(`{"Version":1,"UpdatedAt":"2026-11-25T01:00:00Z","NextUpdate":"2026-11-28T01:00:00Z","DownloadedAt":"2026-11-26T09:00:01Z"}`), 0o644)
	case args[0] == "image":
		image := args[len(args)-1]
		if args[len(args)-2] != "--" {
			return fatal("the image is not after --")
		}
		if d := os.Getenv("FAKE_TRIVY_SLEEP"); d != "" {
			n, _ := time.ParseDuration(d)
			time.Sleep(n)
		}
		if strings.Contains(image, "broken") {
			return fatal("image scan error: scan error: unable to inspect the image (" + image + "): GET https://x/v2/: UNAUTHORIZED")
		}
		os.WriteFile(flag("--output"), []byte(sampleReport), 0o644)
	case args[0] == "convert":
		if os.Getenv("FAKE_TRIVY_NO_SBOM") != "" {
			return fatal("convert error")
		}
		os.WriteFile(flag("--output"), []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"openssl","version":"3.0.11-1"}]}`), 0o644)
	default:
		return fatal("unknown command " + args[0])
	}
	return 0
}

const sampleReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "registry.example.org/shop/web@sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "Metadata": {"OS": {"Family": "debian", "Name": "12.5"}},
  "Results": [
    {"Target": "registry.example.org/shop/web (debian 12.5)", "Class": "os-pkgs", "Type": "debian",
     "Packages": [{"Name": "openssl"}, {"Name": "zlib1g"}, {"Name": "libc6"}],
     "Vulnerabilities": [
       {"VulnerabilityID": "CVE-2026-0002", "PkgName": "zlib1g", "InstalledVersion": "1:1.2.13", "Status": "affected", "Severity": "MEDIUM",
        "Title": "zlib: something", "Description": "a long description that is left out", "CVSS": {"redhat": {"V3Score": 5.3}}},
       {"VulnerabilityID": "CVE-2026-0001", "PkgName": "openssl", "InstalledVersion": "3.0.11-1", "FixedVersion": "3.0.13-1", "Status": "fixed",
        "Severity": "CRITICAL", "Title": "openssl: a bad one", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-0001",
        "PublishedDate": "2026-01-02T00:00:00Z", "CVSS": {"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 8.1}}},
       {"VulnerabilityID": "CVE-2025-9999", "PkgName": "libc6", "InstalledVersion": "2.36-9", "Severity": "strange"}
     ]},
    {"Target": "app/server", "Class": "lang-pkgs", "Type": "gobinary",
     "Packages": [{"Name": "golang.org/x/net"}],
     "Vulnerabilities": [
       {"VulnerabilityID": "CVE-2026-0003", "PkgName": "golang.org/x/net", "InstalledVersion": "v0.20.0", "FixedVersion": "0.23.0", "Severity": "HIGH",
        "CVSS": {"ghsa": {"V3Score": 7.5}}}
     ]}
  ]
}`

func TestTrim(t *testing.T) {
	rep, err := Trim([]byte(sampleReport))
	if err != nil {
		t.Fatal(err)
	}
	if rep.OS != "debian 12.5" || rep.Packages != 4 {
		t.Fatalf("os %q packages %d", rep.OS, rep.Packages)
	}
	var ids []string
	for _, v := range rep.Vulnerabilities {
		ids = append(ids, v.ID+"/"+v.Severity)
	}
	if got := strings.Join(ids, " "); got != "CVE-2026-0001/CRITICAL CVE-2026-0003/HIGH CVE-2026-0002/MEDIUM CVE-2025-9999/UNKNOWN" {
		t.Fatalf("order %s", got)
	}
	first := rep.Vulnerabilities[0]
	if first.Score != 9.8 || first.Fixed != "3.0.13-1" || first.Target == "" || first.Type != "debian" || first.Published == nil {
		t.Fatalf("first %+v", first)
	}
	if rep.Vulnerabilities[1].Score != 7.5 || rep.Vulnerabilities[2].Score != 5.3 {
		t.Fatalf("scores %+v", rep.Vulnerabilities)
	}
	s := Summarize(rep.Vulnerabilities)
	if s != (Summary{Critical: 1, High: 1, Medium: 1, Unknown: 1, Fixable: 2}) || s.Total() != 4 || s.AtLeast(High) != 2 || s.AtLeast(Low) != 3 {
		t.Fatalf("summary %+v", s)
	}
	if w := Worst(Summary{Critical: 1, Low: 5}, Summary{High: 2, Low: 1}); w != (Summary{Critical: 1, High: 2, Low: 5}) {
		t.Fatalf("worst %+v", w)
	}
	if _, err := Trim([]byte("not json")); err == nil {
		t.Fatal("garbage was read")
	}
}

// fake starts a scanner around the fake Trivy; env goes to it.
func fake(t *testing.T, cfg Config, env ...string) (*Service, *Client, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.jsonl")
	cfg.Trivy, cfg.CacheDir, cfg.Secret = exe, filepath.Join(dir, "cache"), "scanner-secret-123"
	cfg.Env = append([]string{"KARTAL_FAKE_TRIVY=1", "FAKE_TRIVY_LOG=" + logPath}, env...)
	svc := New(cfg)
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)
	return svc, &Client{URL: ts.URL, Secret: cfg.Secret}, logPath
}

func calls(t *testing.T, path string) []call {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []call
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var c call
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

const image = "registry.example.org:5000/shop/web@sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestScan(t *testing.T) {
	// The scanner's own secret is not Trivy's to see.
	t.Setenv("KARTAL_SCANNER_SECRET", "not-for-trivy")
	_, c, logPath := fake(t, Config{DBRepository: "registry.example.org/trivy/trivy-db:2", Offline: true})
	ctx := context.Background()
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Scanner != "Trivy 0.69.3" || st.DB != nil || st.Workers != 2 || st.DBRepository == "" {
		t.Fatalf("status before %+v", st)
	}
	// The first scan gets the databases first.
	res, err := c.Scan(ctx, Request{Image: image, Username: "kartal$scanner", Password: "the-ticket", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Scanner != "Trivy 0.69.3" || res.Report.DB == nil || !res.Report.DB.Equal(time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC)) ||
		len(res.Report.Vulnerabilities) != 4 || !strings.Contains(string(res.SBOM), "CycloneDX") {
		t.Fatalf("result %+v sbom %s", res.Report, res.SBOM)
	}
	st, _ = c.Status(ctx)
	if st.DB == nil || st.JavaDB == nil || st.LastUpdate == nil || st.UpdateError != "" || st.Scanning != 0 {
		t.Fatalf("status after %+v", st)
	}
	var scan *call
	downloads := 0
	for _, cl := range calls(t, logPath) {
		if strings.Contains(strings.Join(cl.Args, " "), "--download-db-only") {
			downloads++
			if cl.Env["TRIVY_DB_REPOSITORY"] != "registry.example.org/trivy/trivy-db:2" {
				t.Fatalf("db repository %v", cl.Env)
			}
		}
		if cl.Args[0] == "image" && cl.Args[len(cl.Args)-1] == image {
			cl := cl
			scan = &cl
		}
		if _, ok := cl.Env["KARTAL_SCANNER_SECRET"]; ok {
			t.Fatal("the scanner's own environment went to Trivy")
		}
	}
	if downloads != 1 || scan == nil {
		t.Fatalf("downloads %d scan %v", downloads, scan)
	}
	args := strings.Join(scan.Args, " ")
	if strings.Contains(args, "the-ticket") || scan.Env["TRIVY_PASSWORD"] != "the-ticket" || scan.Env["TRIVY_USERNAME"] != "kartal$scanner" {
		t.Fatalf("credentials: args %s env %v", args, scan.Env)
	}
	for _, want := range []string{"--skip-db-update", "--skip-java-db-update", "--scanners vuln", "--insecure", "--list-all-pkgs"} {
		if !strings.Contains(args, want) {
			t.Fatalf("%s missing from %s", want, args)
		}
	}
	if scan.Env["TRIVY_OFFLINE_SCAN"] != "true" || scan.Env["TRIVY_SKIP_VERSION_CHECK"] != "true" {
		t.Fatalf("env %v", scan.Env)
	}
	// A second scan downloads nothing.
	if _, err := c.Scan(ctx, Request{Image: image}); err != nil {
		t.Fatal(err)
	}
	downloads = 0
	for _, cl := range calls(t, logPath) {
		if strings.Contains(strings.Join(cl.Args, " "), "--download-db-only") {
			downloads++
		}
	}
	if downloads != 1 {
		t.Fatalf("downloads %d", downloads)
	}
}

func TestScanRefusals(t *testing.T) {
	_, c, _ := fake(t, Config{})
	ctx := context.Background()
	// The secret is needed, but not for the health check.
	bad := &Client{URL: c.URL, Secret: "wrong"}
	if _, err := bad.Status(ctx); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("wrong secret: %v", err)
	}
	resp, err := http.Get(c.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz %v %v", resp, err)
	}
	resp.Body.Close()
	// Only an image by digest, that cannot be taken for a flag.
	for _, img := range []string{"", "--help", "shop/web:latest", "registry.example.org/shop/web:1.0", "-x/shop@sha256:" + strings.Repeat("1", 64),
		"registry.example.org/Shop/web@sha256:" + strings.Repeat("1", 64), "registry.example.org/shop/web@sha256:abc"} {
		if _, err := c.Scan(ctx, Request{Image: img}); !errors.Is(err, ErrScanner) || !strings.Contains(err.Error(), "by digest") {
			t.Fatalf("%q: %v", img, err)
		}
	}
	// Trivy's failure is told by what it logged.
	_, err = c.Scan(ctx, Request{Image: "registry.example.org/shop/broken@sha256:" + strings.Repeat("2", 64)})
	if err == nil || !strings.Contains(err.Error(), "unable to inspect the image") || strings.Contains(err.Error(), "FATAL") || strings.Contains(err.Error(), "2026-11-26") {
		t.Fatalf("broken: %v", err)
	}
}

func TestNoSBOMStillReports(t *testing.T) {
	_, c, _ := fake(t, Config{}, "FAKE_TRIVY_NO_SBOM=1")
	res, err := c.Scan(context.Background(), Request{Image: image})
	if err != nil || len(res.Report.Vulnerabilities) != 4 || res.SBOM != nil {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestDBFailure(t *testing.T) {
	_, c, _ := fake(t, Config{}, "FAKE_TRIVY_DB_FAIL=1")
	ctx := context.Background()
	if _, err := c.UpdateDB(ctx); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("update: %v", err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.DB != nil || !strings.Contains(st.UpdateError, "connection refused") {
		t.Fatalf("status %+v %v", st, err)
	}
	// A scan without a database says why there is none.
	if _, err := c.Scan(ctx, Request{Image: image}); err == nil || !strings.Contains(err.Error(), "no vulnerability DB") {
		t.Fatalf("scan: %v", err)
	}
}

func TestCompromisedTrivy(t *testing.T) {
	_, c, _ := fake(t, Config{}, "FAKE_TRIVY_VERSION=v0.69.4")
	ctx := context.Background()
	if _, err := c.Status(ctx); err == nil || !strings.Contains(err.Error(), "malicious") {
		t.Fatalf("status: %v", err)
	}
	if _, err := c.Scan(ctx, Request{Image: image}); err == nil || !strings.Contains(err.Error(), "malicious") {
		t.Fatalf("scan: %v", err)
	}
}

func TestScansWaitTheirTurn(t *testing.T) {
	svc, c, _ := fake(t, Config{Workers: 1}, "FAKE_TRIVY_SLEEP=600ms")
	ctx := context.Background()
	if _, err := c.UpdateDB(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.Scan(ctx, Request{Image: image})
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		svc.mu.Lock()
		scanning, waiting := svc.scanning, svc.waiting
		svc.mu.Unlock()
		if scanning == 1 && waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scanning %d waiting %d", scanning, waiting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A caller who gives up stops the scan.
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := c.Scan(short, Request{Image: image}); err == nil {
		t.Fatal("a scan outlived its caller")
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		svc.mu.Lock()
		scanning := svc.scanning
		svc.mu.Unlock()
		if scanning == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan kept running")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUpdatesAtOnceAreOne(t *testing.T) {
	_, c, logPath := fake(t, Config{})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.UpdateDB(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	downloads := 0
	for _, cl := range calls(t, logPath) {
		if strings.Contains(strings.Join(cl.Args, " "), "--download-db-only") {
			downloads++
		}
	}
	// Three at once may be one or two updates, never three.
	if downloads < 1 || downloads > 2 {
		t.Fatalf("downloads %d", downloads)
	}
}

func TestRank(t *testing.T) {
	if Rank("critical") != 4 || Rank(Low) != 1 || Rank(Unknown) != 0 || Rank("nope") != -1 {
		t.Fatal("ranks")
	}
}
