package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

// cannedScanner finds the same two vulnerabilities in every image, without
// pulling it.
type cannedScanner struct{}

func (cannedScanner) Scan(context.Context, scanner.Request) (scanner.Result, error) {
	return scanner.Result{Report: scanner.Report{Scanner: "Canned 1", Packages: 2, Vulnerabilities: []scanner.Vulnerability{
		{ID: "CVE-2026-1000", Package: "openssl", Installed: "3.0.11", Fixed: "3.0.13", Severity: scanner.Critical},
		{ID: "CVE-2026-1001", Package: "zlib", Installed: "1.2.13", Severity: scanner.Medium},
	}}, SBOM: json.RawMessage(`{"bomFormat":"CycloneDX"}`)}, nil
}

func (cannedScanner) UpdateDB(context.Context) (scanner.Status, error) {
	return scanner.Status{Scanner: "Canned 1"}, nil
}

func (cannedScanner) Status(context.Context) (scanner.Status, error) {
	return scanner.Status{Scanner: "Canned 1"}, nil
}

// pushTiny pushes an image of a config alone, and answers its digest.
func (e *regEnv) pushTiny(repo, tag, tok string) string {
	e.t.Helper()
	cfg := []byte(`{"architecture":"amd64","os":"linux","created":"2026-11-26T10:00:00Z"}`)
	cd := blobstore.Digest(cfg)
	if resp := e.v2("POST", "/v2/"+repo+"/blobs/uploads/?digest="+url.QueryEscape(cd), tok, cfg, ""); resp.StatusCode != 201 {
		e.t.Fatalf("push the config: %d", resp.StatusCode)
	}
	m := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		cd + `","size":` + strconv.Itoa(len(cfg)) + `},"layers":[]}`)
	if resp := e.v2("PUT", "/v2/"+repo+"/manifests/"+tag, tok, m, "application/vnd.oci.image.manifest.v1+json"); resp.StatusCode != 201 {
		e.t.Fatalf("push the manifest: %d", resp.StatusCode)
	}
	return blobstore.Digest(m)
}

func TestRegistryScansThroughTheServer(t *testing.T) {
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
	body := `{"repo":"team-a/web","digest":"` + d + `"}`

	// Everyone sees whether images are scanned.
	if code, b := e.call("GET", "/api/v1/registry", regViewTok, ""); code != 200 || !strings.Contains(string(b), `"scanner":true`) {
		t.Errorf("info: %d %s", code, b)
	}
	// A viewer does not have images scanned; an operator does.
	if code, _ := e.call("POST", "/api/v1/registry/scan", regViewTok, body); code != http.StatusForbidden {
		t.Errorf("a viewer scanned: %d", code)
	}
	if code, b := e.call("POST", "/api/v1/registry/scan", regTeamTok, `{"repo":"nope","digest":"`+d+`"}`); code != 400 {
		t.Errorf("a bad repository: %d %s", code, b)
	}
	if code, b := e.call("POST", "/api/v1/registry/scan", regTeamTok, body); code != http.StatusAccepted {
		t.Fatalf("scan: %d %s", code, b)
	}
	// A viewer reads what it found, once it did.
	path := "/api/v1/registry/vulnerabilities?repo=team-a/web&digest=" + d
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, b := e.call("GET", path, regViewTok, "")
		if code == 200 && strings.Contains(string(b), "CVE-2026-1000") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("vulnerabilities: %d %s", code, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code, _ := e.call("GET", path, clusterTok, ""); code != http.StatusForbidden {
		t.Errorf("a cluster admin read a private project's vulnerabilities: %d", code)
	}
	if code, _ := e.call("GET", "/api/v1/registry/vulnerabilities?repo=team-a/web&digest=latest", regViewTok, ""); code != 400 {
		t.Errorf("a tag for a digest: %d", code)
	}
	// The SBOM comes as a file.
	req, _ := http.NewRequest("GET", e.api.URL+"/api/v1/registry/sbom?repo=team-a/web&digest="+d, nil)
	req.Header.Set("Authorization", "Bearer "+regViewTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Disposition") != `attachment; filename="web-`+d[7:19]+`.cdx.json"` {
		t.Errorf("sbom: %d %v", resp.StatusCode, resp.Header)
	}
	// The scanner is the registry's admins'.
	for _, c := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/api/v1/registry/scanner", regLeadTok, 403},
		{"POST", "/api/v1/registry/scanner/db", regTeamTok, 403},
		{"GET", "/api/v1/registry/scanner", bossTok, 200},
		{"POST", "/api/v1/registry/scanner/db", bossTok, 202},
	} {
		if code, b := e.call(c.method, c.path, c.token, ""); code != c.want {
			t.Errorf("%s %s: %d %s", c.method, c.path, code, b)
		}
	}
	if _, b := e.call("GET", "/api/v1/registry/scanner", bossTok, ""); !strings.Contains(string(b), `"address":"http://kartal-registry:5000"`) {
		t.Errorf("scanner: %s", b)
	}
	// A project's admins have its images scanned on push; its operators do not.
	if code, _ := e.call("PUT", "/api/v1/registry/projects/team-a", regTeamTok, `{"scanOnPush":true}`); code != 403 {
		t.Errorf("an operator set scan on push: %d", code)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, `{"scanOnPush":true}`); code != 200 ||
		!strings.Contains(string(b), `"scanOnPush":true`) {
		t.Errorf("scan on push: %d %s", code, b)
	}
}
