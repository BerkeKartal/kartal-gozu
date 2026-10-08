package ui

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyAllowsTheInlineScript(t *testing.T) {
	script := InlineScript(index.body)
	if !strings.Contains(script, "location.replace") {
		t.Fatalf("inline script not found: %q", script)
	}
	sum := sha256.Sum256([]byte(script))
	if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(policy, want) {
		t.Errorf("policy %q does not allow the inline script (%s)", policy, want)
	}
	if n := strings.Count(string(index.body), "<script"); n != 2 {
		t.Errorf("index.html has %d scripts; the policy expects one inline script and app.js", n)
	}
}

// The UI must work without internet access: nothing may be loaded from
// another origin.
func TestNothingComesFromElsewhere(t *testing.T) {
	files := map[string]string{"index.html": string(index.body)}
	for name, a := range assets {
		if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css") {
			files[name] = string(a.body)
		}
	}
	for _, name := range []string{"app.js", "app.css", "yaml.js", "chart.js", "plot.js"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("%s is not embedded", name)
		}
	}
	// The allowed uses: links to the hosts of the cluster's ingresses, and
	// the SVG namespace, which is a name and never fetched.
	files["app.js"] = strings.Replace(files["app.js"], "(tls ? 'https://' : 'http://')", "", 1)
	files["chart.js"] = strings.Replace(files["chart.js"], "'http://www.w3.org/2000/svg'", "", 1)
	files["plot.js"] = strings.Replace(files["plot.js"], "'http://www.w3.org/2000/svg'", "", 1)
	for name, body := range files {
		for _, bad := range []string{"http://", "https://", "//cdn", "@import"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

func get(h http.Handler, path string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAssets(t *testing.T) {
	h := Assets()
	for name, ctype := range map[string]string{"app.js": "text/javascript", "app.css": "text/css", "eagle.svg": "image/svg+xml"} {
		rec := get(h, "/_ui/"+name)
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), ctype) {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get("Content-Type"))
			continue
		}
		if again := get(h, "/_ui/"+name, "If-None-Match", rec.Header().Get("ETag")); again.Code != http.StatusNotModified {
			t.Errorf("%s: revalidation got %d, want 304", name, again.Code)
		}
	}

	rec := get(h, "/_ui/app.js", "Accept-Encoding", "gzip")
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("app.js was not compressed for a gzip-capable client")
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); string(b) != string(assets["app.js"].body) {
		t.Error("compressed app.js does not match the original")
	}

	for _, path := range []string{"/_ui/nope.js", "/_ui/index.html", "/_ui/"} {
		if rec := get(h, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, rec.Code)
		}
	}
}
