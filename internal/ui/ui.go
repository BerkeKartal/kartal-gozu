// Package ui embeds the web interface: plain HTML, CSS and one ES module.
// There is nothing to build and nothing is fetched from the internet, so the
// UI works in air-gapped networks exactly as it does anywhere else.
package ui

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/httpx"
)

//go:embed static
var static embed.FS

type asset struct {
	body, gz    []byte
	contentType string
	etag        string
}

// Set explicitly: on Windows the mime package reads the registry, which can
// map .js to text/plain, and browsers refuse to run modules served that way.
var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".svg":  "image/svg+xml",
}

var (
	assets = map[string]*asset{}
	index  *asset
	// policy is the Content-Security-Policy of the page.
	policy string
)

func init() {
	entries, err := fs.ReadDir(static, "static")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		b, err := fs.ReadFile(static, "static/"+e.Name())
		if err != nil {
			panic(err)
		}
		assets[e.Name()] = newAsset(e.Name(), b)
	}
	index = assets["index.html"]
	delete(assets, "index.html")
	policy = contentPolicy(index.body)
}

func newAsset(name string, b []byte) *asset {
	sum := sha256.Sum256(b)
	a := &asset{body: b, contentType: contentTypes[path.Ext(name)], etag: `W/"` + hex.EncodeToString(sum[:8]) + `"`}
	if a.contentType == "" {
		a.contentType = "application/octet-stream"
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(b)
	zw.Close()
	if buf.Len() < len(b) {
		a.gz = buf.Bytes()
	}
	return a
}

// contentPolicy allows same-origin resources only, plus the page's one inline
// script (it adds the trailing slash that relative URLs depend on).
func contentPolicy(page []byte) string {
	sum := sha256.Sum256([]byte(InlineScript(page)))
	return "default-src 'none'; script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; " +
		"style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

// InlineScript returns the body of the first attribute-less <script> element.
func InlineScript(page []byte) string {
	s := string(page)
	const open, end = "<script>", "</script>"
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	j := strings.Index(s, end)
	if j < 0 {
		return ""
	}
	return s[:j]
}

// Assets serves the files below /_ui/.
func Assets() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := assets[strings.TrimPrefix(r.URL.Path, "/_ui/")]
		if a == nil {
			http.NotFound(w, r)
			return
		}
		serve(w, r, a)
	})
}

// Index serves the page itself; the caller decides at which paths.
func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", policy)
	serve(w, r, index)
}

// serve sends an embedded file. "no-cache" with an ETag means browsers keep
// the file but check it on every load, so an upgrade is never half-applied.
func serve(w http.ResponseWriter, r *http.Request, a *asset) {
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", a.etag)
	h.Set("Vary", "Accept-Encoding")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	if strings.Contains(r.Header.Get("If-None-Match"), a.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.body
	if a.gz != nil && httpx.AcceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}
