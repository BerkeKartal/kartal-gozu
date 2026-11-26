package remote_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/remote"
)

// ci may push to any project.
type ci struct{}

func (ci) Authorize(_ context.Context, user, secret string, projects []string) (registry.Identity, error) {
	if user != "ci" || secret != "pw" {
		return registry.Identity{}, registry.ErrBadCredentials
	}
	roles := map[string]auth.Role{}
	for _, p := range projects {
		roles[p] = auth.Operator
	}
	return registry.Identity{Subject: "ci", Roles: roles}, nil
}

// source is a kartal-registry to read, with a project shop.
func source(t *testing.T) *httptest.Server {
	t.Helper()
	store, _ := blobstore.NewFile(t.TempDir())
	db, err := meta.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.CreateProject(meta.Project{Name: "shop"}, "root")
	srv := httptest.NewServer(registry.New(registry.Config{Store: store, DB: db, Auth: ci{}}).Public())
	t.Cleanup(srv.Close)
	return srv
}

// push pushes an image the way docker does, and answers its digest.
func push(t *testing.T, base, repo, tag string) string {
	t.Helper()
	q := url.Values{"service": {"kartal-registry"}, "scope": {"repository:" + repo + ":pull,push"}}
	req, _ := http.NewRequest("GET", base+"/token?"+q.Encode(), nil)
	req.SetBasicAuth("ci", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tok struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	do := func(method, path string, body []byte, ct string) *http.Response {
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok.Token)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	cfg := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("a layer of " + repo + ":" + tag)
	for _, b := range [][]byte{cfg, layer} {
		if r := do("POST", "/v2/"+repo+"/blobs/uploads/?digest="+url.QueryEscape(blobstore.Digest(b)), b, ""); r.StatusCode != 201 {
			t.Fatalf("blob: %d", r.StatusCode)
		}
	}
	m := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		blobstore.Digest(cfg) + `","size":` + strconv.Itoa(len(cfg)) + `},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` +
		blobstore.Digest(layer) + `","size":` + strconv.Itoa(len(layer)) + `}]}`)
	if r := do("PUT", "/v2/"+repo+"/manifests/"+tag, m, manifest.OCIManifest); r.StatusCode != 201 {
		t.Fatalf("manifest: %d", r.StatusCode)
	}
	return blobstore.Digest(m)
}

func TestARegistry(t *testing.T) {
	src := source(t)
	d := push(t, src.URL, "shop/web", "1.0")
	push(t, src.URL, "shop/web", "1.1")
	push(t, src.URL, "shop/api", "2.0")
	ctx := context.Background()
	if c, _ := remote.New(remote.Options{URL: src.URL, Username: "ci", Password: "wrong"}); c.Ping(ctx) == nil {
		t.Error("a wrong password let in")
	}
	c, err := remote.New(remote.Options{URL: src.URL + "/", Username: "ci", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if repos, err := c.Catalog(ctx); err != nil || strings.Join(repos, ",") != "shop/api,shop/web" {
		t.Errorf("catalog: %v %v", repos, err)
	}
	if tags, err := c.Tags(ctx, "shop/web"); err != nil || strings.Join(tags, ",") != "1.0,1.1" {
		t.Errorf("tags: %v %v", tags, err)
	}
	body, mt, digest, err := c.Manifest(ctx, "shop/web", "1.0")
	if err != nil || mt != manifest.OCIManifest || digest != d {
		t.Fatalf("manifest: %s %s %v", mt, digest, err)
	}
	if _, _, _, err := c.Manifest(ctx, "shop/web", d); err != nil {
		t.Errorf("by digest: %v", err)
	}
	var m manifest.Manifest
	json.Unmarshal(body, &m)
	rc, _, err := c.Blob(ctx, "shop/web", m.Layers[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "a layer of shop/web:1.0" {
		t.Errorf("blob: %q", b)
	}
	if _, _, err := c.Blob(ctx, "shop/web", "sha256:"+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("a missing blob: %v", err)
	}
	if refs, err := c.Referrers(ctx, "shop/web", d); err != nil || len(refs) != 0 {
		t.Errorf("referrers: %v %v", refs, err)
	}
	s := remote.Source{Kind: remote.KindRegistry, URL: src.URL}
	imgs, err := remote.Images(ctx, s, c, "shop/*", func(r string) bool { return r == "shop/web" })
	if err != nil || len(imgs) != 2 || imgs[0].Repo != "shop/web" || imgs[0].Tag != "1.0" {
		t.Errorf("images: %+v %v", imgs, err)
	}
	// One repository named is read without the catalog.
	imgs, err = remote.Images(ctx, s, c, "shop/api", func(r string) bool { return r == "shop/api" })
	if err != nil || len(imgs) != 1 {
		t.Errorf("one repository: %+v %v", imgs, err)
	}
	if ps, err := remote.Projects(ctx, s, c); err != nil || len(ps) != 1 || ps[0].Name != "shop" || ps[0].Repositories != 2 {
		t.Errorf("projects: %+v %v", ps, err)
	}
}

func TestRetriesAndChallenges(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "u" || pass != "p" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, _ := remote.New(remote.Options{URL: srv.URL, Username: "u", Password: "p"})
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("after a 503, with Basic: %v", err)
	}
	none, _ := remote.New(remote.Options{URL: srv.URL})
	if err := none.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "user name and password") {
		t.Errorf("without credentials: %v", err)
	}
	if _, err := remote.New(remote.Options{URL: "ftp://example.org"}); err == nil {
		t.Error("an ftp address was taken")
	}
	if _, err := remote.New(remote.Options{URL: "https://example.org", CA: "not a certificate"}); err == nil {
		t.Error("a CA that is not one was taken")
	}
}

func basic(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func TestHarbor(t *testing.T) {
	pushed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !basic(t, w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v2.0/projects":
			fmt.Fprint(w, `[{"name":"library","repo_count":1,"metadata":{"public":"true"}},{"name":"team-a","repo_count":1,"metadata":{"public":"false"}}]`)
		case r.URL.Path == "/api/v2.0/projects/team-a/repositories":
			fmt.Fprint(w, `[{"name":"team-a/apps/web"}]`)
		case r.URL.Path == "/api/v2.0/projects/library/repositories":
			fmt.Fprint(w, `[{"name":"library/nginx"}]`)
		case r.URL.EscapedPath() == "/api/v2.0/projects/team-a/repositories/apps%252Fweb/artifacts":
			fmt.Fprintf(w, `[{"digest":"sha256:%s","push_time":%q,"tags":[{"name":"1.0"},{"name":"latest"}]},{"digest":"sha256:%s","tags":null}]`,
				strings.Repeat("a", 64), pushed.Format(time.RFC3339), strings.Repeat("b", 64))
		default:
			t.Errorf("unexpected %s", r.URL.EscapedPath())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	s := remote.Source{Kind: remote.KindHarbor, URL: srv.URL, Options: remote.Options{Username: "admin", Password: "secret"}}
	c, err := remote.Open(s)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := remote.Projects(context.Background(), s, c)
	if err != nil || len(ps) != 2 || !ps[0].Public || ps[1].Public {
		t.Errorf("projects: %+v %v", ps, err)
	}
	imgs, err := remote.Images(context.Background(), s, c, "team-a/**", func(r string) bool { return strings.HasPrefix(r, "team-a/") })
	if err != nil || len(imgs) != 2 || imgs[0].Repo != "team-a/apps/web" || imgs[0].Tag != "1.0" || !imgs[0].Pushed.Equal(pushed) ||
		imgs[1].Tag != "latest" || imgs[0].Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Errorf("images: %+v %v", imgs, err)
	}
	s.Options.Password = "wrong"
	c, _ = remote.Open(s)
	if _, err := remote.Projects(context.Background(), s, c); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a wrong password: %v", err)
	}
}

func TestNexus(t *testing.T) {
	sum := strings.Repeat("c", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !basic(t, w, r) {
			return
		}
		if r.URL.Path != "/nexus/service/rest/v1/components" || r.URL.Query().Get("repository") != "docker-hosted" {
			t.Errorf("unexpected %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continuationToken") == "" {
			fmt.Fprintf(w, `{"items":[{"name":"team-a/web","version":"1.0","assets":[{"path":"v2/team-a/web/manifests/1.0","lastModified":"2026-09-01T10:00:00.000+00:00","checksum":{"sha256":%q}}]}],"continuationToken":"next"}`, sum)
			return
		}
		fmt.Fprint(w, `{"items":[{"name":"team-b/api","version":"2.0","assets":[]}],"continuationToken":null}`)
	}))
	defer srv.Close()
	s := remote.Source{Kind: remote.KindNexus, URL: srv.URL + "/nexus", Repository: "docker-hosted", Options: remote.Options{Username: "admin", Password: "secret"}}
	c, err := remote.Open(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(c.URL(), "/nexus/repository/docker-hosted") {
		t.Errorf("the Docker API's address: %s", c.URL())
	}
	imgs, err := remote.Images(context.Background(), s, c, "**", func(string) bool { return true })
	if err != nil || len(imgs) != 2 || imgs[0].Digest != "sha256:"+sum || imgs[0].Pushed.IsZero() || imgs[1].Digest != "" {
		t.Errorf("images: %+v %v", imgs, err)
	}
	if ps, err := remote.Projects(context.Background(), s, c); err != nil || len(ps) != 2 {
		t.Errorf("projects: %+v %v", ps, err)
	}
	if _, err := remote.Open(remote.Source{Kind: remote.KindNexus, URL: srv.URL}); err == nil {
		t.Error("a Nexus source without its repository")
	}
}
