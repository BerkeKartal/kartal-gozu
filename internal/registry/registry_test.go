package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// people is an Authorizer with three users, all with the password "pw".
type people struct{}

func (*people) Authorize(_ context.Context, user, secret string, _ []string) (Identity, error) {
	if secret != "pw" {
		return Identity{}, ErrBadCredentials
	}
	switch user {
	case "ci":
		return Identity{Subject: "ci", Roles: map[string]auth.Role{"shop": auth.Operator, "infra": auth.Operator}}, nil
	case "dev":
		return Identity{Subject: "dev", Roles: map[string]auth.Role{"shop": auth.Viewer}}, nil
	case "root":
		return Identity{Subject: "root", Admin: true}, nil
	}
	return Identity{}, ErrBadCredentials
}

type env struct {
	t   *testing.T
	dir string // the blob store's
	srv *httptest.Server
	adm *httptest.Server
	reg *Server
	db  *meta.DB
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	store, err := blobstore.NewFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := meta.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	reg := New(Config{Store: store, DB: db, Auth: &people{}})
	e := &env{t: t, dir: dir, reg: reg, db: db, srv: httptest.NewServer(reg.Public()), adm: httptest.NewServer(reg.Admin("admin-secret"))}
	t.Cleanup(e.srv.Close)
	t.Cleanup(e.adm.Close)
	for _, p := range []meta.Project{{Name: "shop"}, {Name: "infra"}, {Name: "pub", Public: true}} {
		if err := db.CreateProject(p, "root"); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// token gets a token the way docker does.
func (e *env) token(user string, scopes ...string) string {
	e.t.Helper()
	q := url.Values{"service": {"kartal-registry"}, "scope": scopes}
	req, _ := http.NewRequest("GET", e.srv.URL+"/token?"+q.Encode(), nil)
	if user != "" {
		req.SetBasicAuth(user, "pw")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Token string `json:"token"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&body) != nil || body.Token == "" {
		e.t.Fatalf("token for %s %v: %d", user, scopes, resp.StatusCode)
	}
	return body.Token
}

type answer struct {
	code int
	h    http.Header
	body []byte
}

func (a answer) errCode() string {
	var e struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	json.Unmarshal(a.body, &e)
	if len(e.Errors) == 0 {
		return ""
	}
	return e.Errors[0].Code
}

func (e *env) do(method, path, token string, body []byte, header ...string) answer {
	e.t.Helper()
	base := e.srv.URL
	if strings.HasPrefix(path, "/admin/") {
		base = e.adm.URL
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return answer{resp.StatusCode, resp.Header, b}
}

// pushBlob uploads a blob in two chunks.
func (e *env) pushBlob(repo, token string, content []byte) string {
	e.t.Helper()
	d := blobstore.Digest(content)
	a := e.do("POST", "/v2/"+repo+"/blobs/uploads/", token, nil)
	if a.code != 202 || a.h.Get("Location") == "" {
		e.t.Fatalf("start an upload in %s: %d %s", repo, a.code, a.body)
	}
	loc := a.h.Get("Location")
	half := len(content) / 2
	a = e.do("PATCH", loc, token, content[:half], "Content-Range", "0-"+itoa(half-1), "Content-Type", "application/octet-stream")
	if a.code != 202 || a.h.Get("Range") != "0-"+itoa(max(half-1, 0)) {
		e.t.Fatalf("first chunk: %d %v %s", a.code, a.h, a.body)
	}
	a = e.do("PATCH", loc, token, content[half:])
	if a.code != 202 {
		e.t.Fatalf("second chunk: %d %s", a.code, a.body)
	}
	a = e.do("PUT", loc+"?digest="+url.QueryEscape(d), token, nil)
	if a.code != 201 || a.h.Get("Docker-Content-Digest") != d {
		e.t.Fatalf("finish: %d %s", a.code, a.body)
	}
	return d
}

func itoa(n int) string { return strconv.Itoa(n) }

func jsonInt(n int) string { return strconv.Itoa(n) }

// pushImage pushes a config, a layer and a manifest, tagged.
func (e *env) pushImage(repo, tag, token, arch string) (string, []byte) {
	e.t.Helper()
	cfg := []byte(`{"architecture":"` + arch + `","os":"linux","created":"2026-11-20T10:00:00Z","config":{"Labels":{"org.opencontainers.image.revision":"abc123"}}}`)
	layer := []byte("layer of " + repo + " " + arch)
	cd := e.pushBlob(repo, token, cfg)
	ld := e.pushBlob(repo, token, layer)
	m := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `",
		"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + cd + `","size":` + jsonInt(len(cfg)) + `},
		"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + ld + `","size":` + jsonInt(len(layer)) + `}]}`)
	a := e.do("PUT", "/v2/"+repo+"/manifests/"+tag, token, m, "Content-Type", manifest.OCIManifest)
	if a.code != 201 {
		e.t.Fatalf("push the manifest %s:%s: %d %s", repo, tag, a.code, a.body)
	}
	return a.h.Get("Docker-Content-Digest"), m
}

func TestSignIn(t *testing.T) {
	e := newEnv(t)
	a := e.do("GET", "/v2/", "", nil)
	if a.code != 401 || !strings.Contains(a.h.Get("WWW-Authenticate"), `Bearer realm="`+e.srv.URL+`/token",service="kartal-registry"`) ||
		a.h.Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Fatalf("/v2/ without a token: %d %v", a.code, a.h)
	}
	if a := e.do("GET", "/v2/", e.token("ci"), nil); a.code != 200 {
		t.Errorf("/v2/ with a token: %d", a.code)
	}
	// docker login asks for a token without a scope; wrong credentials are
	// refused there.
	req, _ := http.NewRequest("GET", e.srv.URL+"/token?service=kartal-registry", nil)
	req.SetBasicAuth("ci", "wrong")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	// A password grant, as some clients send.
	resp, _ = http.PostForm(e.srv.URL+"/token", url.Values{"grant_type": {"password"}, "username": {"ci"}, "password": {"pw"},
		"scope": {"repository:shop/web:pull"}, "service": {"kartal-registry"}})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("password grant: %d", resp.StatusCode)
	}
}

func TestPushAndPull(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	digest, body := e.pushImage("shop/web", "1.0", ci, "amd64")

	// Someone who may only pull.
	dev := e.token("dev", "repository:shop/web:pull,push")
	a := e.do("GET", "/v2/shop/web/manifests/1.0", dev, nil)
	if a.code != 200 || !bytes.Equal(a.body, body) || a.h.Get("Content-Type") != manifest.OCIManifest || a.h.Get("Docker-Content-Digest") != digest {
		t.Fatalf("pull: %d %v", a.code, a.h)
	}
	if a := e.do("HEAD", "/v2/shop/web/manifests/"+digest, dev, nil); a.code != 200 || a.h.Get("Content-Length") != jsonInt(len(body)) {
		t.Errorf("head by digest: %d %v", a.code, a.h)
	}
	if a := e.do("POST", "/v2/shop/web/blobs/uploads/", dev, nil); a.code != 403 || a.errCode() != "DENIED" {
		t.Errorf("a viewer's push: %d %s", a.code, a.body)
	}
	// Nobody signed in, and a private project.
	if a := e.do("GET", "/v2/shop/web/manifests/1.0", "", nil); a.code != 401 ||
		!strings.Contains(a.h.Get("WWW-Authenticate"), `scope="repository:shop/web:pull"`) {
		t.Errorf("anonymous pull from a private project: %d %v", a.code, a.h)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/1.0", e.token("", "repository:shop/web:pull"), nil); a.code != 403 {
		t.Errorf("anonymous token for a private project: %d", a.code)
	}
	// A blob, whole and in part.
	var m manifest.Descriptor
	var parsed struct {
		Layers []manifest.Descriptor `json:"layers"`
	}
	json.Unmarshal(body, &parsed)
	m = parsed.Layers[0]
	if a := e.do("HEAD", "/v2/shop/web/blobs/"+m.Digest, dev, nil); a.code != 200 || a.h.Get("Content-Length") != jsonInt(int(m.Size)) {
		t.Errorf("head a blob: %d %v", a.code, a.h)
	}
	if a := e.do("GET", "/v2/shop/web/blobs/"+m.Digest, dev, nil, "Range", "bytes=0-4"); a.code != 206 || string(a.body) != "layer" {
		t.Errorf("a range of a blob: %d %q", a.code, a.body)
	}
	// The blob is in shop/web, not in shop/other, even with the digest.
	other := e.token("ci", "repository:shop/other:pull,push")
	if a := e.do("GET", "/v2/shop/other/blobs/"+m.Digest, other, nil); a.code != 404 || a.errCode() != "BLOB_UNKNOWN" {
		t.Errorf("a blob of another repository: %d %s", a.code, a.body)
	}
	// Pulls are counted.
	e.do("GET", "/v2/shop/web/manifests/1.0", dev, nil)
	if art, _ := e.db.Artifact("shop/web", digest); art.Pulls != 2 || art.PushedBy != "ci" || art.Platform.String() != "linux/amd64" ||
		art.Labels["org.opencontainers.image.revision"] != "abc123" {
		t.Errorf("artifact: %+v", art)
	}
}

func TestPushRefusals(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:nowhere/web:pull,push")
	if a := e.do("POST", "/v2/nowhere/web/blobs/uploads/", ci, nil); a.code != 403 {
		t.Errorf("a project ci has no role in: %d", a.code)
	}
	root := e.token("root", "repository:nowhere/web:pull,push")
	if a := e.do("POST", "/v2/nowhere/web/blobs/uploads/", root, nil); a.code != 404 || a.errCode() != "NAME_UNKNOWN" ||
		!strings.Contains(string(a.body), "project nowhere does not exist") {
		t.Errorf("a project that does not exist: %d %s", a.code, a.body)
	}
	missing := `{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `",
		"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:` + strings.Repeat("e", 64) + `","size":2},"layers":[]}`
	if a := e.do("PUT", "/v2/shop/web/manifests/1.0", ci, []byte(missing), "Content-Type", manifest.OCIManifest); a.code != 400 ||
		a.errCode() != "MANIFEST_BLOB_UNKNOWN" {
		t.Errorf("a manifest whose config is missing: %d %s", a.code, a.body)
	}
	if a := e.do("PUT", "/v2/shop/web/manifests/sha256:"+strings.Repeat("1", 64), ci, []byte(missing), "Content-Type", manifest.OCIManifest); a.code != 400 ||
		a.errCode() != "DIGEST_INVALID" {
		t.Errorf("pushed by the wrong digest: %d %s", a.code, a.body)
	}
	if a := e.do("PUT", "/v2/shop/web/manifests/-bad", ci, []byte(missing), "Content-Type", manifest.OCIManifest); a.code != 400 {
		t.Errorf("a bad tag: %d", a.code)
	}
	if a := e.do("PUT", "/v2/shop/web/manifests/1.0", ci, []byte(`{"schemaVersion":1}`)); a.code != 400 || a.errCode() != "MANIFEST_INVALID" {
		t.Errorf("schema 1: %d %s", a.code, a.body)
	}
	if a := e.do("GET", "/v2/Shop/Web/tags/list", ci, nil); a.code != 400 || a.errCode() != "NAME_INVALID" {
		t.Errorf("an uppercase name: %d", a.code)
	}
	if a := e.do("GET", "/v2/single/tags/list", ci, nil); a.code != 400 || a.errCode() != "NAME_INVALID" {
		t.Errorf("a name without a project: %d", a.code)
	}
	// A chunk that does not start where the upload ends.
	a := e.do("POST", "/v2/shop/web/blobs/uploads/", ci, nil)
	loc := a.h.Get("Location")
	e.do("PATCH", loc, ci, []byte("abcd"), "Content-Range", "0-3")
	if a := e.do("PATCH", loc, ci, []byte("efgh"), "Content-Range", "2-5"); a.code != 416 || a.h.Get("Range") != "0-3" {
		t.Errorf("a chunk at the wrong place: %d %v", a.code, a.h)
	}
	if a := e.do("GET", loc, ci, nil); a.code != 204 || a.h.Get("Range") != "0-3" {
		t.Errorf("upload status: %d %v", a.code, a.h)
	}
	if a := e.do("PUT", loc+"?digest="+url.QueryEscape(blobstore.Digest([]byte("nope"))), ci, nil); a.code != 400 || a.errCode() != "DIGEST_INVALID" {
		t.Errorf("finishing with the wrong digest: %d %s", a.code, a.body)
	}
	// An upload belongs to the repository it was started in.
	infra := e.token("ci", "repository:infra/proxy:pull,push")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if a := e.do("PATCH", "/v2/infra/proxy/blobs/uploads/"+id, infra, []byte("x")); a.code != 404 || a.errCode() != "BLOB_UPLOAD_UNKNOWN" {
		t.Errorf("another repository's upload: %d %s", a.code, a.body)
	}
	if a := e.do("DELETE", loc, ci, nil); a.code != 204 {
		t.Errorf("cancel: %d", a.code)
	}
}

func TestMonolithicAndMount(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/api:pull,push", "repository:infra/proxy:pull,push")
	content := []byte("a whole blob")
	d := blobstore.Digest(content)
	if a := e.do("POST", "/v2/shop/web/blobs/uploads/?digest="+url.QueryEscape(d), ci, content); a.code != 201 || a.h.Get("Docker-Content-Digest") != d {
		t.Fatalf("monolithic: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/v2/shop/web/blobs/uploads/?digest="+url.QueryEscape(blobstore.Digest([]byte("x"))), ci, content); a.code != 400 {
		t.Errorf("monolithic with the wrong digest: %d", a.code)
	}
	if a := e.do("POST", "/v2/shop/api/blobs/uploads/?mount="+url.QueryEscape(d)+"&from=shop/web", ci, nil); a.code != 201 {
		t.Errorf("mount: %d %s", a.code, a.body)
	}
	if a := e.do("HEAD", "/v2/shop/api/blobs/"+d, ci, nil); a.code != 200 {
		t.Errorf("the mounted blob: %d", a.code)
	}
	// From a repository the token cannot read, it is an upload instead.
	noRead := e.token("ci", "repository:infra/proxy:pull,push")
	if a := e.do("POST", "/v2/infra/proxy/blobs/uploads/?mount="+url.QueryEscape(d)+"&from=shop/web", noRead, nil); a.code != 202 {
		t.Errorf("mount from a repository not in the token: %d", a.code)
	}
}

func TestIndexReferrersAndLists(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push,delete")
	amd, _ := e.pushImage("shop/web", "1.0-amd64", ci, "amd64")
	arm, _ := e.pushImage("shop/web", "1.0-arm64", ci, "arm64")
	index := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIIndex + `","manifests":[
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + amd + `","size":1,"platform":{"architecture":"amd64","os":"linux"}},
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + arm + `","size":1,"platform":{"architecture":"arm64","os":"linux"}}]}`)
	a := e.do("PUT", "/v2/shop/web/manifests/1.0", ci, index, "Content-Type", manifest.OCIIndex)
	if a.code != 201 {
		t.Fatalf("index: %d %s", a.code, a.body)
	}
	indexDigest := a.h.Get("Docker-Content-Digest")
	missing := strings.Replace(string(index), amd, "sha256:"+strings.Repeat("9", 64), 1)
	if a := e.do("PUT", "/v2/shop/web/manifests/bad", ci, []byte(missing), "Content-Type", manifest.OCIIndex); a.code != 400 {
		t.Errorf("an index with a missing image: %d", a.code)
	}
	// An SBOM about the index.
	empty := e.pushBlob("shop/web", ci, []byte("{}"))
	doc := e.pushBlob("shop/web", ci, []byte(`{"spdxVersion":"SPDX-2.3"}`))
	sbom := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","artifactType":"application/spdx+json",
		"config":{"mediaType":"` + manifest.OCIEmpty + `","digest":"` + empty + `","size":2},
		"layers":[{"mediaType":"application/spdx+json","digest":"` + doc + `","size":26}],
		"subject":{"mediaType":"` + manifest.OCIIndex + `","digest":"` + indexDigest + `","size":` + jsonInt(len(index)) + `}}`)
	a = e.do("PUT", "/v2/shop/web/manifests/"+blobstore.Digest(sbom), ci, sbom, "Content-Type", manifest.OCIManifest)
	if a.code != 201 || a.h.Get("OCI-Subject") != indexDigest {
		t.Fatalf("sbom: %d %v %s", a.code, a.h, a.body)
	}
	a = e.do("GET", "/v2/shop/web/referrers/"+indexDigest+"?artifactType=application/spdx%2Bjson", ci, nil)
	var refs struct {
		Manifests []manifest.Descriptor `json:"manifests"`
	}
	json.Unmarshal(a.body, &refs)
	if a.code != 200 || a.h.Get("OCI-Filters-Applied") != "artifactType" || len(refs.Manifests) != 1 || refs.Manifests[0].ArtifactType != "application/spdx+json" {
		t.Errorf("referrers: %d %v %s", a.code, a.h, a.body)
	}
	// Tags, a page at a time.
	a = e.do("GET", "/v2/shop/web/tags/list?n=2", ci, nil)
	var tags struct {
		Tags []string `json:"tags"`
	}
	json.Unmarshal(a.body, &tags)
	if a.code != 200 || strings.Join(tags.Tags, ",") != "1.0,1.0-amd64" || !strings.Contains(a.h.Get("Link"), "last=1.0-amd64") {
		t.Errorf("tags: %d %v %s", a.code, a.h, a.body)
	}
	a = e.do("GET", "/v2/shop/web/tags/list?n=2&last=1.0-amd64", ci, nil)
	json.Unmarshal(a.body, &tags)
	if strings.Join(tags.Tags, ",") != "1.0-arm64" || a.h.Get("Link") != "" {
		t.Errorf("the last page: %v %v", tags.Tags, a.h)
	}
	// Deleting a tag keeps the image; deleting by digest removes it.
	if a := e.do("DELETE", "/v2/shop/web/manifests/1.0-arm64", ci, nil); a.code != 202 {
		t.Errorf("delete a tag: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/"+arm, ci, nil); a.code != 200 {
		t.Errorf("the image after its tag went: %d", a.code)
	}
	// An image the index lists stays while the index does.
	if a := e.do("DELETE", "/v2/shop/web/manifests/"+amd, ci, nil); a.code != 409 || a.errCode() != "DENIED" {
		t.Errorf("delete an index's image: %d %s", a.code, a.body)
	}
	// The index goes by its digest, and the SBOM about it with it.
	if a := e.do("DELETE", "/v2/shop/web/manifests/"+indexDigest, ci, nil); a.code != 202 {
		t.Errorf("delete the index: %d %s", a.code, a.body)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/"+blobstore.Digest(sbom), ci, nil); a.code != 404 {
		t.Errorf("the SBOM about a deleted index: %d", a.code)
	}
	if a := e.do("DELETE", "/v2/shop/web/manifests/"+amd, ci, nil); a.code != 202 {
		t.Errorf("delete by digest: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/1.0-amd64", ci, nil); a.code != 404 || a.errCode() != "MANIFEST_UNKNOWN" {
		t.Errorf("a deleted image: %d", a.code)
	}
}

func TestCatalogIsFiltered(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:infra/proxy:pull,push")
	e.pushImage("shop/web", "1", ci, "amd64")
	e.pushImage("infra/proxy", "1", ci, "amd64")
	root := e.token("root", "repository:pub/tools:pull,push")
	e.pushImage("pub/tools", "1", root, "amd64")
	list := func(user string) string {
		a := e.do("GET", "/v2/_catalog", e.token(user, "registry:catalog:*"), nil)
		var c struct {
			Repositories []string `json:"repositories"`
		}
		json.Unmarshal(a.body, &c)
		return strings.Join(c.Repositories, ",")
	}
	if got := list("dev"); got != "pub/tools,shop/web" {
		t.Errorf("dev's catalog: %s", got)
	}
	if got := list("root"); got != "infra/proxy,pub/tools,shop/web" {
		t.Errorf("root's catalog: %s", got)
	}
	if got := list(""); got != "pub/tools" {
		t.Errorf("anonymous catalog: %s", got)
	}
	// Anyone pulls from a public project, even without a token.
	if a := e.do("GET", "/v2/pub/tools/manifests/1", "", nil); a.code != 200 {
		t.Errorf("a public pull without a token: %d", a.code)
	}
	if a := e.do("GET", "/v2/_catalog", ci, nil); a.code != 403 {
		t.Errorf("the catalog with a token not given for it: %d", a.code)
	}
}

func TestAdminAPI(t *testing.T) {
	e := newEnv(t)
	if a := e.do("GET", "/admin/v1/projects", "wrong", nil); a.code != 401 {
		t.Errorf("without the secret: %d", a.code)
	}
	sec := "admin-secret"
	if a := e.do("POST", "/admin/v1/projects", sec, []byte(`{"name":"Bad Name"}`)); a.code != 400 {
		t.Errorf("a bad project name: %d", a.code)
	}
	if a := e.do("POST", "/admin/v1/projects", sec, []byte(`{"name":"team-a","public":true}`), UserHeader, "ozan"); a.code != 201 {
		t.Fatalf("make a project: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/admin/v1/projects", sec, []byte(`{"name":"team-a"}`)); a.code != 409 {
		t.Errorf("the same project twice: %d", a.code)
	}
	ci := e.token("root", "repository:team-a/app:pull,push")
	digest, _ := e.pushImage("team-a/app", "1.0", ci, "arm64")
	a := e.do("GET", "/admin/v1/artifact?repo=team-a/app&ref=1.0", sec, nil)
	var d ArtifactDetail
	if err := json.Unmarshal(a.body, &d); err != nil || a.code != 200 {
		t.Fatalf("artifact: %d %s", a.code, a.body)
	}
	if d.Digest != digest || d.Config == nil || d.Config.Platform.Architecture != "arm64" || !strings.Contains(string(d.Manifest), "schemaVersion") ||
		d.Total <= d.Size || strings.Join(d.Tags, ",") != "1.0" {
		t.Errorf("artifact detail: %+v", d)
	}
	if a := e.do("PUT", "/admin/v1/tag?repo=team-a/app&tag=stable", sec, []byte(`{"digest":"`+digest+`"}`), UserHeader, "ozan"); a.code != 204 {
		t.Errorf("tag: %d %s", a.code, a.body)
	}
	a = e.do("GET", "/admin/v1/repository?name=team-a/app", sec, nil)
	if a.code != 200 || !strings.Contains(string(a.body), `"stable"`) {
		t.Errorf("repository: %d %s", a.code, a.body)
	}
	if a := e.do("DELETE", "/admin/v1/projects/team-a", sec, nil); a.code != 409 {
		t.Errorf("deleting a project with repositories: %d", a.code)
	}
	a = e.do("GET", "/admin/v1/events?project=team-a", sec, nil)
	var events []meta.Event
	json.Unmarshal(a.body, &events)
	if len(events) < 3 || events[0].Action != "tag" || events[0].User != "ozan" || events[len(events)-1].Action != "project-create" {
		t.Errorf("events: %+v", events)
	}
	if a := e.do("DELETE", "/admin/v1/repository?name=team-a/app", sec, nil); a.code != 204 {
		t.Errorf("delete the repository: %d", a.code)
	}
	if a := e.do("DELETE", "/admin/v1/projects/team-a", sec, nil); a.code != 204 {
		t.Errorf("delete the project: %d", a.code)
	}
}

func TestParse(t *testing.T) {
	for path, want := range map[string]target{
		"/v2/":                                {},
		"/v2/_catalog":                        {kind: "catalog"},
		"/v2/shop/web/tags/list":              {name: "shop/web", kind: "tags"},
		"/v2/shop/web/blobs/uploads/":         {name: "shop/web", kind: "uploads"},
		"/v2/shop/web/blobs/uploads":          {name: "shop/web", kind: "uploads"},
		"/v2/shop/web/blobs/uploads/abc":      {name: "shop/web", kind: "uploads", ref: "abc"},
		"/v2/shop/blobs/x/manifests/1":        {name: "shop/blobs/x", kind: "manifests", ref: "1"},
		"/v2/shop/web/blobs/sha256:abc":       {name: "shop/web", kind: "blobs", ref: "sha256:abc"},
		"/v2/shop/a/b/referrers/sha256:abc":   {name: "shop/a/b", kind: "referrers", ref: "sha256:abc"},
		"/v2/shop/manifests/x/tags/list":      {name: "shop/manifests/x", kind: "tags"},
		"/v2/shop/manifests/web/manifests/v1": {name: "shop/manifests/web", kind: "manifests", ref: "v1"},
	} {
		got, ok := parse(path)
		if !ok || got != want {
			t.Errorf("parse(%q) = %+v %v, want %+v", path, got, ok, want)
		}
	}
	if _, ok := parse("/v2/shop/web/other"); ok {
		t.Error("an unknown route parsed")
	}
}

func TestProjectRules(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push,delete")
	e.pushImage("shop/web", "v1", ci, "amd64")
	v := []string{"v*"}
	if _, err := e.db.UpdateProject("shop", meta.ProjectChange{Immutable: &v}, "root"); err != nil {
		t.Fatal(err)
	}
	// Another image under an immutable tag, and taking the tag off, are refused.
	cfg := e.pushBlob("shop/web", ci, []byte(`{"architecture":"arm64","os":"linux"}`))
	m := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		cfg + `","size":37},"layers":[]}`)
	if a := e.do("PUT", "/v2/shop/web/manifests/v1", ci, m, "Content-Type", manifest.OCIManifest); a.code != 409 || a.errCode() != "DENIED" ||
		!strings.Contains(string(a.body), "immutable") {
		t.Errorf("a push over an immutable tag: %d %s", a.code, a.body)
	}
	if a := e.do("DELETE", "/v2/shop/web/manifests/v1", ci, nil); a.code != 409 {
		t.Errorf("removing an immutable tag: %d %s", a.code, a.body)
	}
	if a := e.do("PUT", "/v2/shop/web/manifests/latest", ci, m, "Content-Type", manifest.OCIManifest); a.code != 201 {
		t.Errorf("another tag: %d %s", a.code, a.body)
	}
	// A quota the project is already at refuses what is new.
	used := int64(0)
	for _, p := range e.db.Projects() {
		if p.Name == "shop" {
			used = p.Size
		}
	}
	if _, err := e.db.UpdateProject("shop", meta.ProjectChange{Quota: &used}, "root"); err != nil {
		t.Fatal(err)
	}
	if a := e.do("POST", "/v2/shop/web/blobs/uploads/?digest="+url.QueryEscape(blobstore.Digest([]byte("more"))), ci, []byte("more")); a.code != 403 ||
		a.errCode() != "DENIED" || !strings.Contains(string(a.body), "quota") {
		t.Errorf("a blob over the quota: %d %s", a.code, a.body)
	}
	// What the project holds already is no more.
	if a := e.do("POST", "/v2/shop/web/blobs/uploads/?digest="+url.QueryEscape(cfg), ci, []byte(`{"architecture":"arm64","os":"linux"}`)); a.code != 201 {
		t.Errorf("a blob the project has: %d %s", a.code, a.body)
	}
	// The admin API checks the rules it is given.
	if a := e.do("PUT", "/admin/v1/projects/shop", "admin-secret", []byte(`{"immutable":["v[1"]}`)); a.code != 400 {
		t.Errorf("a pattern that cannot match: %d %s", a.code, a.body)
	}
	if a := e.do("PUT", "/admin/v1/projects/shop", "admin-secret", []byte(`{"quota":-1}`)); a.code != 400 {
		t.Errorf("a quota below zero: %d %s", a.code, a.body)
	}
}
