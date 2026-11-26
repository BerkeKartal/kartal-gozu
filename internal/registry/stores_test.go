package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore/s3test"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// newStoresEnv is an env whose registry may have blob stores of its own.
func newStoresEnv(t *testing.T) *env {
	e := newEnv(t)
	e.reg.cfg.SourcesKey = SourcesKey("stores-test-secret")
	e.reg.cfg.StagingDir = t.TempDir()
	return e
}

func (e *env) storeViews() map[string]StoreView {
	e.t.Helper()
	var views []StoreView
	a := e.do("GET", "/admin/v1/stores", "admin-secret", nil)
	if a.code != 200 || json.Unmarshal(a.body, &views) != nil {
		e.t.Fatalf("stores: %d %s", a.code, a.body)
	}
	out := map[string]StoreView{}
	for _, v := range views {
		out[v.Name] = v
	}
	return out
}

func walked(t *testing.T, st blobstore.Store) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if err := st.Walk(func(d string, _ int64, _ time.Time) error { out[d] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFileStores(t *testing.T) {
	e := newStoresEnv(t)
	dir := t.TempDir()
	for body, want := range map[string]int{
		`{"name":"default","kind":"file","path":"` + dir + `"}`: 400,
		`{"name":"archive","kind":"nfs","path":"` + dir + `"}`:  400,
		`{"name":"archive","kind":"file","path":"relative"}`:    400,
		`{"name":"Archive","kind":"file","path":"` + dir + `"}`: 400,
	} {
		if a := e.do("POST", "/admin/v1/stores", "admin-secret", []byte(body)); a.code != want {
			t.Errorf("%s: %d %s", body, a.code, a.body)
		}
	}
	if a := e.do("POST", "/admin/v1/stores", "admin-secret", []byte(`{"name":"archive","kind":"file","path":"`+dir+`","quota":1000000}`)); a.code != 201 {
		t.Fatalf("add a store: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/admin/v1/stores", "admin-secret", []byte(`{"name":"archive","kind":"file","path":"`+dir+`"}`)); a.code != 409 {
		t.Errorf("the same name again: %d", a.code)
	}
	if a := e.do("POST", "/admin/v1/projects", "admin-secret", []byte(`{"name":"arch","store":"nowhere"}`)); a.code != 400 {
		t.Errorf("a project on no store: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/admin/v1/projects", "admin-secret", []byte(`{"name":"arch","store":"archive"}`)); a.code != 201 {
		t.Fatalf("a project on the store: %d %s", a.code, a.body)
	}

	// Its pushes go to its store; the default one gets none of them.
	root := e.token("root", "repository:arch/web:pull,push", "repository:shop/web:pull,push", "repository:arch/other:pull,push")
	d, _ := e.pushImage("arch/web", "1.0", root, "amd64")
	archive, err := e.reg.storeNamed("archive")
	if err != nil {
		t.Fatal(err)
	}
	inArchive, inDefault := walked(t, archive), walked(t, e.reg.cfg.Store)
	if len(inArchive) != 3 || !inArchive[d] || len(inDefault) != 0 {
		t.Fatalf("archive %v, default %v", inArchive, inDefault)
	}
	if a := e.do("GET", "/v2/arch/web/manifests/1.0", root, nil); a.code != 200 {
		t.Errorf("pull: %d", a.code)
	}
	m, _ := e.db.Artifact("arch/web", d)
	layer := m.Layers[0].Digest
	if a := e.do("GET", "/v2/arch/web/blobs/"+layer, root, nil); a.code != 200 || !strings.Contains(string(a.body), "layer of arch/web") {
		t.Errorf("a layer: %d %q", a.code, a.body)
	}
	// A blob is mounted only from what the project's store has.
	only := e.pushBlob("shop/web", root, []byte("only in the default store"))
	if a := e.do("POST", "/v2/arch/other/blobs/uploads/?mount="+only+"&from=shop/web", root, nil); a.code != 202 {
		t.Errorf("a mount across stores: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/v2/arch/other/blobs/uploads/?mount="+layer+"&from=arch/web", root, nil); a.code != 201 {
		t.Errorf("a mount in the store: %d %s", a.code, a.body)
	}
	views := e.storeViews()
	if v := views["archive"]; v.Size == 0 || v.Blobs != 3 || len(v.Projects) != 1 || v.Projects[0] != "arch" || v.Quota != 1000000 || v.Default {
		t.Errorf("the archive's view: %+v", v)
	}
	if v := views["default"]; !v.Default || v.Path == "" || v.Blobs != 1 {
		t.Errorf("the default's view: %+v", v)
	}

	// A store a project uses stays; a project with repositories keeps its
	// store, an empty one moves.
	if a := e.do("DELETE", "/admin/v1/stores/archive", "admin-secret", nil); a.code != 409 {
		t.Errorf("deleting a store in use: %d", a.code)
	}
	if a := e.do("PUT", "/admin/v1/projects/arch", "admin-secret", []byte(`{"store":"default"}`)); a.code != 409 {
		t.Errorf("moving a project with repositories: %d %s", a.code, a.body)
	}
	if a := e.do("PUT", "/admin/v1/projects/infra", "admin-secret", []byte(`{"store":"archive"}`)); a.code != 200 {
		t.Errorf("moving an empty project: %d %s", a.code, a.body)
	}
	if p, _ := e.db.Project("infra"); p.StoreName() != "archive" {
		t.Errorf("infra: %+v", p)
	}

	// The same blob in both stores, each collected by its own projects.
	e.pushImage("shop/web", "1.0", root, "amd64")
	if err := e.db.DeleteArtifact("arch/web", d, "root"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rep, err := e.reg.GC(ctx, 0, false, "root")
	if err != nil || len(rep.Stores) != 2 {
		t.Fatalf("gc: %+v %v", rep, err)
	}
	// The layer arch/other mounted is used by none of its artifacts:
	// without a grace period, garbage as the rest.
	if got := walked(t, archive); len(got) != 0 {
		t.Errorf("the archive after collecting: %v", got)
	}
	if got := walked(t, e.reg.cfg.Store); len(got) < 3 {
		t.Errorf("the default store after collecting: %v", got)
	}
	ver, err := e.reg.Verify(ctx, "root")
	if err != nil || !ver.OK() || strings.Join(ver.Stores, ",") != "default,archive" {
		t.Errorf("verify: %+v %v", ver, err)
	}
}

func TestS3StoreInTheRegistry(t *testing.T) {
	e := newStoresEnv(t)
	fake := s3test.New(t)
	body := func(extra string) []byte {
		return []byte(`{"name":"minio","kind":"s3","endpoint":"` + fake.URL + `","bucket":"kartal","prefix":"reg","accessKey":"` + fake.Access + `","pathStyle":true` + extra + `}`)
	}
	if a := e.do("POST", "/admin/v1/stores", "admin-secret", body(``)); a.code != 400 || !strings.Contains(string(a.body), "secret key") {
		t.Errorf("without a secret: %d %s", a.code, a.body)
	}
	wrong := []byte(`{"name":"minio","kind":"s3","endpoint":"` + fake.URL + `","bucket":"kartal","accessKey":"nope","secretKey":"x","pathStyle":true}`)
	if a := e.do("POST", "/admin/v1/stores", "admin-secret", wrong); a.code != 400 || !strings.Contains(string(a.body), "does not work") {
		t.Errorf("keys that do not work: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/admin/v1/stores/test", "admin-secret", body(`,"secretKey":"`+fake.Secret+`"`)); !strings.Contains(string(a.body), `"ok":true`) {
		t.Errorf("test: %s", a.body)
	}
	if a := e.do("POST", "/admin/v1/stores", "admin-secret", body(`,"secretKey":"`+fake.Secret+`"`)); a.code != 201 || strings.Contains(string(a.body), fake.Secret) {
		t.Fatalf("add: %d %s", a.code, a.body)
	}
	bs, _ := e.db.BlobStoreNamed("minio")
	if bs.Secret == "" || bs.Secret == fake.Secret {
		t.Errorf("the secret is not sealed: %q", bs.Secret)
	}
	// Changed without its secret, it keeps it.
	if a := e.do("PUT", "/admin/v1/stores/minio", "admin-secret", body(`,"quota":5000`)); a.code != 200 {
		t.Fatalf("change: %d %s", a.code, a.body)
	}
	if after, _ := e.db.BlobStoreNamed("minio"); after.Secret != bs.Secret || after.Quota != 5000 {
		t.Errorf("after the change: %+v", after)
	}
	if v := e.storeViews()["minio"]; !v.HasSecret || v.Secret != "" || v.Bucket != "kartal" {
		t.Errorf("view: %+v", v)
	}

	// A project there pushes into the bucket, and pulls from it.
	if a := e.do("POST", "/admin/v1/projects", "admin-secret", []byte(`{"name":"cloud","store":"minio"}`)); a.code != 201 {
		t.Fatalf("project: %d %s", a.code, a.body)
	}
	root := e.token("root", "repository:cloud/web:pull,push")
	d, _ := e.pushImage("cloud/web", "1.0", root, "amd64")
	keys := strings.Join(fake.Keys(), " ")
	hexPart := strings.TrimPrefix(d, "sha256:")
	if !strings.Contains(keys, "reg/blobs/sha256/"+hexPart[:2]+"/"+hexPart) || strings.Count(keys, "reg/blobs/") != 3 {
		t.Fatalf("the bucket: %s", keys)
	}
	m, _ := e.db.Artifact("cloud/web", d)
	if a := e.do("GET", "/v2/cloud/web/blobs/"+m.Layers[0].Digest, root, nil); a.code != 200 || !bytes.Contains(a.body, []byte("layer of cloud/web")) {
		t.Errorf("pull a layer: %d %q", a.code, a.body)
	}
	if len(walked(t, e.reg.cfg.Store)) != 0 {
		t.Error("the default store got blobs of the bucket's project")
	}

	// Looked at, it is well; a bucket gone is a problem.
	ctx := context.Background()
	e.reg.checkStores(ctx)
	if v := e.storeViews()["minio"]; v.Problem != "" || v.Checked == nil {
		t.Errorf("well: %+v", v)
	}
	fake.Do(func(f *s3test.Fake) { f.Bucket = "gone" })
	e.reg.checkStores(ctx)
	if v := e.storeViews()["minio"]; !strings.Contains(v.Problem, "NoSuchBucket") {
		t.Errorf("gone: %+v", v)
	}
	fake.Do(func(f *s3test.Fake) { f.Bucket = "kartal" })

	// A store that cannot be opened (its secret sealed with another key)
	// leaves its projects unavailable, not wrong.
	e.reg.cfg.SourcesKey = SourcesKey("another key")
	e.reg.dropStore("minio")
	if a := e.do("GET", "/v2/cloud/web/manifests/1.0", root, nil); a.code != 503 || a.errCode() != "UNAVAILABLE" {
		t.Errorf("a store that cannot be opened: %d %s", a.code, a.body)
	}
	rep, err := e.reg.GC(ctx, 0, true, "root")
	if err == nil || !strings.Contains(err.Error(), "minio") || len(rep.Stores) != 2 || rep.Stores[1].Error == "" {
		t.Errorf("gc with a store that cannot be opened: %+v %v", rep, err)
	}
}

func TestStoresAreKept(t *testing.T) {
	dir := t.TempDir()
	db, err := meta.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutBlobStore(meta.BlobStore{Name: "archive", Kind: "file", Path: "/data/archive"}, "root"); err != nil {
		t.Fatal(err)
	}
	if err := db.PutBlobStore(meta.BlobStore{Name: meta.DefaultStore, Kind: "file"}, "root"); err == nil {
		t.Error("a store named default was kept")
	}
	if err := db.CreateProject(meta.Project{Name: "arch", Store: "archive"}, "root"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = meta.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if bs, ok := db.BlobStoreNamed("archive"); !ok || bs.Path != "/data/archive" {
		t.Errorf("after reopening: %+v %v", bs, ok)
	}
	if p, _ := db.Project("arch"); p.StoreName() != "archive" {
		t.Errorf("the project: %+v", p)
	}
	if err := db.DeleteBlobStore("archive", "root"); err == nil {
		t.Error("a store in use was deleted")
	}
}
