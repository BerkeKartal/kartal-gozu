package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
)

// blobFile is where the store keeps a blob.
func (e *env) blobFile(digest string) string {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(e.dir, "blobs", "sha256", hexPart[:2], hexPart)
}

// age makes a blob as old as if it was written long ago.
func (e *env) age(digest string, ago time.Duration) {
	e.t.Helper()
	at := time.Now().Add(-ago)
	if err := os.Chtimes(e.blobFile(digest), at, at); err != nil {
		e.t.Fatal(err)
	}
}

func TestGCCollectsWhatNothingUses(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push,delete", "repository:shop/api:pull,push")
	// Both images have the same config; their layers differ.
	web, webManifest := e.pushImage("shop/web", "1.0", ci, "amd64")
	_, apiManifest := e.pushImage("shop/api", "1.0", ci, "amd64")
	config := strings.Split(strings.Split(string(apiManifest), `"config":{`)[1], `"digest":"`)[1][:71]
	webLayer := strings.Split(strings.Split(string(webManifest), `"layers":[`)[1], `"digest":"`)[1][:71]
	if a := e.do("DELETE", "/v2/shop/web/manifests/"+web, ci, nil); a.code != 202 {
		t.Fatalf("delete: %d %s", a.code, a.body)
	}
	// Within the grace period nothing goes: the layer is still linked, and
	// the manifest, which nothing has any more, is spared.
	rep, err := e.reg.GC(context.Background(), DefaultGrace, false, "root")
	if err != nil || rep.Unlinked != 0 || rep.Blobs != 0 || rep.Spared != 1 {
		t.Errorf("within the grace period: %+v %v", rep, err)
	}
	// A dry run tells what would go, and changes nothing.
	rep, err = e.reg.GC(context.Background(), 0, true, "root")
	if err != nil || rep.Unlinked != 2 || rep.Blobs != 2 || rep.Freed == 0 {
		t.Errorf("a dry run: %+v %v", rep, err)
	}
	if _, ok := e.db.Blob("shop/web", webLayer); !ok {
		t.Error("the dry run unlinked a blob")
	}
	rep, err = e.reg.GC(context.Background(), 0, false, "root")
	if err != nil || rep.Unlinked != 2 || rep.Blobs != 2 {
		t.Errorf("collecting: %+v %v", rep, err)
	}
	// The deleted image's own layer and manifest are gone; the config the
	// other image has stays, and it still pulls.
	for _, dg := range []string{webLayer, web} {
		if _, err := os.Stat(e.blobFile(dg)); !os.IsNotExist(err) {
			t.Errorf("%s is still there: %v", dg, err)
		}
	}
	if a := e.do("GET", "/v2/shop/api/blobs/"+config, ci, nil); a.code != 200 {
		t.Errorf("the other image's config: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/api/manifests/1.0", ci, nil); a.code != 200 {
		t.Errorf("the other image: %d", a.code)
	}
	if ev := e.db.Events(nil, 1); ev[0].Action != "gc" || !strings.Contains(ev[0].Detail, "2 links, 2 blobs") {
		t.Errorf("the log: %+v", ev)
	}
	// Nothing more to collect.
	if rep, _ := e.reg.GC(context.Background(), 0, false, "root"); rep.Unlinked != 0 || rep.Blobs != 0 {
		t.Errorf("again: %+v", rep)
	}
}

func TestGCSparesAPushUnderWay(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	// A layer uploaded long ago, for a push that never sent its manifest;
	// its link is old too.
	now := time.Now()
	e.db.SetClock(func() time.Time { return now.Add(-3 * time.Hour) })
	layer := e.pushBlob("shop/web", ci, []byte("a layer pushed again"))
	e.db.SetClock(time.Now)
	e.age(layer, 3*time.Hour)
	// The push now: docker asks whether the layer is there and, finding it,
	// sends the manifest that uses it a moment later.
	if a := e.do("HEAD", "/v2/shop/web/blobs/"+layer, ci, nil); a.code != 200 {
		t.Fatalf("head: %d", a.code)
	}
	rep, err := e.reg.GC(context.Background(), DefaultGrace, false, "root")
	if err != nil || rep.Unlinked != 0 || rep.Blobs != 0 {
		t.Errorf("a layer a push uses again: %+v %v", rep, err)
	}
	// One only pulled stays old, and goes.
	puller := e.token("dev", "repository:shop/web:pull")
	e.db.SetClock(func() time.Time { return now.Add(-3 * time.Hour) })
	other := e.pushBlob("shop/web", ci, []byte("a layer nobody pushes"))
	e.db.SetClock(time.Now)
	e.age(other, 3*time.Hour)
	if a := e.do("HEAD", "/v2/shop/web/blobs/"+other, puller, nil); a.code != 200 {
		t.Fatalf("head: %d", a.code)
	}
	rep, err = e.reg.GC(context.Background(), DefaultGrace, false, "root")
	if err != nil || rep.Unlinked != 1 || rep.Blobs != 1 {
		t.Errorf("a layer nobody uses: %+v %v", rep, err)
	}
}

func TestGCRemovesUploadsLeftBehind(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	a := e.do("POST", "/v2/shop/web/blobs/uploads/", ci, nil)
	loc := a.h.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(filepath.Join(e.dir, "uploads", id), old, old); err != nil {
		t.Fatal(err)
	}
	fresh := e.do("POST", "/v2/shop/web/blobs/uploads/", ci, nil)
	rep, err := e.reg.GC(context.Background(), DefaultGrace, false, "root")
	if err != nil || rep.Uploads != 1 {
		t.Errorf("uploads: %+v %v", rep, err)
	}
	if a := e.do("GET", loc, ci, nil); a.code != 404 {
		t.Errorf("the upload left behind: %d", a.code)
	}
	if a := e.do("GET", fresh.h.Get("Location"), ci, nil); a.code != 204 {
		t.Errorf("the upload under way: %d", a.code)
	}
}

func TestGCKeepsABlobStoredAgain(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	content := []byte("left behind, then pushed again")
	// In the store and in no repository: an upload finished, not linked.
	d := blobstore.Digest(content)
	if err := e.reg.cfg.Store.Put(d, content); err != nil {
		t.Fatal(err)
	}
	e.age(d, 3*time.Hour)
	// Pushed again: the store has it, and makes it new.
	e.pushBlob("shop/web", ci, content)
	e.db.UnlinkBlob("shop/web", d)
	rep, err := e.reg.GC(context.Background(), DefaultGrace, false, "root")
	if err != nil || rep.Blobs != 0 || rep.Spared != 1 {
		t.Errorf("a blob stored again: %+v %v", rep, err)
	}
}

func TestVerify(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	_, m := e.pushImage("shop/web", "1.0", ci, "amd64")
	rep, err := e.reg.Verify(context.Background(), "root")
	if err != nil || !rep.OK() || rep.Checked != 3 {
		t.Errorf("a sound store: %+v %v", rep, err)
	}
	layer := strings.Split(strings.Split(string(m), `"layers":[`)[1], `"digest":"`)[1][:71]
	config := strings.Split(strings.Split(string(m), `"config":{`)[1], `"digest":"`)[1][:71]
	if err := os.WriteFile(e.blobFile(layer), []byte("rotten"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(e.blobFile(config))
	rep, err = e.reg.Verify(context.Background(), "root")
	if err != nil || rep.OK() || len(rep.Corrupt) != 1 || rep.Corrupt[0] != layer || len(rep.Missing) != 1 || rep.Missing[0] != "shop/web@"+config {
		t.Errorf("a damaged store: %+v %v", rep, err)
	}
	if ev := e.db.Events(nil, 1); ev[0].Action != "verify" || !strings.Contains(ev[0].Detail, "1 corrupt, 1 missing") {
		t.Errorf("the log: %+v", ev)
	}
}

func TestBlobsArtifactsUseStayLinked(t *testing.T) {
	e := newEnv(t)
	ci := e.token("ci", "repository:shop/web:pull,push,delete")
	_, m := e.pushImage("shop/web", "1.0", ci, "amd64")
	layer := strings.Split(strings.Split(string(m), `"layers":[`)[1], `"digest":"`)[1][:71]
	if a := e.do("DELETE", "/v2/shop/web/blobs/"+layer, ci, nil); a.code != 409 || a.errCode() != "DENIED" {
		t.Errorf("unlinking a layer an image uses: %d %s", a.code, a.body)
	}
	other := e.pushBlob("shop/web", ci, []byte("not used"))
	if a := e.do("DELETE", "/v2/shop/web/blobs/"+other, ci, nil); a.code != 202 {
		t.Errorf("unlinking a blob nothing uses: %d %s", a.code, a.body)
	}
}
