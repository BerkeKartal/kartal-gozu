package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
)

// withArchive is a stores env with a second file store, archive.
func withArchive(t *testing.T) (*env, blobstore.Store) {
	e := newStoresEnv(t)
	if a := e.do("POST", "/admin/v1/stores", "admin-secret", []byte(`{"name":"archive","kind":"file","path":"`+t.TempDir()+`"}`)); a.code != 201 {
		t.Fatalf("add a store: %d %s", a.code, a.body)
	}
	st, err := e.reg.storeNamed("archive")
	if err != nil {
		t.Fatal(err)
	}
	return e, st
}

func TestMoveAProject(t *testing.T) {
	e, archive := withArchive(t)
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/api:pull,push")
	d1, _ := e.pushImage("shop/web", "1.0", ci, "amd64")
	e.pushImage("shop/api", "2.0", ci, "arm64")
	blobs := len(e.db.ProjectBlobs("shop"))
	if _, err := e.reg.StartMove("shop", "default", false, "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a move to where it is: %v", err)
	}
	if _, err := e.reg.StartMove("shop", "nowhere", false, "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a move to no store: %v", err)
	}
	// A dry run copies nothing.
	j, err := e.reg.StartMove("shop", "archive", true, "root")
	if err != nil {
		t.Fatal(err)
	}
	j = e.wait(j.ID)
	var rep MoveReport
	json.Unmarshal(j.Report, &rep)
	if j.Status != "done" || rep.Copied != blobs || rep.Blobs != blobs || len(walked(t, archive)) != 0 {
		t.Fatalf("dry run: %+v %+v", j, rep)
	}
	if p, _ := e.db.Project("shop"); p.StoreName() != "default" {
		t.Errorf("a dry run moved it: %+v", p)
	}
	// Through the admin API, as kartal-server starts it.
	a := e.do("POST", "/admin/v1/jobs", "admin-secret", []byte(`{"kind":"move","project":"shop","store":"archive"}`))
	if a.code != 202 || json.Unmarshal(a.body, &j) != nil {
		t.Fatalf("move: %d %s", a.code, a.body)
	}
	j = e.wait(j.ID)
	json.Unmarshal(j.Report, &rep)
	if j.Status != "done" || rep.Copied != blobs || rep.From != "default" || rep.To != "archive" || j.Store != "archive" {
		t.Fatalf("move: %+v %+v", j, rep)
	}
	p, _ := e.db.Project("shop")
	if p.StoreName() != "archive" || p.MovedFrom != "" {
		t.Fatalf("after the move: %+v", p)
	}
	if got := walked(t, archive); len(got) != blobs || !got[d1] {
		t.Errorf("the archive has %d of %d", len(got), blobs)
	}
	// What is left in the old store is garbage; the project pulls on.
	ctx := context.Background()
	if _, err := e.reg.GC(ctx, 0, false, "root"); err != nil {
		t.Fatal(err)
	}
	if got := walked(t, e.reg.cfg.Store); len(got) != 0 {
		t.Errorf("the old store after collecting: %d", len(got))
	}
	m, _ := e.db.Artifact("shop/web", d1)
	if a := e.do("GET", "/v2/shop/web/blobs/"+m.Layers[0].Digest, ci, nil); a.code != 200 {
		t.Errorf("a layer after the move: %d", a.code)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/1.0", ci, nil); a.code != 200 {
		t.Errorf("a manifest after the move: %d", a.code)
	}
}

// Switched but not copied, as a move cut short: blobs are read where they
// were, which keeps them, and the move run again goes on.
func TestAMoveCutShort(t *testing.T) {
	e, archive := withArchive(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	d, _ := e.pushImage("shop/web", "1.0", ci, "amd64")
	if _, err := e.db.MoveProject("shop", "archive", "root"); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.db.Project("shop"); p.StoreName() != "archive" || p.MovedFrom != "default" {
		t.Fatalf("switched: %+v", p)
	}
	if a := e.do("GET", "/v2/shop/web/manifests/1.0", ci, nil); a.code != 200 {
		t.Errorf("a manifest from where it was: %d", a.code)
	}
	ctx := context.Background()
	if _, err := e.reg.GC(ctx, 0, false, "root"); err != nil {
		t.Fatal(err)
	}
	if got := walked(t, e.reg.cfg.Store); len(got) != 3 {
		t.Fatalf("the old store's collection took the moving project's blobs: %d", len(got))
	}
	// Another store may not be asked for before this move ends.
	if _, err := e.reg.StartMove("shop", "default", false, "root"); !errors.Is(err, ErrJob) {
		t.Errorf("another move meanwhile: %v", err)
	}
	if a := e.do("PUT", "/admin/v1/projects/shop", "admin-secret", []byte(`{"store":"default"}`)); a.code != 409 {
		t.Errorf("a change of store meanwhile: %d", a.code)
	}
	if a := e.do("DELETE", "/admin/v1/stores/archive", "admin-secret", nil); a.code != 409 {
		t.Errorf("deleting the store it goes to: %d", a.code)
	}
	j, err := e.reg.StartMove("shop", "", false, "root")
	if err != nil {
		t.Fatal(err)
	}
	if j = e.wait(j.ID); j.Status != "done" {
		t.Fatalf("going on: %+v", j)
	}
	if p, _ := e.db.Project("shop"); p.MovedFrom != "" {
		t.Errorf("the move did not end: %+v", p)
	}
	if got := walked(t, archive); len(got) != 3 || !got[d] {
		t.Errorf("the archive: %v", got)
	}
}

// An upload started before the switch and finished after it is copied into
// the new store as it finishes.
func TestAnUploadAcrossAMove(t *testing.T) {
	e, archive := withArchive(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	content := []byte("a layer pushed while the project moved")
	d := blobstore.Digest(content)
	a := e.do("POST", "/v2/shop/web/blobs/uploads/", ci, nil)
	if a.code != 202 {
		t.Fatalf("start: %d", a.code)
	}
	loc := a.h.Get("Location")
	if a := e.do("PATCH", loc, ci, content[:10]); a.code != 202 {
		t.Fatalf("chunk: %d", a.code)
	}
	if _, err := e.db.MoveProject("shop", "archive", "root"); err != nil {
		t.Fatal(err)
	}
	if a := e.do("PUT", loc+"?digest="+url.QueryEscape(d), ci, content[10:]); a.code != 201 {
		t.Fatalf("finish: %d %s", a.code, a.body)
	}
	if !walked(t, archive)[d] {
		t.Error("the new store lacks the blob")
	}
	if err := e.db.EndMove("shop", "root"); err != nil {
		t.Fatal(err)
	}
	if a := e.do("GET", "/v2/shop/web/blobs/"+d, ci, nil); a.code != 200 || !strings.Contains(string(a.body), "while the project moved") {
		t.Errorf("the blob after the move: %d", a.code)
	}
}

// A move that takes longer than collecting garbage waits: what it copied
// is the project's in the new store from the start, so the new store's
// collection keeps it.
func TestAMoveOutlastsACollection(t *testing.T) {
	e, archive := withArchive(t)
	ci := e.token("ci", "repository:shop/web:pull,push")
	e.pushImage("shop/web", "1.0", ci, "amd64")
	from, _ := e.reg.storeNamed("default")
	ctx := context.Background()
	collected := false
	// The collection runs as the move copies its first blob.
	_, _, err := e.reg.copyBlob(ctx, from, &collectOnce{Store: archive, before: func() {
		if !collected {
			collected = true
			if _, err := e.reg.GC(ctx, 0, false, "root"); err != nil {
				t.Error(err)
			}
		}
	}}, firstBlob(e, "shop"), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Above, no switch: the copy is garbage, and gone. The move itself
	// switches first.
	if len(walked(t, archive)) != 0 {
		t.Fatal("a copy of a project still elsewhere survived the collection")
	}
	j, err := e.reg.StartMove("shop", "archive", false, "root")
	if err != nil {
		t.Fatal(err)
	}
	e.wait(j.ID)
	if _, err := e.reg.GC(ctx, 0, false, "root"); err != nil {
		t.Fatal(err)
	}
	if got := walked(t, archive); len(got) != 3 {
		t.Errorf("after the move and a collection: %d of 3", len(got))
	}
}

func firstBlob(e *env, project string) string {
	for d := range e.db.ProjectBlobs(project) {
		return d
	}
	return ""
}

// collectOnce is a store that runs a function before it finishes an upload.
type collectOnce struct {
	blobstore.Store
	before func()
}

func (c *collectOnce) Finish(id, digest string) (int64, error) {
	n, err := c.Store.Finish(id, digest)
	c.before()
	return n, err
}
