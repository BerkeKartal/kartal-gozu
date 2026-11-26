package registry

import (
	"context"
	"net/url"
	"sync"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// hooked is a blob store that runs a hook once, right after the call it
// waits for: a move that switches and ends just then.
type hooked struct {
	blobstore.Store
	mu   sync.Mutex
	on   string
	hook func()
}

func (h *hooked) arm(on string, hook func()) {
	h.mu.Lock()
	h.on, h.hook = on, hook
	h.mu.Unlock()
}

func (h *hooked) fire(op string) {
	h.mu.Lock()
	f := h.hook
	if h.on != op {
		f = nil
	} else {
		h.hook = nil
	}
	h.mu.Unlock()
	if f != nil {
		f()
	}
}

func (h *hooked) Put(digest string, b []byte) error {
	err := h.Store.Put(digest, b)
	h.fire("put")
	return err
}

func (h *hooked) Stat(digest string) (int64, error) {
	n, err := h.Store.Stat(digest)
	h.fire("stat")
	return n, err
}

func (h *hooked) Finish(id, digest string) (int64, error) {
	n, err := h.Store.Finish(id, digest)
	h.fire("finish")
	return n, err
}

// A move whose passes are done before a blob or manifest written into the
// old store is recorded: the blob is the project's in the new store all
// the same, once the move ended.
func TestWritesAcrossAMovesEnd(t *testing.T) {
	e, archive := withArchive(t)
	h := &hooked{Store: e.reg.cfg.Store}
	e.reg.cfg.Store = h
	// The move switches, finds nothing more to copy, and ends.
	move := func() {
		if _, err := e.db.MoveProject("shop", "archive", "root"); err != nil {
			t.Error(err)
		}
		if err := e.db.EndMove("shop", "root"); err != nil {
			t.Error(err)
		}
	}
	back := func() {
		t.Helper()
		if _, err := e.db.MoveProject("shop", "default", "root"); err != nil {
			t.Fatal(err)
		}
		if err := e.db.EndMove("shop", "root"); err != nil {
			t.Fatal(err)
		}
	}
	ci := e.token("ci", "repository:shop/web:pull,push", "repository:shop/api:pull", "repository:shop/mounted:pull,push")

	// A manifest.
	h.arm("put", move)
	d, _ := e.pushImage("shop/web", "1.0", ci, "amd64")
	if !walked(t, archive)[d] {
		t.Error("a manifest: the new store lacks it")
	}
	if a := e.do("GET", "/v2/shop/web/manifests/1.0", ci, nil); a.code != 200 {
		t.Errorf("a manifest after the move: %d %s", a.code, a.body)
	}
	back()

	// A blob pushed whole: the move ends after its store said where it is.
	content := []byte("a layer pushed whole as the move ended")
	cd := blobstore.Digest(content)
	h.arm("stat", move)
	if a := e.do("POST", "/v2/shop/web/blobs/uploads/?digest="+url.QueryEscape(cd), ci, content); a.code != 201 {
		t.Fatalf("a blob whole: %d %s", a.code, a.body)
	}
	if !walked(t, archive)[cd] {
		t.Error("a blob whole: the new store lacks it")
	}
	back()

	// A blob mounted from another repository of the project.
	other := []byte("a layer mounted as the move ended")
	od := blobstore.Digest(other)
	if a := e.do("POST", "/v2/shop/api/blobs/uploads/?digest="+url.QueryEscape(od), e.token("ci", "repository:shop/api:pull,push"), other); a.code != 201 {
		t.Fatalf("a blob of shop/api: %d %s", a.code, a.body)
	}
	h.arm("stat", move)
	if a := e.do("POST", "/v2/shop/mounted/blobs/uploads/?mount="+url.QueryEscape(od)+"&from=shop/api", ci, nil); a.code != 201 {
		t.Fatalf("a mount: %d %s", a.code, a.body)
	}
	if !walked(t, archive)[od] {
		t.Error("a mount: the new store lacks it")
	}
	if a := e.do("GET", "/v2/shop/mounted/blobs/"+od, ci, nil); a.code != 200 {
		t.Errorf("a mounted blob after the move: %d", a.code)
	}
}

// The same of a blob a replication pulls.
func TestReplicationAcrossAMovesEnd(t *testing.T) {
	up := newUpstream(t)
	e, archive := withArchive(t)
	h := &hooked{Store: e.reg.cfg.Store}
	e.reg.cfg.Store = h
	src := e.source(t, up.srv.URL)
	r := e.rule(t, src, meta.ReplicationRule{Name: "infra", Repositories: "infra/proxy", Tags: "1.0", Project: "shop"})
	h.arm("finish", func() {
		if _, err := e.db.MoveProject("shop", "archive", "root"); err != nil {
			t.Error(err)
		}
		if err := e.db.EndMove("shop", "root"); err != nil {
			t.Error(err)
		}
	})
	if _, err := e.reg.Replicate(context.Background(), r.ID, false, "root", nil); err != nil {
		t.Fatal(err)
	}
	have := walked(t, archive)
	for d := range e.db.ProjectBlobs("shop") {
		if !have[d] {
			t.Errorf("the new store lacks %s", d)
		}
	}
}
