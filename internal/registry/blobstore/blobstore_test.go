package blobstore

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPutOpenDelete(t *testing.T) {
	f, err := NewFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schemaVersion":2}`)
	d := Digest(body)
	if err := f.Put(Digest([]byte("other")), body); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("put with the wrong digest: %v", err)
	}
	if err := f.Put(d, body); err != nil {
		t.Fatal(err)
	}
	// Putting the same content again is no error.
	if err := f.Put(d, body); err != nil {
		t.Fatal(err)
	}
	if n, err := f.Stat(d); err != nil || n != int64(len(body)) {
		t.Errorf("stat: %d %v", n, err)
	}
	r, n, err := f.Open(d)
	if err != nil || n != int64(len(body)) {
		t.Fatalf("open: %d %v", n, err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, body) {
		t.Errorf("read %q", got)
	}
	var seen []string
	f.Walk(func(digest string, size int64, _ time.Time) error {
		seen = append(seen, digest)
		return nil
	})
	if len(seen) != 1 || seen[0] != d {
		t.Errorf("walk: %v", seen)
	}
	if err := f.Delete(d); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(d); !errors.Is(err, ErrNotFound) {
		t.Errorf("stat after delete: %v", err)
	}
	if err := f.Delete(d); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
	for _, bad := range []string{"", "sha256:xyz", "sha512:" + strings.Repeat("a", 128), "../../etc/passwd"} {
		if _, err := f.Stat(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("stat %q: %v", bad, err)
		}
		if _, _, err := f.Open(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("open %q: %v", bad, err)
		}
	}
}

func TestChunkedUpload(t *testing.T) {
	root := t.TempDir()
	f, err := NewFile(root)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(strings.Repeat("kartal", 1000))
	d := Digest(content)
	id, err := f.StartUpload()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.Append(id, 0, bytes.NewReader(content[:100])); err != nil || n != 100 {
		t.Fatalf("first chunk: %d %v", n, err)
	}
	// A chunk that does not start where the upload ends is refused, and the
	// upload's size is told.
	if n, err := f.Append(id, 50, bytes.NewReader(content[50:200])); !errors.Is(err, ErrOffset) || n != 100 {
		t.Errorf("chunk at the wrong offset: %d %v", n, err)
	}
	if n, err := f.Append(id, 100, bytes.NewReader(content[100:3000])); err != nil || n != 3000 {
		t.Fatalf("second chunk: %d %v", n, err)
	}
	// The wrong digest is refused, and the upload can go on.
	if _, err := f.Finish(id, d); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("finish too early: %v", err)
	}
	// A restart loses the digest in memory; it is read again from the disk.
	f2, err := NewFile(root)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f2.UploadSize(id); err != nil || n != 3000 {
		t.Errorf("size after a restart: %d %v", n, err)
	}
	if n, err := f2.Append(id, 3000, bytes.NewReader(content[3000:])); err != nil || n != int64(len(content)) {
		t.Fatalf("last chunk: %d %v", n, err)
	}
	if n, err := f2.Finish(id, d); err != nil || n != int64(len(content)) {
		t.Fatalf("finish: %d %v", n, err)
	}
	r, _, err := f2.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, content) {
		t.Error("the blob is not what was uploaded")
	}
	if _, err := f2.UploadSize(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("the upload is still there: %v", err)
	}
}

func TestFinishingWhatIsAlreadyThere(t *testing.T) {
	f, _ := NewFile(t.TempDir())
	content := []byte("layer")
	d := Digest(content)
	if err := f.Put(d, content); err != nil {
		t.Fatal(err)
	}
	id, _ := f.StartUpload()
	f.Append(id, 0, bytes.NewReader(content))
	if _, err := f.Finish(id, d); err != nil {
		t.Fatal(err)
	}
	var uploads int
	f.WalkUploads(func(string, int64, time.Time) error { uploads++; return nil })
	if uploads != 0 {
		t.Errorf("%d uploads left", uploads)
	}
}

func TestUploadsListedAndCancelled(t *testing.T) {
	f, _ := NewFile(t.TempDir())
	a, _ := f.StartUpload()
	b, _ := f.StartUpload()
	f.Append(b, 0, strings.NewReader("abc"))
	got := map[string]int64{}
	f.WalkUploads(func(id string, size int64, _ time.Time) error { got[id] = size; return nil })
	if len(got) != 2 || got[a] != 0 || got[b] != 3 {
		t.Errorf("uploads: %v", got)
	}
	if err := f.Cancel(a); err != nil {
		t.Fatal(err)
	}
	if err := f.Cancel(a); !errors.Is(err, ErrNotFound) {
		t.Errorf("cancelling twice: %v", err)
	}
	for _, bad := range []string{"", "../x", strings.Repeat("g", 32)} {
		if _, err := f.Append(bad, 0, strings.NewReader("x")); !errors.Is(err, ErrNotFound) {
			t.Errorf("append to %q: %v", bad, err)
		}
	}
}
