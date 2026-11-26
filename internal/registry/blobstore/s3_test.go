package blobstore

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore/s3test"
)

func TestS3Layout(t *testing.T) {
	fake := newFakeS3(t)
	s := fakeStore(t, fake, t.TempDir())
	body := []byte("a manifest")
	d := Digest(body)
	if err := s.Put(d, body); err != nil {
		t.Fatal(err)
	}
	hexPart := strings.TrimPrefix(d, "sha256:")
	key := "registry/blobs/sha256/" + hexPart[:2] + "/" + hexPart
	if o, ok := fake.Objects[key]; !ok || !bytes.Equal(o.Data, body) {
		t.Fatalf("objects: %v", fake.Objects)
	}
	// One PUT, signed with the blob's own digest, which S3 checks.
	var puts []string
	for _, r := range fake.Requests() {
		if strings.HasPrefix(r, "PUT ") {
			puts = append(puts, r)
		}
	}
	if len(puts) != 1 || !strings.Contains(puts[0], "/kartal/"+key) {
		t.Errorf("puts: %v", puts)
	}
	// Stored again, it is not sent again.
	if err := s.Put(d, body); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range fake.Requests() {
		if strings.HasPrefix(r, "PUT ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d puts", n)
	}
}

func TestS3MultipartAndWalk(t *testing.T) {
	fake := newFakeS3(t)
	fake.Page = 2
	s := fakeStore(t, fake, t.TempDir())
	want := map[string]int64{}
	for i := 0; i < 5; i++ {
		content := []byte(strings.Repeat(fmt.Sprintf("layer %d ", i), 300+i*50))
		d := Digest(content)
		id, _ := s.StartUpload()
		if _, err := s.Append(id, 0, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		if n, err := s.Finish(id, d); err != nil || n != int64(len(content)) {
			t.Fatalf("finish %d: %d %v", i, n, err)
		}
		want[d] = int64(len(content))
	}
	parts := 0
	for _, r := range fake.Requests() {
		if strings.HasPrefix(r, "PUT ") && strings.Contains(r, "partNumber=") {
			parts++
		}
	}
	if parts < 10 || len(fake.Uploads) != 0 {
		t.Errorf("%d parts, %d multipart uploads left", parts, len(fake.Uploads))
	}
	// Something else in the bucket is no blob.
	fake.Objects["registry/blobs/sha256/zz/not-a-blob"] = s3test.Object{Data: []byte("x"), Mod: time.Now()}
	fake.Objects["elsewhere/blobs/sha256/ab/"+strings.Repeat("a", 64)] = s3test.Object{Data: []byte("x"), Mod: time.Now()}
	got := map[string]int64{}
	if err := s.Walk(func(digest string, size int64, mod time.Time) error {
		got[digest] = size
		if mod.IsZero() {
			t.Errorf("%s has no time", digest)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("walked %v, want %v", got, want)
	}
	lists := 0
	for _, r := range fake.Requests() {
		if strings.Contains(r, "list-type=2") {
			lists++
		}
	}
	// Six objects below the prefix (one no blob), two a page.
	if lists != 3 {
		t.Errorf("%d pages", lists)
	}
}

func TestS3TriesAgain(t *testing.T) {
	fake := newFakeS3(t)
	s := fakeStore(t, fake, t.TempDir())
	body := []byte("worth another try")
	fake.Fail = 2
	if err := s.Put(Digest(body), body); err != nil {
		t.Fatalf("after two failures: %v", err)
	}
	fake.Fail = 100
	other := []byte("never")
	err := s.Put(Digest(other), other)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("when it keeps failing: %v", err)
	}
}

func TestS3Reads(t *testing.T) {
	fake := newFakeS3(t)
	s := fakeStore(t, fake, t.TempDir())
	content := []byte(strings.Repeat("0123456789", 300))
	d := Digest(content)
	if err := s.Put(d, content); err != nil {
		t.Fatal(err)
	}
	r, size, err := s.Open(d)
	if err != nil || size != int64(len(content)) {
		t.Fatalf("open: %d %v", size, err)
	}
	defer r.Close()
	asked := len(fake.Requests())
	if end, err := r.Seek(0, io.SeekEnd); err != nil || end != size || len(fake.Requests()) != asked {
		t.Errorf("seeking to the end: %d %v, %d requests", end, err, len(fake.Requests())-asked)
	}
	r.Seek(1005, io.SeekStart)
	buf := make([]byte, 10)
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "5678901234" {
		t.Errorf("from 1005: %q %v", buf, err)
	}
	// What docker asks: a range, served as from a file.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Range", "bytes=2990-2999")
	r.Seek(0, io.SeekStart)
	http.ServeContent(w, req, "", time.Time{}, r)
	if w.Code != http.StatusPartialContent || w.Body.String() != "0123456789" {
		t.Errorf("a range: %d %q", w.Code, w.Body)
	}
	r.Seek(0, io.SeekStart)
	all, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(all, content) {
		t.Errorf("all of it: %d %v", len(all), err)
	}
}

func TestS3DeleteIf(t *testing.T) {
	fake := newFakeS3(t)
	s := fakeStore(t, fake, t.TempDir())
	past := time.Now().Add(-time.Hour)
	fake.Clock = func() time.Time { return past }
	s.now = func() time.Time { return past }
	old, again, kept := []byte("old"), []byte("again"), []byte("kept")
	for _, b := range [][]byte{old, again, kept} {
		if err := s.Put(Digest(b), b); err != nil {
			t.Fatal(err)
		}
	}
	fake.Clock, s.now = time.Now, time.Now
	before := time.Now().Add(-time.Minute)
	// Stored again (it is there: only noted).
	if err := s.Put(Digest(again), again); err != nil {
		t.Fatal(err)
	}
	if n, deleted, err := s.DeleteIf(Digest(old), before, func() bool { return false }); err != nil || !deleted || n != 3 {
		t.Errorf("old: %d %v %v", n, deleted, err)
	}
	if _, deleted, err := s.DeleteIf(Digest(again), before, func() bool { return false }); err != nil || deleted {
		t.Errorf("stored again: %v %v", deleted, err)
	}
	if _, deleted, err := s.DeleteIf(Digest(kept), before, func() bool { return true }); err != nil || deleted {
		t.Errorf("kept: %v %v", deleted, err)
	}
	if _, deleted, err := s.DeleteIf(Digest(old), before, func() bool { return false }); err != nil || deleted {
		t.Errorf("gone already: %v %v", deleted, err)
	}
	// A store started again does not remember what it stored lately; the
	// object's own time says, as a file's does.
	s2 := fakeStore(t, fake, t.TempDir())
	if _, deleted, err := s2.DeleteIf(Digest(again), before, func() bool { return false }); err != nil || !deleted {
		t.Errorf("after a restart: %v %v", deleted, err)
	}
}

func TestS3Trouble(t *testing.T) {
	fake := newFakeS3(t)
	if err := fakeStore(t, fake, t.TempDir()).Check(); err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(fake.Objects) != 0 {
		t.Errorf("the check left %v", fake.Objects)
	}
	wrong, err := NewS3(S3Config{Endpoint: fake.URL, Bucket: "kartal", AccessKey: fake.Access, SecretKey: "wrong", PathStyle: true, Staging: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Check(); err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("a wrong secret: %v", err)
	}
	missing, _ := NewS3(S3Config{Endpoint: fake.URL, Bucket: "nope", AccessKey: fake.Access, SecretKey: fake.Secret, PathStyle: true, Staging: t.TempDir()})
	if err := missing.Check(); err == nil || !strings.Contains(err.Error(), "NoSuchBucket") {
		t.Errorf("no such bucket: %v", err)
	}
	for _, cfg := range []S3Config{
		{Endpoint: "ftp://x", Bucket: "kartal"},
		{Endpoint: "https://s3.example.org", Bucket: "Bad_Bucket"},
		{Endpoint: "https://s3.example.org", Bucket: "kartal", Prefix: "../up"},
		{Endpoint: "https://s3.example.org", Bucket: "kartal"},
		{Endpoint: "https://s3.example.org", Bucket: "kartal", AccessKey: "a", SecretKey: "b", PartSize: 1024, Staging: t.TempDir()},
		{Endpoint: "https://s3.example.org", Bucket: "kartal", AccessKey: "a", SecretKey: "b"},
	} {
		if _, err := NewS3(cfg); err == nil {
			t.Errorf("%+v was taken", cfg)
		}
	}
}

func TestS3Addresses(t *testing.T) {
	path, err := NewS3(S3Config{Endpoint: "https://minio.example.org:9000/", Bucket: "kartal", Prefix: "/team/", AccessKey: "a", SecretKey: "b",
		PathStyle: true, Staging: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if got := path.objectURL("team/blobs/x", nil).String(); got != "https://minio.example.org:9000/kartal/team/blobs/x" {
		t.Errorf("path style: %s", got)
	}
	host, _ := NewS3(S3Config{Endpoint: "https://s3.eu-central-1.amazonaws.com", Region: "eu-central-1", Bucket: "kartal", AccessKey: "a", SecretKey: "b",
		Staging: t.TempDir()})
	if got := host.objectURL("blobs/x", nil).String(); got != "https://kartal.s3.eu-central-1.amazonaws.com/blobs/x" {
		t.Errorf("host style: %s", got)
	}
	if k, _ := path.key("sha256:" + strings.Repeat("ab", 32)); k != "team/blobs/sha256/ab/"+strings.Repeat("ab", 32) {
		t.Errorf("key %s", k)
	}
}

func TestPing(t *testing.T) {
	fake := newFakeS3(t)
	if err := fakeStore(t, fake, t.TempDir()).Ping(); err != nil {
		t.Errorf("s3: %v", err)
	}
	missing, _ := NewS3(S3Config{Endpoint: fake.URL, Bucket: "nope", AccessKey: fake.Access, SecretKey: fake.Secret, PathStyle: true, Staging: t.TempDir()})
	if err := missing.Ping(); err == nil || !strings.Contains(err.Error(), "NoSuchBucket") {
		t.Errorf("no bucket: %v", err)
	}
	f, _ := NewFile(t.TempDir())
	if err := f.Ping(); err != nil {
		t.Errorf("file: %v", err)
	}
}
