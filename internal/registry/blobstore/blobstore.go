// Package blobstore keeps the registry's content: blobs addressed by their
// digest, and the uploads that become blobs. Store is what the registry
// uses; File keeps everything on a disk, S3 the blobs in a bucket of S3 or
// of anything that speaks its API (MinIO, Ceph), and the uploads on a disk
// until they are whole.
package blobstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound is a blob or an upload that is not there.
	ErrNotFound = errors.New("not found")
	// ErrDigestMismatch is an upload whose content does not have the digest
	// it was to have.
	ErrDigestMismatch = errors.New("the content does not match the digest")
	// ErrOffset is a chunk that does not start where the upload ends.
	ErrOffset = errors.New("the chunk does not start where the upload ends")
)

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ValidDigest tells whether a digest is one the store takes: sha256, the
// one algorithm every client uses.
func ValidDigest(d string) bool { return digestRE.MatchString(d) }

// Digest is the digest of some content.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ReadSeekCloser is a blob being read.
type ReadSeekCloser interface {
	io.ReadSeeker
	io.Closer
}

// Store keeps blobs and uploads.
type Store interface {
	// Stat is a blob's size.
	Stat(digest string) (int64, error)
	// Open reads a blob.
	Open(digest string) (ReadSeekCloser, int64, error)
	// Put stores content whose digest is known, such as a manifest.
	Put(digest string, b []byte) error
	// Delete removes a blob; a blob that is not there is no error.
	Delete(digest string) error
	// DeleteIf removes a blob last written before a time, unless keep says
	// otherwise, asked at the last moment; it tells the size removed and
	// whether it was. Storing the same blob meanwhile makes it new again,
	// so that collecting garbage never takes a blob being pushed.
	DeleteIf(digest string, before time.Time, keep func() bool) (int64, bool, error)
	// Walk visits every blob.
	Walk(fn func(digest string, size int64, modified time.Time) error) error

	// StartUpload begins an upload and names it.
	StartUpload() (string, error)
	// UploadSize is how much of an upload has arrived.
	UploadSize(id string) (int64, error)
	// Append adds a chunk at offset, which must be where the upload ends,
	// and returns the upload's new size.
	Append(id string, offset int64, r io.Reader) (int64, error)
	// Finish makes an upload the blob digest, checking that it is.
	Finish(id, digest string) (int64, error)
	// Cancel drops an upload.
	Cancel(id string) error
	// WalkUploads visits every upload, as GC must keep their blobs alive.
	WalkUploads(fn func(id string, size int64, modified time.Time) error) error
}

// File is a Store on a disk:
//
//	<root>/blobs/sha256/<first two hex digits>/<hex>
//	<root>/uploads/<id>
type File struct {
	root string

	mu      sync.Mutex
	hashers map[string]*upload
	// placing is held while a blob is stored or deleted, so that a blob
	// stored again is never deleted as old.
	placing sync.Mutex
}

// upload is the digest of what an upload holds so far, so that finishing
// it does not read it all again. A restart loses it; the upload is read
// again then.
type upload struct {
	mu   sync.Mutex
	h    hash.Hash
	size int64
}

// NewFile keeps blobs below root.
func NewFile(root string) (*File, error) {
	for _, d := range []string{"blobs/sha256", "uploads"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			return nil, err
		}
	}
	return &File{root: root, hashers: map[string]*upload{}}, nil
}

func (f *File) blobPath(digest string) (string, error) {
	if !ValidDigest(digest) {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	hexPart := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(f.root, "blobs", "sha256", hexPart[:2], hexPart), nil
}

var uploadRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (f *File) uploadPath(id string) (string, error) {
	if !uploadRE.MatchString(id) {
		return "", ErrNotFound
	}
	return filepath.Join(f.root, "uploads", id), nil
}

func (f *File) Stat(digest string) (int64, error) {
	p, err := f.blobPath(digest)
	if err != nil {
		return 0, ErrNotFound
	}
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (f *File) Open(digest string) (ReadSeekCloser, int64, error) {
	p, err := f.blobPath(digest)
	if err != nil {
		return nil, 0, ErrNotFound
	}
	fh, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	fi, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, 0, err
	}
	return fh, fi.Size(), nil
}

func (f *File) Put(digest string, b []byte) error {
	if Digest(b) != digest {
		return ErrDigestMismatch
	}
	p, err := f.blobPath(digest)
	if err != nil {
		return err
	}
	if f.renew(p) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Join(f.root, "uploads"), "put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	return f.place(tmp, p)
}

// renew tells whether a blob is there, and makes it new if so: it is being
// stored again.
func (f *File) renew(p string) bool {
	f.placing.Lock()
	defer f.placing.Unlock()
	if _, err := os.Stat(p); err != nil {
		return false
	}
	now := time.Now()
	return os.Chtimes(p, now, now) == nil
}

// place syncs a finished file and moves it to its blob path, where a blob
// that is already there wins: it has the same content, and is new again.
func (f *File) place(fh *os.File, p string) error {
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f.placing.Lock()
	defer f.placing.Unlock()
	if _, err := os.Stat(p); err == nil {
		now := time.Now()
		if err := os.Chtimes(p, now, now); err != nil {
			return err
		}
		return os.Remove(fh.Name())
	}
	if err := os.Rename(fh.Name(), p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Some file systems (and Windows) do not sync directories; the rename
	// is still there.
	_ = d.Sync()
	return nil
}

func (f *File) Delete(digest string) error {
	p, err := f.blobPath(digest)
	if err != nil {
		return nil
	}
	f.placing.Lock()
	defer f.placing.Unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f *File) DeleteIf(digest string, before time.Time, keep func() bool) (int64, bool, error) {
	p, err := f.blobPath(digest)
	if err != nil {
		return 0, false, nil
	}
	f.placing.Lock()
	defer f.placing.Unlock()
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !fi.ModTime().Before(before) || keep() {
		return 0, false, nil
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, false, err
	}
	return fi.Size(), true, nil
}

func (f *File) Walk(fn func(digest string, size int64, modified time.Time) error) error {
	base := filepath.Join(f.root, "blobs", "sha256")
	dirs, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(base, d.Name()))
		if err != nil {
			return err
		}
		for _, e := range files {
			digest := "sha256:" + e.Name()
			if !ValidDigest(digest) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if err := fn(digest, info.Size(), info.ModTime()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *File) StartUpload() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	p, _ := f.uploadPath(id)
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	if err := fh.Close(); err != nil {
		return "", err
	}
	f.mu.Lock()
	f.hashers[id] = &upload{h: sha256.New()}
	f.mu.Unlock()
	return id, nil
}

func (f *File) UploadSize(id string) (int64, error) {
	p, err := f.uploadPath(id)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// hasher is an upload's digest so far; catchUp reads the upload again
// when the one in memory was lost (a restart) or fell behind.
func (f *File) hasher(id string) *upload {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.hashers[id]
	if u == nil {
		u = &upload{h: sha256.New(), size: -1}
		f.hashers[id] = u
	}
	return u
}

// catchUp brings the digest up to the file's size; the lock is held.
func catchUp(u *upload, p string, size int64) error {
	if u.size == size {
		return nil
	}
	u.h, u.size = sha256.New(), 0
	fh, err := os.Open(p)
	if err != nil {
		return err
	}
	defer fh.Close()
	n, err := io.Copy(u.h, io.LimitReader(fh, size))
	u.size = n
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (f *File) Append(id string, offset int64, r io.Reader) (int64, error) {
	p, err := f.uploadPath(id)
	if err != nil {
		return 0, err
	}
	u := f.hasher(id)
	u.mu.Lock()
	defer u.mu.Unlock()
	fh, err := os.OpenFile(p, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	if offset != size {
		return size, ErrOffset
	}
	if err := catchUp(u, p, size); err != nil {
		return size, err
	}
	if _, err := fh.Seek(size, io.SeekStart); err != nil {
		return size, err
	}
	n, err := io.Copy(io.MultiWriter(fh, u.h), r)
	u.size += n
	if err != nil {
		// What arrived stays: the client may resume from the new size, which
		// it asks for. The file is cut back if the write itself failed.
		if terr := fh.Truncate(size + n); terr != nil {
			u.size = -1
		}
		return size + n, err
	}
	return size + n, nil
}

func (f *File) Finish(id, digest string) (int64, error) {
	return f.finishWith(id, digest, func(p string, _ int64) error {
		target, err := f.blobPath(digest)
		if err != nil {
			return err
		}
		fh, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		return f.place(fh, target)
	})
}

// finishWith checks that an upload is the blob digest, and hands its file
// to place, which makes it the blob (and moves or removes the file).
func (f *File) finishWith(id, digest string, place func(path string, size int64) error) (int64, error) {
	if !ValidDigest(digest) {
		return 0, ErrDigestMismatch
	}
	p, err := f.uploadPath(id)
	if err != nil {
		return 0, err
	}
	u := f.hasher(id)
	u.mu.Lock()
	defer u.mu.Unlock()
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if err := catchUp(u, p, fi.Size()); err != nil {
		return 0, err
	}
	// The digest of what is there so far, without ending the hash, which a
	// mismatch leaves usable for more chunks.
	sum := u.h.(encoding.BinaryMarshaler)
	state, err := sum.MarshalBinary()
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return 0, err
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		return 0, ErrDigestMismatch
	}
	if err := place(p, fi.Size()); err != nil {
		return 0, err
	}
	f.mu.Lock()
	delete(f.hashers, id)
	f.mu.Unlock()
	return fi.Size(), nil
}

func (f *File) Cancel(id string) error {
	p, err := f.uploadPath(id)
	if err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.hashers, id)
	f.mu.Unlock()
	if err := os.Remove(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func (f *File) WalkUploads(fn func(id string, size int64, modified time.Time) error) error {
	entries, err := os.ReadDir(filepath.Join(f.root, "uploads"))
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !uploadRE.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if err := fn(e.Name(), info.Size(), info.ModTime()); err != nil {
			return err
		}
	}
	return nil
}
