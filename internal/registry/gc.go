package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// Garbage is collected while the registry serves. A push uploads its blobs
// before the manifest that uses them, so what nothing uses yet is spared
// for a grace period: a blob newer than it, or linked to a repository
// lately (a push that finds a blob there renews its link), stays.

// DefaultGrace is how long garbage is spared, for the pushes under way: as
// long as it counts in its project's quota.
const DefaultGrace = meta.PendingLinks

// uploadsKept is how long an upload left behind is kept.
const uploadsKept = 24 * time.Hour

// GCReport is what a garbage collection did, or, in a dry run, would do.
type GCReport struct {
	DryRun  bool      `json:"dryRun"`
	Started time.Time `json:"started"`
	// Seconds is how long it took.
	Seconds float64 `json:"seconds"`
	// Unlinked are the blobs taken from repositories none of whose
	// artifacts uses them.
	Unlinked int `json:"unlinked"`
	// Blobs are the blobs deleted, which no repository had any more, and
	// Freed the bytes they took.
	Blobs int   `json:"blobs"`
	Freed int64 `json:"freed"`
	// Spared are the unused blobs newer than the grace period.
	Spared int `json:"spared"`
	// Uploads are the uploads left behind that were removed.
	Uploads int `json:"uploads"`
}

func (r GCReport) String() string {
	return fmt.Sprintf("%d links, %d blobs (%s) and %d uploads collected, %d blobs spared", r.Unlinked, r.Blobs, meta.HumanBytes(r.Freed),
		r.Uploads, r.Spared)
}

// GC collects garbage: the links that no artifact of their repository
// uses, the blobs no repository has, and the uploads left behind. Only
// one runs at a time.
func (s *Server) GC(ctx context.Context, grace time.Duration, dryRun bool, user string) (GCReport, error) {
	if grace < 0 {
		return GCReport{}, errors.New("the grace period cannot be negative")
	}
	s.gcMu.Lock()
	defer s.gcMu.Unlock()
	start := time.Now()
	rep := GCReport{DryRun: dryRun, Started: s.now().UTC()}
	before := s.now().Add(-grace)
	garbage := s.cfg.DB.GarbageLinks(before)
	for _, dgs := range garbage {
		rep.Unlinked += len(dgs)
	}
	if !dryRun {
		n, err := s.cfg.DB.UnlinkGarbage(garbage, before)
		rep.Unlinked = n
		if err != nil {
			return rep, err
		}
		garbage = nil
	}
	inUse := s.cfg.DB.BlobsInUse(garbage)
	err := s.cfg.Store.Walk(func(digest string, size int64, modified time.Time) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if inUse[digest] {
			return nil
		}
		if !modified.Before(before) {
			rep.Spared++
			return nil
		}
		if dryRun {
			rep.Blobs++
			rep.Freed += size
			return nil
		}
		// Asked again at the last moment: a push may have linked it since.
		n, deleted, err := s.cfg.Store.DeleteIf(digest, before, func() bool { return s.cfg.DB.InUse(digest) })
		if err != nil {
			return err
		}
		if deleted {
			rep.Blobs++
			rep.Freed += n
		} else {
			rep.Spared++
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	keepUploads := max(uploadsKept, grace)
	err = s.cfg.Store.WalkUploads(func(id string, _ int64, modified time.Time) error {
		if s.now().Sub(modified) < keepUploads {
			return nil
		}
		rep.Uploads++
		if dryRun {
			return nil
		}
		s.forget(id)
		if err := s.cfg.Store.Cancel(id); err != nil && !errors.Is(err, blobstore.ErrNotFound) {
			return err
		}
		return nil
	})
	rep.Seconds = time.Since(start).Seconds()
	if err != nil {
		return rep, err
	}
	if !dryRun {
		if err := s.cfg.DB.Record(user, "gc", "", "", "", "", rep.String()); err != nil {
			s.cfg.Log.Warn("registry: recording a garbage collection", "err", err)
		}
	}
	return rep, nil
}

// VerifyReport is what checking the blobs found.
type VerifyReport struct {
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	// Checked are the blobs read again, Bytes their size.
	Checked int   `json:"checked"`
	Bytes   int64 `json:"bytes"`
	// Corrupt are the blobs whose content is not their digest any more.
	Corrupt []string `json:"corrupt"`
	// Missing are the blobs that artifacts use and the store does not
	// have, as repository@digest.
	Missing []string `json:"missing"`
}

// OK tells whether the check found nothing wrong.
func (r VerifyReport) OK() bool { return len(r.Corrupt) == 0 && len(r.Missing) == 0 }

func (r VerifyReport) String() string {
	return fmt.Sprintf("%d blobs (%s) checked: %d corrupt, %d missing", r.Checked, meta.HumanBytes(r.Bytes), len(r.Corrupt), len(r.Missing))
}

// Verify reads every blob again to see that it is still its digest, and
// checks that what the artifacts use is there.
func (s *Server) Verify(ctx context.Context, user string) (VerifyReport, error) {
	start := time.Now()
	rep := VerifyReport{Started: s.now().UTC(), Corrupt: []string{}, Missing: []string{}}
	err := s.cfg.Store.Walk(func(digest string, size int64, _ time.Time) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, _, err := s.cfg.Store.Open(digest)
		if errors.Is(err, blobstore.ErrNotFound) {
			return nil // collected meanwhile
		}
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		rep.Checked++
		rep.Bytes += size
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
			rep.Corrupt = append(rep.Corrupt, digest)
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	for repo, used := range s.cfg.DB.Uses() {
		for _, dg := range used {
			if _, err := s.cfg.Store.Stat(dg); errors.Is(err, blobstore.ErrNotFound) {
				rep.Missing = append(rep.Missing, repo+"@"+dg)
			}
		}
	}
	sort.Strings(rep.Missing)
	rep.Seconds = time.Since(start).Seconds()
	if err := s.cfg.DB.Record(user, "verify", "", "", "", "", rep.String()); err != nil {
		s.cfg.Log.Warn("registry: recording a check", "err", err)
	}
	return rep, nil
}
