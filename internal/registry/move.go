package registry

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// A project with repositories moves to another blob store with a job:
//
//  1. While it is where it was, its blobs are copied to the new store,
//     each digest checked as the store takes it; what is there already is
//     left.
//  2. The project is pointed at the new store; the one it came from is
//     MovedFrom: a blob the new store lacks is read there meanwhile, and
//     that store's collection keeps the project's blobs.
//  3. What was pushed during the copy is copied too; then the move ends.
//
// An upload started in the old store and finished after the switch is
// copied into the new one as it finishes. A move stopped or failed after
// the switch leaves the project readable; run again, it goes on.

// JobMove moves a project to another blob store.
const JobMove = "move"

// moveWorkers is how many blobs a move copies at once.
const moveWorkers = 4

// MoveReport is what a move did, or, in a dry run, would do.
type MoveReport struct {
	DryRun  bool      `json:"dryRun"`
	Project string    `json:"project"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	// Blobs are the project's blobs and manifests; Copied went to the new
	// store, Present were there already, Bytes were copied.
	Blobs   int   `json:"blobs"`
	Copied  int   `json:"copied"`
	Present int   `json:"present"`
	Bytes   int64 `json:"bytes"`
	// Missing are blobs the old store did not have either.
	Missing []string `json:"missing,omitempty"`
}

func (r MoveReport) String() string {
	verb := "moved"
	if r.DryRun {
		verb = "would move"
	}
	return fmt.Sprintf("%s %s from %s to %s: %d blobs, %d copied (%s), %d there already, %d missing", r.Project, verb, r.From, r.To,
		r.Blobs, r.Copied, meta.HumanBytes(r.Bytes), r.Present, len(r.Missing))
}

// StartMove starts a project's move to a blob store, or its dry run; a
// move that did not end goes on with the store it is at.
func (s *Server) StartMove(project, to string, dryRun bool, by string) (meta.Job, error) {
	p, ok := s.cfg.DB.Project(project)
	if !ok {
		return meta.Job{}, fmt.Errorf("%w: project %s does not exist", ErrJob, project)
	}
	if to == "" {
		to = p.StoreName()
	}
	if _, err := s.storeNamed(to); err != nil {
		return meta.Job{}, fmt.Errorf("%w: %v", ErrJob, err)
	}
	if to == p.StoreName() && p.MovedFrom == "" {
		return meta.Job{}, fmt.Errorf("%w: the project is in %s already", ErrJob, to)
	}
	if p.MovedFrom != "" && to != p.StoreName() {
		return meta.Job{}, fmt.Errorf("%w: the project's move to %s did not end; run it again to %s first", ErrJob, p.StoreName(), p.StoreName())
	}
	return s.launch(meta.Job{Kind: JobMove, DryRun: dryRun, Project: project, Store: to, By: by})
}

// Move copies a project's blobs to a blob store and points the project at
// it, as above; progress hears how far it got.
func (s *Server) Move(ctx context.Context, project, to string, dryRun bool, by string, progress func(meta.JobProgress)) (MoveReport, error) {
	start := time.Now()
	rep := MoveReport{DryRun: dryRun, Project: project, To: to, Started: s.now().UTC()}
	p, ok := s.cfg.DB.Project(project)
	if !ok {
		return rep, fmt.Errorf("project %s does not exist", project)
	}
	rep.From = p.StoreName()
	if p.MovedFrom != "" {
		rep.From = p.MovedFrom
	}
	from, err := s.storeNamed(rep.From)
	if err != nil {
		return rep, err
	}
	dest, err := s.storeNamed(to)
	if err != nil {
		return rep, err
	}
	// Each pass copies what the project has now that the new store lacks.
	done := map[string]bool{}
	pass := func() error {
		blobs := s.cfg.DB.ProjectBlobs(project)
		var todo []string
		for d := range blobs {
			if !done[d] {
				todo = append(todo, d)
			}
		}
		sort.Strings(todo)
		rep.Blobs = len(blobs)
		var mu sync.Mutex
		var first error
		work := make(chan string)
		var wg sync.WaitGroup
		for i := 0; i < moveWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for d := range work {
					n, copied, err := s.copyBlob(ctx, from, dest, d, dryRun, blobs[d])
					mu.Lock()
					switch {
					case errors.Is(err, blobstore.ErrNotFound):
						rep.Missing = append(rep.Missing, d)
					case err != nil:
						if first == nil {
							first = fmt.Errorf("copying %s: %w", d, err)
						}
					case copied:
						rep.Copied++
						rep.Bytes += n
					default:
						rep.Present++
					}
					if err == nil || errors.Is(err, blobstore.ErrNotFound) {
						done[d] = true
					}
					if progress != nil {
						progress(meta.JobProgress{Done: len(done), Total: rep.Blobs, Bytes: rep.Bytes})
					}
					mu.Unlock()
				}
			}()
		}
	feed:
		for _, d := range todo {
			select {
			case work <- d:
			case <-ctx.Done():
				break feed
			}
		}
		close(work)
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
		return first
	}
	finish := func(err error) (MoveReport, error) {
		sort.Strings(rep.Missing)
		rep.Seconds = time.Since(start).Seconds()
		return rep, err
	}
	if err := pass(); err != nil {
		return finish(err)
	}
	if dryRun {
		return finish(nil)
	}
	if _, err := s.cfg.DB.MoveProject(project, to, by); err != nil {
		return finish(err)
	}
	// What was pushed meanwhile, into the old store.
	if err := pass(); err != nil {
		return finish(err)
	}
	if err := s.cfg.DB.EndMove(project, by); err != nil {
		return finish(err)
	}
	return finish(nil)
}

// copyBlob copies a blob from one store to another, unless it is there:
// through an upload, which checks its digest. It tells the bytes copied
// and whether it copied; blobstore.ErrNotFound is a blob neither has.
func (s *Server) copyBlob(ctx context.Context, from, to blobstore.Store, digest string, dryRun bool, size int64) (int64, bool, error) {
	if _, err := to.Stat(digest); err == nil {
		return 0, false, nil
	} else if !errors.Is(err, blobstore.ErrNotFound) {
		return 0, false, err
	}
	if dryRun {
		if _, err := from.Stat(digest); err != nil {
			return 0, false, err
		}
		return size, true, nil
	}
	rc, _, err := from.Open(digest)
	if err != nil {
		return 0, false, err
	}
	defer rc.Close()
	id, err := to.StartUpload()
	if err != nil {
		return 0, false, err
	}
	if _, err := to.Append(id, 0, &ctxReader{ctx: ctx, r: rc}); err != nil {
		to.Cancel(id)
		return 0, false, err
	}
	n, err := to.Finish(id, digest)
	if err != nil {
		to.Cancel(id)
		return 0, false, err
	}
	return n, true, nil
}

// ctxReader stops reading when its context ends.
type ctxReader struct {
	ctx context.Context
	r   interface{ Read([]byte) (int, error) }
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// openBlob reads a blob of a repository from its project's store, or,
// while the project moves, from the store it comes from.
func (s *Server) openBlob(repo, digest string) (blobstore.ReadSeekCloser, int64, error) {
	st, _, err := s.storeOf(repo)
	if err != nil {
		return nil, 0, err
	}
	f, n, err := st.Open(digest)
	if errors.Is(err, blobstore.ErrNotFound) {
		if p, _ := s.cfg.DB.Project(meta.ProjectOf(repo)); p.MovedFrom != "" {
			if old, oerr := s.storeNamed(p.MovedFrom); oerr == nil {
				return old.Open(digest)
			}
		}
	}
	return f, n, err
}

// settle makes a blob an upload finished in a store the project left
// (it moved meanwhile) the project's in its store now.
func (s *Server) settle(repo, uploadStore, digest string) error {
	now := s.storeNameOf(repo)
	if uploadStore == now {
		return nil
	}
	from, err := s.storeNamed(uploadStore)
	if err != nil {
		return err
	}
	to, err := s.storeNamed(now)
	if err != nil {
		return err
	}
	_, _, err = s.copyBlob(context.Background(), from, to, digest, false, 0)
	return err
}
