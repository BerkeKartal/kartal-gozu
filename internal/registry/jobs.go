package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/cron"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The registry's jobs, collecting garbage and checking the blobs, run when
// someone starts one or when its schedule says, one of a kind at a time.
// What each did is remembered with the metadata.

// The kinds of jobs.
const (
	JobGC     = "gc"
	JobVerify = "verify"
)

// defaultSchedules are the schedules a registry starts with: garbage
// every night, the blobs checked every Sunday.
var defaultSchedules = []meta.Schedule{
	{Kind: JobGC, Cron: "0 3 * * *", Enabled: true},
	{Kind: JobVerify, Cron: "0 4 * * 0", Enabled: true},
}

var (
	// ErrRunning is a job of a kind that is running already.
	ErrRunning = errors.New("a job of this kind is running")
	// ErrJob is a job that cannot be started as asked.
	ErrJob = errors.New("no such job")
	// ErrSchedule is a schedule that cannot be read.
	ErrSchedule = errors.New("not a schedule")
)

// ScheduledBy is who a schedule's jobs are by.
const ScheduledBy = "schedule"

func jobKind(kind string) bool { return kind == JobGC || kind == JobVerify }

// Start lets jobs run until ctx ends, and runs the schedules. A job that was
// running when the registry stopped is marked as failed.
func (s *Server) Start(ctx context.Context) {
	s.jobMu.Lock()
	s.jobCtx = ctx
	s.jobMu.Unlock()
	for _, j := range s.cfg.DB.Jobs(0) {
		if j.Status == meta.JobRunning {
			now := s.now().UTC()
			j.Status, j.Error, j.Finished = meta.JobFailed, "the registry stopped while it ran", &now
			if err := s.cfg.DB.PutJob(j); err != nil {
				s.cfg.Log.Warn("registry: marking a job that did not finish", "job", j.ID, "err", err)
			}
		}
	}
	have := map[string]bool{}
	for _, sc := range s.cfg.DB.Schedules() {
		have[sc.Kind] = true
	}
	for _, sc := range defaultSchedules {
		if !have[sc.Kind] {
			sc.Since = s.now().UTC()
			if err := s.cfg.DB.SetSchedule(sc, ""); err != nil {
				s.cfg.Log.Warn("registry: setting a schedule", "kind", sc.Kind, "err", err)
			}
		}
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for ctx.Err() == nil {
			s.RunDue()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}()
}

// zone is the time zone schedules are read in.
func (s *Server) zone() *time.Location {
	if s.cfg.Zone != nil {
		return s.cfg.Zone
	}
	loc, err := cron.Zone("")
	if err != nil {
		return time.UTC
	}
	return loc
}

// NextRun is when a schedule runs next, or the zero time when it does not.
func (s *Server) NextRun(sc meta.Schedule) time.Time {
	if !sc.Enabled {
		return time.Time{}
	}
	c, err := cron.Parse(sc.Cron)
	if err != nil {
		return time.Time{}
	}
	from := sc.Since
	if sc.Last != nil && sc.Last.After(from) {
		from = *sc.Last
	}
	return c.Next(from, s.zone())
}

// RunDue starts the jobs whose schedules are due. A registry that was down
// when one was runs it once when it is back.
func (s *Server) RunDue() {
	now := s.now()
	for _, sc := range s.cfg.DB.Schedules() {
		next := s.NextRun(sc)
		if next.IsZero() || next.After(now) {
			continue
		}
		if err := s.cfg.DB.MarkScheduled(sc.Kind, now); err != nil {
			s.cfg.Log.Warn("registry: noting a schedule's run", "kind", sc.Kind, "err", err)
			continue
		}
		if _, err := s.StartJob(sc.Kind, false, ScheduledBy); err != nil && !errors.Is(err, ErrRunning) {
			s.cfg.Log.Warn("registry: starting a scheduled job", "kind", sc.Kind, "err", err)
		}
	}
}

// SetSchedule changes a kind of job's schedule; it runs first at the first
// time after now that it matches.
func (s *Server) SetSchedule(kind, expr string, enabled bool, user string) (meta.Schedule, error) {
	if !jobKind(kind) {
		return meta.Schedule{}, fmt.Errorf("%w: %q", ErrJob, kind)
	}
	c, err := cron.Parse(expr)
	if err != nil {
		return meta.Schedule{}, fmt.Errorf("%w: %w", ErrSchedule, err)
	}
	sc := meta.Schedule{Kind: kind, Cron: c.String(), Enabled: enabled, Since: s.now().UTC(), By: user}
	return sc, s.cfg.DB.SetSchedule(sc, user)
}

// StartJob starts a job, which runs on its own; the job is remembered as
// running. Only collecting garbage has a dry run.
func (s *Server) StartJob(kind string, dryRun bool, by string) (meta.Job, error) {
	if !jobKind(kind) {
		return meta.Job{}, fmt.Errorf("%w: %q", ErrJob, kind)
	}
	if dryRun && kind != JobGC {
		return meta.Job{}, fmt.Errorf("%w: a %s has no dry run", ErrJob, kind)
	}
	b := make([]byte, 8)
	rand.Read(b)
	j := meta.Job{ID: hex.EncodeToString(b), Kind: kind, DryRun: dryRun, By: by, Started: s.now().UTC(), Status: meta.JobRunning}
	s.jobMu.Lock()
	if id, ok := s.running[kind]; ok {
		s.jobMu.Unlock()
		return meta.Job{}, fmt.Errorf("%w: %s", ErrRunning, id)
	}
	s.running[kind] = j.ID
	ctx := s.jobCtx
	s.jobMu.Unlock()
	if err := s.cfg.DB.PutJob(j); err != nil {
		s.jobMu.Lock()
		delete(s.running, kind)
		s.jobMu.Unlock()
		return meta.Job{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	go s.runJob(ctx, j)
	return j, nil
}

func (s *Server) runJob(ctx context.Context, j meta.Job) {
	defer func() {
		s.jobMu.Lock()
		delete(s.running, j.Kind)
		s.jobMu.Unlock()
	}()
	var report any
	var err error
	switch j.Kind {
	case JobGC:
		var rep GCReport
		rep, err = s.GC(ctx, DefaultGrace, j.DryRun, j.By)
		report, j.Summary = rep, rep.String()
	case JobVerify:
		var rep VerifyReport
		rep, err = s.Verify(ctx, j.By)
		report, j.Summary = rep, rep.String()
		if err == nil && !rep.OK() {
			j.Alarm = fmt.Sprintf("%d corrupt and %d missing blobs", len(rep.Corrupt), len(rep.Missing))
		}
	}
	if b, merr := json.Marshal(report); merr == nil {
		j.Report = b
	}
	now := s.now().UTC()
	j.Finished, j.Status = &now, meta.JobDone
	if err != nil {
		j.Status, j.Error = meta.JobFailed, err.Error()
		s.cfg.Log.Warn("registry: a job failed", "job", j.ID, "kind", j.Kind, "err", err)
	}
	if err := s.cfg.DB.PutJob(j); err != nil {
		s.cfg.Log.Warn("registry: recording a job", "job", j.ID, "err", err)
	}
}
