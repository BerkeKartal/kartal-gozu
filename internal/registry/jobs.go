package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/cron"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The registry's jobs, collecting garbage and checking the blobs, run when
// someone starts one or when its schedule says, one of a kind at a time.
// What each did is remembered with the metadata.

// The kinds of jobs.
const (
	JobGC        = "gc"
	JobVerify    = "verify"
	JobRetention = "retention"
)

// defaultSchedules are the schedules a registry starts with: the
// projects' retention rules applied every night, and the garbage they
// leave collected after; the blobs checked every Sunday.
var defaultSchedules = []meta.Schedule{
	{Kind: JobRetention, Cron: "0 2 * * *", Enabled: true},
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

func jobKind(kind string) bool {
	return kind == JobGC || kind == JobVerify || kind == JobRetention || kind == JobScan
}

// scanSchedule is when a registry with a scanner scans every image again:
// every night, after the night's collection and checks.
var scanSchedule = meta.Schedule{Kind: JobScan, Cron: "0 5 * * *", Enabled: true}

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
	defaults := defaultSchedules
	if s.cfg.Scanner != nil {
		defaults = append(append([]meta.Schedule(nil), defaults...), scanSchedule)
	}
	for _, sc := range defaults {
		if !have[sc.Kind] {
			sc.Since = s.now().UTC()
			if err := s.cfg.DB.SetSchedule(sc, ""); err != nil {
				s.cfg.Log.Warn("registry: setting a schedule", "kind", sc.Kind, "err", err)
			}
		}
	}
	s.startScans(ctx)
	go s.watchStores(ctx)
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
		if next.IsZero() || next.After(now) || (sc.Kind == JobScan && s.cfg.Scanner == nil) {
			continue
		}
		if err := s.cfg.DB.MarkScheduled(sc.Kind, now); err != nil {
			s.cfg.Log.Warn("registry: noting a schedule's run", "kind", sc.Kind, "err", err)
			continue
		}
		if _, err := s.StartJob(sc.Kind, false, "", ScheduledBy); err != nil && !errors.Is(err, ErrRunning) {
			s.cfg.Log.Warn("registry: starting a scheduled job", "kind", sc.Kind, "err", err)
		}
	}
	// And the replication rules on schedules of their own.
	for _, r := range s.cfg.DB.Rules() {
		next := s.NextRuleRun(r)
		if next.IsZero() || next.After(now) {
			continue
		}
		if err := s.cfg.DB.MarkRuleRun(r.ID, now); err != nil {
			s.cfg.Log.Warn("registry: noting a rule's run", "rule", r.Name, "err", err)
			continue
		}
		if _, err := s.StartReplication(r.ID, false, ScheduledBy); err != nil && !errors.Is(err, ErrRunning) {
			s.cfg.Log.Warn("registry: starting a scheduled replication", "rule", r.Name, "err", err)
		}
	}
}

// NextRuleRun is when a rule runs next on its schedule, or the zero time.
func (s *Server) NextRuleRun(r meta.ReplicationRule) time.Time {
	if !r.Enabled || r.Cron == "" {
		return time.Time{}
	}
	return s.NextRun(meta.Schedule{Cron: r.Cron, Enabled: true, Since: r.Since, Last: r.Last})
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
// running. Collecting garbage and retention have dry runs, and retention
// may be of one project. A replication rule's runs start with
// StartReplication.
func (s *Server) StartJob(kind string, dryRun bool, project, by string) (meta.Job, error) {
	if !jobKind(kind) {
		if kind == JobReplication {
			return meta.Job{}, fmt.Errorf("%w: a replication runs a rule", ErrJob)
		}
		return meta.Job{}, fmt.Errorf("%w: %q", ErrJob, kind)
	}
	if dryRun && (kind == JobVerify || kind == JobScan) {
		return meta.Job{}, fmt.Errorf("%w: a %s has no dry run", ErrJob, kind)
	}
	if kind == JobScan && s.cfg.Scanner == nil {
		return meta.Job{}, fmt.Errorf("%w: %w", ErrJob, ErrNoScanner)
	}
	if project != "" {
		p, ok := s.cfg.DB.Project(project)
		switch {
		case kind != JobRetention:
			return meta.Job{}, fmt.Errorf("%w: only retention is of a project", ErrJob)
		case !ok:
			return meta.Job{}, fmt.Errorf("%w: project %s does not exist", ErrJob, project)
		case len(p.Retention) == 0:
			return meta.Job{}, fmt.Errorf("%w: project %s has no retention rules", ErrJob, project)
		}
	}
	return s.launch(meta.Job{Kind: kind, DryRun: dryRun, Project: project, By: by})
}

// StartReplication runs a replication rule, or tries it in a dry run.
func (s *Server) StartReplication(rule string, dryRun bool, by string) (meta.Job, error) {
	r, ok := s.cfg.DB.Rule(rule)
	if !ok {
		return meta.Job{}, fmt.Errorf("%w: no such replication rule", ErrJob)
	}
	return s.launch(meta.Job{Kind: JobReplication, DryRun: dryRun, Project: r.Project, Rule: r.ID, RuleName: r.Name, By: by})
}

// runKey is what one job runs at a time of: its kind, or its rule.
func runKey(j meta.Job) string { return j.Kind + "\x00" + j.Rule }

func (s *Server) launch(j meta.Job) (meta.Job, error) {
	b := make([]byte, 8)
	rand.Read(b)
	j.ID, j.Started, j.Status = hex.EncodeToString(b), s.now().UTC(), meta.JobRunning
	key := runKey(j)
	s.jobMu.Lock()
	if id, ok := s.running[key]; ok {
		s.jobMu.Unlock()
		return meta.Job{}, fmt.Errorf("%w: %s", ErrRunning, id)
	}
	s.running[key] = j.ID
	base := s.jobCtx
	s.jobMu.Unlock()
	if err := s.cfg.DB.PutJob(j); err != nil {
		s.jobMu.Lock()
		delete(s.running, key)
		s.jobMu.Unlock()
		return meta.Job{}, err
	}
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	s.jobMu.Lock()
	s.cancels[j.ID] = cancel
	s.jobMu.Unlock()
	go s.runJob(ctx, j)
	return j, nil
}

// CancelJob stops a running job; it ends as failed, saying who stopped it.
func (s *Server) CancelJob(id, by string) error {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	cancel, ok := s.cancels[id]
	if !ok {
		return fmt.Errorf("%w: it is not running", ErrJob)
	}
	s.cancelledBy[id] = by
	cancel()
	return nil
}

// setProgress keeps how far a running job got.
func (s *Server) setProgress(id string, p meta.JobProgress) {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if _, ok := s.cancels[id]; ok {
		s.jobProgress[id] = p
	}
}

// withProgress is a job as the API shows it: a running one with how far
// it got.
func (s *Server) withProgress(j meta.Job) meta.Job {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if p, ok := s.jobProgress[j.ID]; ok && j.Status == meta.JobRunning {
		j.Progress = &p
	}
	return j
}

func (s *Server) runJob(ctx context.Context, j meta.Job) {
	// It is no longer running before it is written down as ended, so that
	// one who sees it ended cannot stop it any more.
	var once sync.Once
	end := func() {
		once.Do(func() {
			s.jobMu.Lock()
			delete(s.running, runKey(j))
			if cancel := s.cancels[j.ID]; cancel != nil {
				cancel()
			}
			delete(s.cancels, j.ID)
			delete(s.jobProgress, j.ID)
			delete(s.cancelledBy, j.ID)
			s.jobMu.Unlock()
		})
	}
	defer end()
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
	case JobRetention:
		var rep RetentionReport
		rep, err = s.Retention(ctx, j.Project, j.DryRun, j.By)
		report, j.Summary = rep, rep.String()
	case JobReplication:
		var rep ReplicationReport
		// So many replications run at once; the others wait their turn, and
		// say so.
		turn := true
		select {
		case s.replicating <- struct{}{}:
		default:
			s.setProgress(j.ID, meta.JobProgress{Waiting: true})
			select {
			case s.replicating <- struct{}{}:
			case <-ctx.Done():
				turn, err = false, ctx.Err()
			}
		}
		if turn {
			rep, err = s.Replicate(ctx, j.Rule, j.DryRun, j.By, func(p meta.JobProgress) { s.setProgress(j.ID, p) })
			<-s.replicating
		}
		report, j.Summary = rep, rep.String()
		if err == nil && rep.Failed > 0 {
			j.Alarm = fmt.Sprintf("%d of %d images could not be copied", rep.Failed, rep.Picked)
		}
	case JobScan:
		var rep ScanReport
		rep, err = s.ScanAll(ctx, j.By, func(p meta.JobProgress) { s.setProgress(j.ID, p) })
		report, j.Summary = rep, rep.String()
		var alarms []string
		if rep.DBError != "" {
			alarms = append(alarms, "the vulnerability DB could not be updated: "+rep.DBError)
		}
		if rep.Failed > 0 {
			alarms = append(alarms, fmt.Sprintf("%d of %d images could not be scanned", rep.Failed, rep.Images))
		}
		if err == nil {
			j.Alarm = strings.Join(alarms, "; ")
		}
	}
	if b, merr := json.Marshal(report); merr == nil {
		j.Report = b
	}
	now := s.now().UTC()
	j.Finished, j.Status = &now, meta.JobDone
	if err != nil {
		s.jobMu.Lock()
		by, stopped := s.cancelledBy[j.ID]
		s.jobMu.Unlock()
		if stopped && errors.Is(err, context.Canceled) {
			err = fmt.Errorf("stopped by %s", by)
		}
		j.Status, j.Error = meta.JobFailed, err.Error()
		s.cfg.Log.Warn("registry: a job failed", "job", j.ID, "kind", j.Kind, "err", err)
	}
	end()
	if err := s.cfg.DB.PutJob(j); err != nil {
		s.cfg.Log.Warn("registry: recording a job", "job", j.ID, "err", err)
	}
}
