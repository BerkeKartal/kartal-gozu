package registry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// wait waits for a job to finish.
func (e *env) wait(id string) meta.Job {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		j, ok := e.db.Job(id)
		if ok && j.Status != meta.JobRunning {
			return j
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("job %s: %+v", id, j)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestJobs(t *testing.T) {
	e := newEnv(t)
	if _, err := e.reg.StartJob("compact", false, "root"); !errors.Is(err, ErrJob) {
		t.Errorf("an unknown job: %v", err)
	}
	if _, err := e.reg.StartJob(JobVerify, true, "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a dry run of a check: %v", err)
	}
	// One of a kind at a time: a collection held up blocks the next.
	e.reg.gcMu.Lock()
	j, err := e.reg.StartJob(JobGC, true, "root")
	if err != nil || j.Status != meta.JobRunning {
		t.Fatalf("start: %+v %v", j, err)
	}
	if _, err := e.reg.StartJob(JobGC, false, "root"); !errors.Is(err, ErrRunning) || !strings.Contains(err.Error(), j.ID) {
		t.Errorf("a second collection: %v", err)
	}
	if v, err := e.reg.StartJob(JobVerify, false, "root"); err != nil {
		t.Errorf("another kind meanwhile: %v", err)
	} else if done := e.wait(v.ID); done.Status != meta.JobDone || done.Alarm != "" {
		t.Errorf("the check: %+v", done)
	}
	e.reg.gcMu.Unlock()
	done := e.wait(j.ID)
	var rep GCReport
	if json.Unmarshal(done.Report, &rep); done.Status != meta.JobDone || !rep.DryRun || done.Finished == nil || !strings.Contains(done.Summary, "collected") {
		t.Errorf("the dry run: %+v %s", done, done.Report)
	}
	// The newest first: the check started after the collection.
	if jobs := e.db.Jobs(0); len(jobs) != 2 || jobs[1].ID != j.ID {
		t.Errorf("jobs: %+v", jobs)
	}
}

func TestSchedules(t *testing.T) {
	e := newEnv(t)
	// A job left running by a registry that stopped.
	e.db.PutJob(meta.Job{ID: "abandoned", Kind: JobGC, Status: meta.JobRunning, Started: time.Now().Add(-time.Hour)})
	// Started with its schedules stopped, so that the test runs them.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.reg.Start(ctx)
	if j, _ := e.db.Job("abandoned"); j.Status != meta.JobFailed || j.Error == "" {
		t.Errorf("a job the registry stopped in: %+v", j)
	}
	scs := e.db.Schedules()
	if len(scs) != 2 || scs[0].Kind != JobGC || scs[0].Cron != "0 3 * * *" || !scs[0].Enabled || scs[1].Kind != JobVerify {
		t.Fatalf("the default schedules: %+v", scs)
	}
	if _, err := e.reg.SetSchedule(JobGC, "every night", true, "root"); !errors.Is(err, ErrSchedule) {
		t.Errorf("a schedule that cannot be read: %v", err)
	}
	if _, err := e.reg.SetSchedule("compact", "0 3 * * *", true, "root"); !errors.Is(err, ErrJob) {
		t.Errorf("an unknown job's schedule: %v", err)
	}
	if _, err := e.reg.SetSchedule(JobVerify, "0 4 * * 0", false, "root"); err != nil {
		t.Fatal(err)
	}
	// A day later the collection is due, once; the check is off.
	later := time.Now().Add(25 * time.Hour)
	e.reg.now = func() time.Time { return later }
	before := len(e.db.Jobs(0))
	e.reg.RunDue()
	jobs := e.db.Jobs(0)
	if len(jobs) != before+1 || jobs[0].Kind != JobGC || jobs[0].By != ScheduledBy {
		t.Fatalf("after a day: %+v", jobs)
	}
	e.wait(jobs[0].ID)
	e.reg.RunDue()
	if n := len(e.db.Jobs(0)); n != before+1 {
		t.Errorf("run again at once: %d jobs", n)
	}
	if sc := e.db.Schedules()[0]; sc.Last == nil || !sc.Last.Equal(later.UTC()) {
		t.Errorf("the schedule's last run: %+v", sc)
	}
	if ev := e.db.Events(nil, 0); !hasEvent(ev, "schedule", "verify: 0 4 * * 0 (off)") {
		t.Errorf("the log: %+v", ev)
	}
}

func hasEvent(events []meta.Event, action, detail string) bool {
	for _, e := range events {
		if e.Action == action && e.Detail == detail {
			return true
		}
	}
	return false
}

func TestJobsThroughTheAdminAPI(t *testing.T) {
	e := newEnv(t)
	e.reg.Start(context.Background())
	a := e.do("POST", "/admin/v1/jobs", "admin-secret", []byte(`{"kind":"verify"}`), UserHeader, "ayse")
	var j meta.Job
	if json.Unmarshal(a.body, &j); a.code != 202 || j.By != "ayse" {
		t.Fatalf("start: %d %s", a.code, a.body)
	}
	e.wait(j.ID)
	if a := e.do("GET", "/admin/v1/jobs/"+j.ID, "admin-secret", nil); a.code != 200 || !strings.Contains(string(a.body), `"status":"done"`) {
		t.Errorf("the job: %d %s", a.code, a.body)
	}
	if a := e.do("POST", "/admin/v1/jobs", "admin-secret", []byte(`{"kind":"verify","dryRun":true}`)); a.code != 400 {
		t.Errorf("a dry run of a check: %d", a.code)
	}
	if a := e.do("PUT", "/admin/v1/schedules/gc", "admin-secret", []byte(`{"cron":"0 25 * * *","enabled":true}`)); a.code != 400 {
		t.Errorf("an hour that is not: %d %s", a.code, a.body)
	}
	a = e.do("PUT", "/admin/v1/schedules/gc", "admin-secret", []byte(`{"cron":"@daily","enabled":true}`), UserHeader, "ayse")
	var sc ScheduleView
	if json.Unmarshal(a.body, &sc); a.code != 200 || sc.Next == nil || sc.By != "ayse" {
		t.Errorf("a schedule: %d %s", a.code, a.body)
	}
	a = e.do("GET", "/admin/v1/jobs", "admin-secret", nil)
	var list struct {
		Jobs      []meta.Job
		Schedules []ScheduleView
		Zone      string
	}
	if json.Unmarshal(a.body, &list); a.code != 200 || len(list.Jobs) != 1 || len(list.Schedules) != 2 || list.Zone != "Europe/Istanbul" {
		t.Errorf("the jobs: %d %s", a.code, a.body)
	}
}
