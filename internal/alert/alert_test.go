package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

type recorder struct {
	mu   sync.Mutex
	sent []Notification
}

func (r *recorder) Name() string { return "test" }
func (r *recorder) Send(_ context.Context, n Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, n)
	return nil
}
func (r *recorder) wait(t *testing.T, want int) []Notification {
	t.Helper()
	for i := 0; i < 200; i++ {
		r.mu.Lock()
		n := len(r.sent)
		r.mu.Unlock()
		if n >= want {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Notification(nil), r.sent...)
}

// flaky is a channel whose first sends fail.
type flaky struct {
	mu    sync.Mutex
	fails int
	tries int
}

func (f *flaky) Name() string { return "flaky" }
func (f *flaky) Send(context.Context, Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.fails > 0 {
		f.fails--
		return errors.New("try later")
	}
	return nil
}

func TestFailedNotificationsAreSentAgain(t *testing.T) {
	for _, c := range []struct {
		fails, tries int
		lost         bool
	}{{0, 1, false}, {2, 3, false}, {5, 3, true}} {
		f := &flaky{fails: c.fails}
		m := NewManager(0, nil, f)
		m.Retry = []time.Duration{time.Millisecond, time.Millisecond}
		m.Observe("prod", broken(), time.Now())
		var sent []Delivery
		for i := 0; i < 400 && len(sent) == 0; i++ {
			time.Sleep(5 * time.Millisecond)
			sent = m.State().Deliveries
		}
		f.mu.Lock()
		tries := f.tries
		f.mu.Unlock()
		if len(sent) != 1 || (sent[0].Error != "") != c.lost || tries != c.tries {
			t.Errorf("a channel failing %d times: %d tries, deliveries %+v", c.fails, tries, sent)
		}
	}
}

func broken() *protocol.Snapshot {
	return &protocol.Snapshot{
		Nodes: []protocol.Node{{Name: "n1", Ready: false, Pressure: []string{"MemoryPressure"}}, {Name: "n2", Ready: true}},
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "crash", Phase: "Running", Reason: "CrashLoopBackOff", Restarts: 4, Total: 1},
			{Namespace: "a", Name: "starting", Phase: "Pending", Reason: "ContainerCreating", Total: 1},
		},
		Workloads: []protocol.Workload{{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 2, Ready: 1}},
	}
}

func TestProblemsMustLastBeforeAnyoneIsTold(t *testing.T) {
	rec := &recorder{}
	m := NewManager(2*time.Minute, nil, rec)
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)

	m.Observe("prod", broken(), start)
	m.Observe("prod", broken(), start.Add(time.Minute))
	if st := m.State(); len(st.Active) != 3 || len(rec.wait(t, 0)) != 0 {
		t.Fatalf("active=%d sent=%d; nothing should be sent yet", len(st.Active), len(rec.sent))
	}

	m.Observe("prod", broken(), start.Add(2*time.Minute))
	sent := rec.wait(t, 1)
	if len(sent) != 1 || len(sent[0].Firing) != 3 || sent[0].Firing[0].Kind != "NodeNotReady" {
		t.Fatalf("expected one digest with 3 problems, critical first: %+v", sent)
	}
	if !strings.Contains(sent[0].Title(), "3 new problem") {
		t.Errorf("title: %q", sent[0].Title())
	}

	// The crash-looping pod recovers; only it is reported as resolved.
	fixed := broken()
	fixed.Pods = fixed.Pods[1:]
	m.Observe("prod", fixed, start.Add(3*time.Minute))
	sent = rec.wait(t, 2)
	if len(sent) != 2 || len(sent[1].Resolved) != 1 || sent[1].Resolved[0].Object != "crash" || len(sent[1].Firing) != 0 {
		t.Fatalf("resolved: %+v", sent)
	}
	if st := m.State(); len(st.Active) != 2 || len(st.Recent) == 0 {
		t.Errorf("state: %+v", st)
	}
}

func TestShortProblemsAreNotSent(t *testing.T) {
	rec := &recorder{}
	m := NewManager(2*time.Minute, nil, rec)
	start := time.Now()
	m.Observe("prod", broken(), start)
	m.Observe("prod", &protocol.Snapshot{}, start.Add(30*time.Second))
	if sent := rec.wait(t, 0); len(sent) != 0 {
		t.Errorf("a problem shorter than the wait was sent: %+v", sent)
	}
	if st := m.State(); len(st.Active) != 0 {
		t.Errorf("still active: %+v", st.Active)
	}
}

func TestAgentOffline(t *testing.T) {
	rec := &recorder{}
	m := NewManager(0, nil, rec)
	now := time.Now()
	m.Observe("prod", &protocol.Snapshot{}, now)
	m.AgentStatus("prod", false, now.Add(-2*time.Minute), now)
	// A snapshot does not clear an offline alert; only the agent does.
	m.Observe("prod", &protocol.Snapshot{}, now)
	m.AgentStatus("prod", true, now, now.Add(time.Minute))
	sent := rec.wait(t, 2)
	if len(sent) != 2 || sent[0].Firing[0].Kind != "AgentOffline" || sent[1].Resolved[0].Kind != "AgentOffline" {
		t.Errorf("sent: %+v", sent)
	}
}

func TestTeamsAndWebhookPayloads(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
	}))
	defer srv.Close()
	n := Notification{Cluster: "prod", URL: "https://panel.example.org/", Firing: []Alert{{Kind: "NodeNotReady", Object: "n1", Detail: "NotReady"}}}
	if err := (Teams{URL: srv.URL}).Send(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if err := (Webhook{URL: srv.URL}).Send(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	var card struct {
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Body []struct{ Text string } `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	json.Unmarshal([]byte(bodies[0]), &card)
	if len(card.Attachments) != 1 || card.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" ||
		!strings.Contains(card.Attachments[0].Content.Body[1].Text, "Node not ready n1") {
		t.Errorf("teams card: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `"cluster":"prod"`) || !strings.Contains(bodies[1], `"resolved":[]`) {
		t.Errorf("webhook: %s", bodies[1])
	}
}

func TestWhatCountsAsAProblem(t *testing.T) {
	m := NewManager(time.Hour, nil)
	m.Observe("prod", &protocol.Snapshot{
		Nodes: []protocol.Node{{Name: "n1", Ready: true, Pressure: []string{"DiskPressure"}}, {Name: "n2", Ready: true}},
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "init-loop", Phase: "Pending", Reason: "Init:CrashLoopBackOff", Owner: "Deployment/web"},
			{Namespace: "a", Name: "job-pod-done", Phase: "Failed", Reason: "Error", Owner: "Job/backup-1"},
			{Namespace: "a", Name: "job-pod-looping", Phase: "Running", Reason: "CrashLoopBackOff", Owner: "Job/backup-2"},
			// Its Deployment already runs another pod in its place.
			{Namespace: "a", Name: "evicted", Phase: "Failed", Reason: "Evicted", Owner: "Deployment/web"},
			{Namespace: "a", Name: "evicted-alone", Phase: "Failed", Reason: "Evicted"},
		},
		Jobs: []protocol.Job{
			{Namespace: "a", Name: "backup-1", Completions: 1, Failed: 3, Condition: "Failed"},
			{Namespace: "a", Name: "backup-2", Completions: 1, Failed: 1}, // between retries
		},
	}, time.Now())
	var got []string
	for _, a := range m.State().Active {
		got = append(got, a.Kind+" "+a.Object)
	}
	want := "JobFailed backup-1,NodePressure n1,PodFailing evicted-alone,PodFailing init-loop,PodFailing job-pod-looping"
	sort.Strings(got)
	if strings.Join(got, ",") != want {
		t.Errorf("active:\n got %s\nwant %s", strings.Join(got, ","), want)
	}
}

// A channel that is off is not listed and gets nothing. Problems that came
// due meanwhile wait, and go out once it is turned on.
func TestSwitchableChannel(t *testing.T) {
	rec := &recorder{}
	sw := NewSwitchable("email")
	m := NewManager(0, nil, sw)
	if ch := m.Channels(); len(ch) != 0 {
		t.Fatalf("an off channel is listed: %v", ch)
	}
	now := time.Now()
	m.Observe("prod", broken(), now) // due at once, while nobody listens
	for _, a := range m.State().Active {
		if a.Notified {
			t.Fatalf("notified with no channel on: %+v", a)
		}
	}
	sw.Set(rec)
	if ch := m.State().Channels; len(ch) != 1 || ch[0] != "email" {
		t.Fatalf("channels: %v", ch)
	}
	m.Observe("prod", broken(), now.Add(15*time.Second))
	m.Observe("prod", &protocol.Snapshot{}, now.Add(time.Minute))
	sent := rec.wait(t, 2)
	if len(sent) != 2 || len(sent[0].Firing) != 3 || len(sent[1].Resolved) != 3 {
		t.Errorf("sent: %+v", sent)
	}
	sw.Set(nil)
	if err := sw.Send(context.Background(), Notification{}); err == nil {
		t.Error("an off channel sent something")
	}
}

func TestVolumesAndCertificates(t *testing.T) {
	m := NewManager(0, nil)
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	gib := int64(1 << 30)
	snap := &protocol.Snapshot{
		VolumeClaims: []protocol.VolumeClaim{
			{Namespace: "a", Name: "ok", Phase: "Bound", UsedBytes: 5 * gib, CapacityBytes: 10 * gib},
			{Namespace: "a", Name: "filling", Phase: "Bound", UsedBytes: 9 * gib, CapacityBytes: 10 * gib},
			{Namespace: "a", Name: "full", Phase: "Bound", UsedBytes: 98 * gib / 10, CapacityBytes: 10 * gib},
			{Namespace: "a", Name: "files", Phase: "Bound", UsedBytes: gib, CapacityBytes: 10 * gib, InodesUsed: 96, Inodes: 100},
			{Namespace: "a", Name: "unknown", Phase: "Bound"},
		},
		Certificates: []protocol.Certificate{
			{Namespace: "a", Secret: "fine", NotAfter: now.Add(60 * 24 * time.Hour)},
			{Namespace: "a", Secret: "soon", Subject: "example.org", NotAfter: now.Add(10*24*time.Hour + time.Hour)},
			{Namespace: "a", Secret: "very-soon", NotAfter: now.Add(5 * time.Hour)},
			{Namespace: "a", Secret: "gone", NotAfter: now.Add(-49 * time.Hour)},
			{Namespace: "a", Secret: "unreadable", Error: "no tls.crt"},
		},
	}
	m.Observe("prod", snap, now)
	var got []string
	for _, a := range m.State().Active {
		got = append(got, a.Severity+" "+a.Object+": "+a.Detail)
	}
	sort.Strings(got)
	want := []string{
		"critical files: 96% of inodes used (96 of 100 files)",
		"critical full: 98% full (9.8 GiB of 10 GiB)",
		"critical gone: expired 2 days ago (2026-09-28 09:00 UTC)",
		"critical very-soon: expires in 5 hours (2026-09-30 15:00 UTC)",
		"warning filling: 90% full (9.0 GiB of 10 GiB)",
		"warning soon: example.org: expires in 10 days (2026-10-10 11:00 UTC)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("alerts:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestNodeDisks(t *testing.T) {
	gib := int64(1 << 30)
	snap := &protocol.Snapshot{Nodes: []protocol.Node{
		{Name: "ok", Ready: true, Disk: &protocol.Disk{UsedBytes: 50 * gib, CapacityBytes: 100 * gib}},
		{Name: "filling", Ready: true, Disk: &protocol.Disk{UsedBytes: 82 * gib, CapacityBytes: 100 * gib}},
		{Name: "images", Ready: true, Disk: &protocol.Disk{UsedBytes: 10 * gib, CapacityBytes: 100 * gib},
			ImageDisk: &protocol.Disk{UsedBytes: 46 * gib, CapacityBytes: 50 * gib}},
		{Name: "files", Ready: true, Disk: &protocol.Disk{UsedBytes: gib, CapacityBytes: 100 * gib, InodesUsed: 85, Inodes: 100}},
		{Name: "unknown", Ready: true},
	}}
	got := func(m *Manager) string {
		m.Observe("prod", snap, time.Now())
		var out []string
		for _, a := range m.State().Active {
			if a.Kind != "NodeDiskFilling" {
				t.Errorf("unexpected alert %+v", a)
			}
			out = append(out, a.Severity+" "+a.Object+": "+a.Detail)
		}
		sort.Strings(out)
		return strings.Join(out, "\n")
	}
	want := strings.Join([]string{
		"critical images (images): 92% full (46 GiB of 50 GiB)",
		"warning files: 85% of inodes used (85 of 100 files)",
		"warning filling: 82% full (82 GiB of 100 GiB)",
	}, "\n")
	if s := got(NewManager(0, nil)); s != want {
		t.Errorf("alerts:\n%s\nwant:\n%s", s, want)
	}
	// The levels can be moved.
	m := NewManager(0, nil)
	m.NodeDiskWarning, m.NodeDiskCritical = 90, 95
	if s := got(m); s != "warning images (images): 92% full (46 GiB of 50 GiB)" {
		t.Errorf("with levels 90 and 95:\n%s", s)
	}
}

func TestChecksBelongToNoCluster(t *testing.T) {
	rec := &recorder{}
	m := NewManager(0, nil, rec)
	now := time.Now()
	m.Observe("prod", broken(), now)
	m.ObserveChecks([]Alert{{Kind: "URLDown", Severity: critical, Object: "web", Detail: "503 Service Unavailable"}}, now)
	sent := rec.wait(t, 2)
	if len(sent) != 2 {
		t.Fatalf("sent %d notifications", len(sent))
	}
	var checks Notification
	for _, n := range sent {
		if n.Cluster == "" {
			checks = n
		}
	}
	if checks.Title() != "Kartal Gözü: 1 new problem(s)" || len(checks.Firing) != 1 {
		t.Errorf("the checks' notification: %q %+v", checks.Title(), checks)
	}
	// The checks' alerts are replaced by the next round only; a cluster's
	// snapshot leaves them alone.
	m.Observe("prod", &protocol.Snapshot{}, now)
	if n := m.ActiveCount("", nil); n != 1 {
		t.Errorf("the check's alert went with prod's: %d", n)
	}
	m.ObserveChecks(nil, now)
	if n := m.ActiveCount("", nil); n != 0 {
		t.Errorf("still active: %d", n)
	}
}

func TestSilencedProblemsWait(t *testing.T) {
	rec := &recorder{}
	m := NewManager(2*time.Minute, nil, rec)
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	// Namespace a is silenced until ten minutes in: the pod and the
	// workload in it wait; the node, in no namespace, does not. (The state
	// asks at the real time, so the silence is a switch here.)
	until := start.Add(10 * time.Minute)
	on := true
	m.Silenced = func(a Alert, _ time.Time) bool { return on && a.Namespace == "a" }

	m.Observe("prod", broken(), start)
	m.Observe("prod", broken(), start.Add(3*time.Minute))
	sent := rec.wait(t, 1)
	if len(sent) != 1 || len(sent[0].Firing) != 1 || sent[0].Firing[0].Kind != "NodeNotReady" {
		t.Fatalf("only the node should be told: %+v", sent)
	}
	silenced := 0
	for _, a := range m.State().Active {
		if a.Silenced {
			silenced++
		}
	}
	if silenced != 2 {
		t.Errorf("%d alerts shown as silenced, want 2", silenced)
	}

	// The workload recovers within the silence: nobody hears of it.
	fixed := broken()
	fixed.Workloads = nil
	m.Observe("prod", fixed, start.Add(5*time.Minute))
	// The pod still fails when the silence ends: it is told then.
	on = false
	m.Observe("prod", fixed, until)
	sent = rec.wait(t, 2)
	if len(sent) != 2 || len(sent[1].Firing) != 1 || sent[1].Firing[0].Object != "crash" || len(sent[1].Resolved) != 0 {
		t.Fatalf("after the silence: %+v", sent)
	}

	// A problem told before a silence starts keeps its "resolved" message.
	m.Silenced = func(Alert, time.Time) bool { return true }
	m.Observe("prod", &protocol.Snapshot{}, until.Add(time.Minute))
	sent = rec.wait(t, 3)
	if len(sent) != 3 || len(sent[2].Resolved) != 2 || len(sent[2].Firing) != 0 {
		t.Errorf("resolved within a silence: %+v", sent)
	}
}

func TestWarningsThatBecomeCriticalAreToldAgain(t *testing.T) {
	rec := &recorder{}
	m := NewManager(time.Minute, nil, rec)
	m.AfterCritical = 10 * time.Second
	start := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	web := func(ready int32) *protocol.Snapshot {
		return &protocol.Snapshot{Workloads: []protocol.Workload{{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 2, Ready: ready}}}
	}
	m.Observe("prod", web(1), start)
	m.Observe("prod", web(1), start.Add(time.Minute))
	if sent := rec.wait(t, 1); len(sent) != 1 || sent[0].Firing[0].Severity != warning {
		t.Fatalf("the warning: %+v", sent)
	}
	// Nothing ready any more: critical, told once that has lasted too.
	m.Observe("prod", web(0), start.Add(2*time.Minute))
	m.Observe("prod", web(0), start.Add(2*time.Minute+5*time.Second))
	if sent := rec.wait(t, 1); len(sent) != 1 {
		t.Fatalf("told of a critical problem at once: %+v", sent)
	}
	m.Observe("prod", web(0), start.Add(2*time.Minute+10*time.Second))
	sent := rec.wait(t, 2)
	if len(sent) != 2 || len(sent[1].Firing) != 1 || sent[1].Firing[0].Severity != critical ||
		sent[1].Firing[0].Detail != "0 of 2 ready (now critical)" || len(sent[1].Resolved) != 0 {
		t.Fatalf("the warning that became critical: %+v", sent)
	}
	if a := m.State().Active[0]; a.Detail != "0 of 2 ready" || a.Escalated != nil || !a.Since.Equal(start) {
		t.Errorf("the alert afterwards: %+v", a)
	}
	// Told once: it stays critical, gets better and worse for a moment.
	m.Observe("prod", web(0), start.Add(3*time.Minute))
	m.Observe("prod", web(1), start.Add(4*time.Minute))
	m.Observe("prod", web(0), start.Add(5*time.Minute))
	m.Observe("prod", web(1), start.Add(5*time.Minute+5*time.Second))
	m.Observe("prod", web(1), start.Add(6*time.Minute))
	if sent := rec.wait(t, 2); len(sent) != 2 {
		t.Fatalf("told again: %+v", sent[2:])
	}
	m.Observe("prod", web(2), start.Add(7*time.Minute))
	if sent := rec.wait(t, 3); len(sent) != 3 || len(sent[2].Resolved) != 1 {
		t.Errorf("resolved: %+v", sent)
	}
}

func TestCriticalProblemsAreToldSooner(t *testing.T) {
	rec := &recorder{}
	m := NewManager(2*time.Minute, nil, rec)
	m.AfterCritical = 30 * time.Second
	start := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)

	m.Observe("prod", broken(), start)
	m.Observe("prod", broken(), start.Add(30*time.Second))
	sent := rec.wait(t, 1)
	if len(sent) != 1 || len(sent[0].Firing) != 1 || sent[0].Firing[0].Kind != "NodeNotReady" {
		t.Fatalf("after 30s only the critical problem is told: %+v", sent)
	}
	m.Observe("prod", broken(), start.Add(2*time.Minute))
	sent = rec.wait(t, 2)
	if len(sent) != 2 || len(sent[1].Firing) != 2 {
		t.Fatalf("after 2m the warnings follow: %+v", sent)
	}
	if st := m.State(); st.After != "2m0s" || st.AfterCritical != "30s" {
		t.Errorf("state: after %q, critical %q", st.After, st.AfterCritical)
	}
	// Without a time of their own, critical problems wait as the others.
	if st := NewManager(time.Minute, nil).State(); st.AfterCritical != "" {
		t.Errorf("critical wait shown without one: %q", st.AfterCritical)
	}
}

func TestAlertsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.json")
	known := func(c string) bool { return c == "prod" }
	start := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)

	rec := &recorder{}
	m := NewManager(time.Minute, nil, rec)
	if err := m.Restore(path, known, start); err != nil {
		t.Fatalf("no file yet: %v", err)
	}
	m.Observe("prod", broken(), start)
	m.Observe("gone", broken(), start)
	m.Observe("prod", broken(), start.Add(time.Minute))
	rec.wait(t, 1)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	// Nothing changed since: the file is left alone.
	os.Remove(path)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("saved again though nothing changed")
	}
	down := []Alert{{Kind: "URLDown", Severity: critical, Object: "web", Detail: "503"}, {Kind: "URLDown", Severity: critical, Object: "api", Detail: "503"}}
	m.ObserveChecks(down, start.Add(90*time.Second))
	m.ObserveChecks(down, start.Add(3*time.Minute))
	m.ObserveRollouts("prod", map[string]string{"shop\x00Deployment/web": "1 of 3 ready after 10m"}, start.Add(3*time.Minute))
	rec.wait(t, 2)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}

	// After a restart the problems are there since they began, those told
	// are not told again, and a cluster the server no longer has is gone.
	rec2 := &recorder{}
	m2 := NewManager(time.Minute, nil, rec2)
	again := start.Add(4 * time.Minute)
	if err := m2.Restore(path, known, again); err != nil {
		t.Fatal(err)
	}
	// A stuck rollout is followed in memory: it cannot be found again.
	st := m2.State()
	if len(st.Active) != 5 || m2.ActiveCount("gone", nil) != 0 || m2.ActiveCount("", nil) != 2 {
		t.Fatalf("restored: %+v", st.Active)
	}
	for _, a := range st.Active {
		if a.Kind == RolloutStuck {
			t.Errorf("a stuck rollout was restored: %+v", a)
		}
	}
	for _, a := range st.Active {
		if a.Cluster == "prod" && (!a.Since.Equal(start) || !a.Notified) {
			t.Errorf("restored %s: since %s, notified %v", a.Kind, a.Since, a.Notified)
		}
	}
	if len(st.Recent) == 0 {
		t.Error("the recent ones were not restored")
	}
	m2.Observe("prod", broken(), start.Add(5*time.Minute))
	// The checks run one after another: the first to answer does not end
	// the alert of the one still to run, and once that answered too it is
	// as it was. One that then answers well is resolved at once.
	m2.ObserveChecks(down[:1], again.Add(10*time.Second))
	m2.ObserveChecks(down, again.Add(20*time.Second))
	if sent := rec2.wait(t, 0); len(sent) != 0 || m2.ActiveCount("", nil) != 2 {
		t.Fatalf("told again after the restart: %+v, %d of the checks' alerts", sent, m2.ActiveCount("", nil))
	}
	m2.ObserveChecks(down[:1], again.Add(30*time.Second))
	if sent := rec2.wait(t, 1); len(sent) != 1 || len(sent[0].Resolved) != 1 || sent[0].Resolved[0].Object != "api" {
		t.Fatalf("a check that answers again after the restart: %+v", sent)
	}
	// What ended while the server was away is resolved by the next snapshot.
	fixed := broken()
	fixed.Nodes[0].Ready, fixed.Nodes[0].Pressure = true, nil
	m2.Observe("prod", fixed, start.Add(6*time.Minute))
	sent := rec2.wait(t, 2)
	if len(sent) != 2 || len(sent[1].Resolved) != 1 || sent[1].Resolved[0].Kind != "NodeNotReady" {
		t.Errorf("resolved after the restart: %+v", sent)
	}

	// A check that never ran again is given up after a while.
	m4 := NewManager(time.Minute, nil, &recorder{})
	if err := m4.Restore(path, known, again); err != nil {
		t.Fatal(err)
	}
	m4.ObserveChecks(nil, again.Add(restoreHold-time.Second))
	if n := m4.ActiveCount("", nil); n != 2 {
		t.Errorf("%d of the checks' alerts while they are kept", n)
	}
	m4.ObserveChecks(nil, again.Add(restoreHold))
	if n := m4.ActiveCount("", nil); n != 0 {
		t.Errorf("%d of the checks' alerts were kept for good", n)
	}

	// A file that cannot be read is an error, and nothing is restored.
	os.WriteFile(path, []byte("{not json"), 0o600)
	m3 := NewManager(time.Minute, nil)
	if err := m3.Restore(path, known, start); err == nil || len(m3.State().Active) != 0 {
		t.Errorf("a broken file: %v, %d active", err, len(m3.State().Active))
	}
}

func TestLogAlertsAreKeptApartFromChecks(t *testing.T) {
	m := NewManager(0, nil, &recorder{})
	now := time.Now()
	m.ObserveLogs([]Alert{{Severity: warning, Object: "Database errors", Detail: "42 in 5m0s, more than 20"}}, nil, now)
	m.ObserveChecks([]Alert{{Kind: "URLDown", Severity: critical, Object: "web", Detail: "503"}}, now)
	if n := m.ActiveCount("", nil); n != 2 {
		t.Fatalf("%d alerts of no cluster, want 2", n)
	}
	// Each round replaces its own alerts only.
	m.ObserveChecks(nil, now)
	if n := m.ActiveCount("", func(a Alert) bool { return a.Kind == LogLimit }); n != 1 {
		t.Errorf("the checks' round took the log rule's alert: %d", n)
	}
	// A rule that could not be counted keeps its alert, and gets none.
	m.ObserveLogs(nil, []string{"Database errors", "Timeouts"}, now)
	if n := m.ActiveCount("", nil); n != 1 {
		t.Errorf("%d alerts while the rules cannot be counted, want the one there was", n)
	}
	m.ObserveLogs(nil, nil, now)
	if n := m.ActiveCount("", nil); n != 0 {
		t.Errorf("still active: %d", n)
	}
}

func TestTeamsMentions(t *testing.T) {
	people, err := ParseMentions(" Ada Lovelace <ada@example.org>, grace@example.org ,, 3f2504e0-4f89-11d3-9a0c-0305e82c3301 ")
	if err != nil || len(people) != 3 || people[0] != (Mention{ID: "ada@example.org", Name: "Ada Lovelace"}) ||
		people[1] != (Mention{ID: "grace@example.org", Name: "grace"}) || people[2].ID != people[2].Name {
		t.Fatalf("parsed %+v, %v", people, err)
	}
	if twice, err := ParseMentions("ada@example.org, Ada <ADA@example.org>"); err != nil || len(twice) != 1 {
		t.Errorf("the same person twice: %+v, %v", twice, err)
	}
	many := ""
	for i := 0; i < 21; i++ {
		many += fmt.Sprintf("p%d@example.org,", i)
	}
	for _, bad := range []string{"Ada <>", "two words", "A<b> <ada@example.org>", "ada@one.example.org, ada@two.example.org", many} {
		if _, err := ParseMentions(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if none, err := ParseMentions(""); err != nil || len(none) != 0 {
		t.Errorf("nobody: %+v, %v", none, err)
	}

	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
	}))
	defer srv.Close()
	teams := Teams{URL: srv.URL, Mentions: people[:2]}
	critAlert := Alert{Kind: "NodeNotReady", Severity: critical, Object: "n1", Detail: "NotReady"}
	warnAlert := Alert{Kind: "PodFailing", Severity: warning, Namespace: "a", Object: "p", Detail: "CrashLoopBackOff"}
	send := func(tm Teams, n Notification) string {
		t.Helper()
		if err := tm.Send(context.Background(), n); err != nil {
			t.Fatal(err)
		}
		return bodies[len(bodies)-1]
	}
	// A critical problem that starts names the people, each <at> text with
	// the entity that makes it a mention.
	body := send(teams, Notification{Cluster: "prod", Firing: []Alert{warnAlert, critAlert}})
	var card struct {
		Attachments []struct {
			Content struct {
				Body    []struct{ Text string } `json:"body"`
				MSTeams struct {
					Entities []struct {
						Type, Text string
						Mentioned  struct{ ID, Name string }
					} `json:"entities"`
				} `json:"msteams"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(body), &card); err != nil {
		t.Fatal(err)
	}
	c := card.Attachments[0].Content
	if len(c.MSTeams.Entities) != 2 || c.MSTeams.Entities[0].Type != "mention" || c.MSTeams.Entities[0].Text != "<at>Ada Lovelace</at>" ||
		c.MSTeams.Entities[0].Mentioned.ID != "ada@example.org" || c.Body[len(c.Body)-1].Text != "<at>Ada Lovelace</at> <at>grace</at>" {
		t.Errorf("mentions: %s", body)
	}
	// Warnings alone, and what was resolved, name nobody; unless every
	// problem is to.
	for name, n := range map[string]Notification{
		"a warning": {Cluster: "prod", Firing: []Alert{warnAlert}},
		"resolved":  {Cluster: "prod", Resolved: []Alert{critAlert}},
	} {
		if body := send(teams, n); strings.Contains(body, `"msteams"`) || strings.Contains(body, "grace") {
			t.Errorf("%s mentions people: %s", name, body)
		}
	}
	teams.MentionAll = true
	if body := send(teams, Notification{Cluster: "prod", Firing: []Alert{warnAlert}}); !strings.Contains(body, `"msteams"`) || !strings.Contains(body, "grace@example.org") {
		t.Errorf("a warning, with everything mentioned: %s", body)
	}
	if body := send(teams, Notification{Cluster: "prod", Resolved: []Alert{critAlert}}); strings.Contains(body, `"msteams"`) {
		t.Errorf("resolved, with everything mentioned: %s", body)
	}
}

func TestAgentVersionAlert(t *testing.T) {
	rec := &recorder{}
	m := NewManager(0, nil, rec)
	now := time.Now()
	m.ObserveAgentVersion("prod", "the agent is 72a9486, the server 7804c92", now)
	// A snapshot does not clear it; only the comparison does.
	m.Observe("prod", &protocol.Snapshot{}, now.Add(time.Second))
	if n := m.ActiveCount("prod", func(Alert) bool { return true }); n != 1 {
		t.Fatalf("%d active, want 1", n)
	}
	m.ObserveAgentVersion("prod", "", now.Add(time.Minute))
	sent := rec.wait(t, 2)
	if len(sent) != 2 || sent[0].Firing[0].Kind != AgentVersion || sent[0].Firing[0].Severity != warning ||
		sent[1].Resolved[0].Kind != AgentVersion {
		t.Fatalf("sent: %+v", sent)
	}
	if s := sent[0].Firing[0].Summary(); s != "Agent version differs prod: the agent is 72a9486, the server 7804c92" {
		t.Errorf("summary %q", s)
	}
}

// The image registry's alerts belong to no cluster either, and neither the
// checks nor the log rules replace them; while it cannot be reached, its
// other alerts stay.
func TestRegistryAlertsAreTheirOwn(t *testing.T) {
	m := NewManager(time.Minute, nil)
	now := time.Now()
	quota := Alert{Kind: RegistryQuota, Severity: warning, Object: "team-a", Detail: "9.1 GiB of 10.0 GiB (91%)"}
	m.ObserveRegistry([]Alert{quota}, now)
	m.ObserveChecks(nil, now)
	m.ObserveLogs(nil, nil, now)
	if n := m.ActiveCount("", nil); n != 1 {
		t.Fatalf("after the checks and the log rules: %d", n)
	}
	m.ObserveRegistry([]Alert{{Kind: RegistryUnreachable, Severity: critical, Object: "kartal-registry", Detail: "refused"}}, now)
	if n := m.ActiveCount("", nil); n != 2 {
		t.Errorf("while unreachable: %d", n)
	}
	m.ObserveRegistry(nil, now)
	if n := m.ActiveCount("", nil); n != 0 {
		t.Errorf("all well: %d", n)
	}
}
