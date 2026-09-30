package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "init-loop", Phase: "Pending", Reason: "Init:CrashLoopBackOff", Owner: "Deployment/web"},
			{Namespace: "a", Name: "job-pod-done", Phase: "Failed", Reason: "Error", Owner: "Job/backup-1"},
			{Namespace: "a", Name: "job-pod-looping", Phase: "Running", Reason: "CrashLoopBackOff", Owner: "Job/backup-2"},
			{Namespace: "a", Name: "evicted", Phase: "Failed", Reason: "Evicted", Owner: "Deployment/web"},
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
	want := "JobFailed backup-1,PodFailing evicted,PodFailing init-loop,PodFailing job-pod-looping"
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
