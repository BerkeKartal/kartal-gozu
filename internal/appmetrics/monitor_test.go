package appmetrics

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// fakeCluster answers sample commands from values the test sets.
type fakeCluster struct {
	mu      sync.Mutex
	values  map[string][]protocol.Sample // by pod
	asked   []protocol.Command
	offline bool
}

func (f *fakeCluster) pods(cluster string) ([]protocol.Pod, bool) {
	if f.offline {
		return nil, false
	}
	return []protocol.Pod{
		{Namespace: "a", Name: "web-1", Phase: "Running", Owner: "Deployment/web"},
		{Namespace: "a", Name: "web-2", Phase: "Running", Owner: "Deployment/web"},
		{Namespace: "a", Name: "web-old", Phase: "Failed", Owner: "Deployment/web"},
		{Namespace: "a", Name: "other-1", Phase: "Running", Owner: "Deployment/other"},
		{Namespace: "b", Name: "web-1", Phase: "Running", Owner: "Deployment/web"},
	}, true
}

func (f *fakeCluster) ask(_ context.Context, cluster string, cmd protocol.Command) (protocol.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, cmd)
	want := map[string]bool{}
	for _, m := range cmd.Metrics {
		want[m] = true
	}
	var out []protocol.PodSamples
	for _, p := range cmd.Pods {
		ps := protocol.PodSamples{Pod: p}
		for _, s := range f.values[p] {
			if want[s.Name] {
				ps.Samples = append(ps.Samples, s)
			}
		}
		out = append(out, ps)
	}
	b, _ := json.Marshal(out)
	return protocol.Result{OK: true, Output: string(b)}, nil
}

func (f *fakeCluster) set(values map[string][]protocol.Sample) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values = values
}

func requests(ok, failed float64) []protocol.Sample {
	return []protocol.Sample{
		{Name: "http_requests_total", Labels: map[string]string{"code": "200"}, Value: protocol.Number(ok)},
		{Name: "http_requests_total", Labels: map[string]string{"code": "500"}, Value: protocol.Number(failed)},
	}
}

func queue(n float64) protocol.Sample {
	return protocol.Sample{Name: "queue_depth", Value: protocol.Number(n)}
}

func limit(v float64) *float64 { return &v }

func TestWatchesReadRatesValuesAndLimits(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(ctx, settings.Memory{}, log)
	alerts := alert.NewManager(time.Hour, log)
	m := New(keeper, alerts, log)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	f := &fakeCluster{}
	m.Attach(f.pods, f.ask)

	base := settings.Watch{Cluster: "prod", Namespace: "a", Target: "Deployment/web", Port: "9100"}
	add := func(change func(*settings.Watch)) settings.Watch {
		w := base
		change(&w)
		saved, err := m.Add(ctx, w)
		if err != nil {
			t.Fatal(err)
		}
		return saved
	}
	add(func(w *settings.Watch) { w.Name, w.Metric, w.Rate = "requests", "http_requests_total", true })
	add(func(w *settings.Watch) {
		w.Name, w.Metric, w.Rate, w.Labels = "errors", "http_requests_total", true, map[string]string{"code": "500"}
	})
	q := add(func(w *settings.Watch) {
		w.Name, w.Metric, w.Aggregate, w.Above = "queue", "queue_depth", "max", limit(10)
	})
	add(func(w *settings.Watch) { w.Name, w.Metric, w.Target = "nobody", "queue_depth", "Deployment/gone" })
	if _, err := m.Add(ctx, base); err == nil {
		t.Error("a watch without a metric was saved")
	}

	f.set(map[string][]protocol.Sample{
		"web-1": append(requests(100, 10), queue(5)),
		"web-2": append(requests(50, 0), queue(20)),
	})
	m.Round(ctx)
	byName := func() map[string]Status {
		out := map[string]Status{}
		for _, s := range m.List(func(settings.Watch) bool { return true }, 1) {
			out[s.Name] = s
		}
		return out
	}
	st := byName()
	if len(st["requests"].Points) != 0 || st["requests"].Error != "" || st["requests"].Pods != 2 {
		t.Errorf("a rate needs two readings: %+v", st["requests"])
	}
	if p := st["queue"].Points; len(p) != 1 || p[0].V != 20 || st["queue"].Past != "above" {
		t.Errorf("queue: %+v", st["queue"])
	}
	if !strings.Contains(st["nobody"].Error, "no running pod") {
		t.Errorf("nobody: %+v", st["nobody"])
	}
	// One command reads both pods of the endpoint, every metric at once,
	// and never the failed pod.
	if len(f.asked) != 1 || strings.Join(f.asked[0].Pods, ",") != "web-1,web-2" ||
		strings.Join(f.asked[0].Metrics, ",") != "http_requests_total,queue_depth" || f.asked[0].Path != "/metrics" {
		t.Errorf("asked: %+v", f.asked)
	}
	active := func() []alert.Alert {
		var out []alert.Alert
		for _, a := range alerts.State().Active {
			if a.Kind == alert.MetricLimit {
				out = append(out, a)
			}
		}
		return out
	}
	if a := active(); len(a) != 1 || a[0].Object != "queue" || a[0].Cluster != "prod" || !strings.Contains(a[0].Detail, "20 is above 10") {
		t.Fatalf("alerts: %+v", a)
	}
	// A snapshot does not take the metric's alert away.
	alerts.Observe("prod", &protocol.Snapshot{}, now)
	if len(active()) != 1 {
		t.Error("a snapshot resolved the metric's alert")
	}

	// 30 seconds later web-1 served 60 more and failed 3 more; web-2
	// restarted, so its counter started over.
	now = now.Add(30 * time.Second)
	f.set(map[string][]protocol.Sample{
		"web-1": append(requests(160, 13), queue(5)),
		"web-2": append(requests(20, 0), queue(3)),
	})
	m.Round(ctx)
	st = byName()
	want := 60.0/30 + 3.0/30 + 20.0/30
	if p := st["requests"].Points; len(p) != 1 || math.Abs(p[0].V-want) > 1e-9 {
		t.Errorf("requests per second: %+v, want %v", p, want)
	}
	if p := st["errors"].Points; len(p) != 1 || math.Abs(p[0].V-0.1) > 1e-9 {
		t.Errorf("errors per second: %+v", p)
	}
	if st["queue"].Past != "" || len(active()) != 0 {
		t.Errorf("the queue went down but is still past its limit: %+v %+v", st["queue"], active())
	}

	// Past the limit again, then removed: the alert goes with it.
	now = now.Add(30 * time.Second)
	f.set(map[string][]protocol.Sample{"web-1": {queue(50)}, "web-2": {queue(1)}})
	m.Round(ctx)
	if len(active()) != 1 {
		t.Fatalf("queue at 50: %+v", active())
	}
	if _, err := m.Remove(ctx, q.ID, func(w settings.Watch) bool { return w.Namespace == "b" }); err == nil {
		t.Error("removed a watch of another namespace")
	}
	if _, err := m.Remove(ctx, q.ID, func(w settings.Watch) bool { return w.Namespace == "a" }); err != nil {
		t.Fatal(err)
	}
	if len(active()) != 0 {
		t.Errorf("a removed watch kept its alert: %+v", active())
	}

	// An agent that is away leaves the values as they were, and says so.
	f.offline = true
	now = now.Add(30 * time.Second)
	m.Round(ctx)
	st = byName()
	if len(st["requests"].Points) != 1 || !strings.Contains(st["requests"].Error, "not connected") {
		t.Errorf("offline: %+v", st["requests"])
	}
}

func TestThin(t *testing.T) {
	var points []Point
	for i := range 1000 {
		points = append(points, Point{T: int64(i), V: float64(i % 2)})
	}
	got := thin(points, 100, 300)
	if len(got) != 300 || got[0].T < 100 || got[0].V <= 0 || got[0].V >= 1 {
		t.Errorf("thinned: %d %+v", len(got), got[0])
	}
	if got := thin(points, 990, 300); len(got) != 10 || got[0].T != 990 {
		t.Errorf("few: %+v", got)
	}
}

// A watch with no values yet still lists its points as an empty list,
// never as null.
func TestNoPointsIsAnEmptyList(t *testing.T) {
	if got := thin(nil, 0, 10); got == nil || len(got) != 0 {
		t.Errorf("thin(nil) = %#v", got)
	}
}

// A watch removed while a round reads it does not get its alert back from
// that round.
func TestRemovedDuringARound(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(ctx, settings.Memory{}, log)
	alerts := alert.NewManager(time.Hour, log)
	m := New(keeper, alerts, log)
	f := &fakeCluster{values: map[string][]protocol.Sample{"web-1": {queue(50)}, "web-2": {queue(50)}}}
	w, err := m.Add(ctx, settings.Watch{Cluster: "prod", Namespace: "a", Target: "Deployment/web", Port: "9100",
		Metric: "queue_depth", Above: limit(10)})
	if err != nil {
		t.Fatal(err)
	}
	removing := false
	m.Attach(f.pods, func(ctx context.Context, cluster string, cmd protocol.Command) (protocol.Result, error) {
		if removing {
			if _, err := m.Remove(ctx, w.ID, func(settings.Watch) bool { return true }); err != nil {
				t.Error(err)
			}
		}
		return f.ask(ctx, cluster, cmd)
	})
	m.Round(ctx)
	if len(alerts.State().Active) != 1 {
		t.Fatalf("queue at 50: %+v", alerts.State().Active)
	}
	removing = true
	m.Round(ctx)
	if a := alerts.State().Active; len(a) != 0 {
		t.Errorf("the removed watch's alert came back: %+v", a)
	}
	if len(m.List(func(settings.Watch) bool { return true }, 1)) != 0 || len(m.series) != 0 {
		t.Errorf("the removed watch is still kept: %d series", len(m.series))
	}
}
