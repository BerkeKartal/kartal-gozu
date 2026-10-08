package collect

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

func newCollector(t *testing.T) *Collector {
	t.Helper()
	dir := t.TempDir()
	db, err := tsdb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(settings.NewKeeper(context.Background(), settings.Memory{}, nil), db, dir, nil)
}

var shopPods = []protocol.Pod{
	{Namespace: "shop", Name: "web-1", Phase: "Running", Owner: "Deployment/web"},
	{Namespace: "shop", Name: "web-2", Phase: "Running", Owner: "Deployment/web"},
	{Namespace: "shop", Name: "web-3", Phase: "Pending", Owner: "Deployment/web"},
	{Namespace: "shop", Name: "db-0", Phase: "Running", Owner: "StatefulSet/db"},
}

// agent answers collect commands with each pod's page, or its error.
type agent struct {
	mu    sync.Mutex
	pages map[string]string
	errs  map[string]string
	// big pods do not fit next to others.
	big  map[string]bool
	asks [][]string
}

func (a *agent) ask(_ context.Context, cluster string, cmd protocol.Command) (protocol.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cluster != "prod" || cmd.Type != protocol.CommandCollect || cmd.Namespace != "shop" || cmd.Port != "9090" || cmd.Path != "/metrics" {
		return protocol.Result{}, errors.New("unexpected command")
	}
	a.asks = append(a.asks, slices.Clone(cmd.Pods))
	var out []protocol.PodMetrics
	for _, p := range cmd.Pods {
		m := protocol.PodMetrics{Pod: p, Text: a.pages[p], Error: a.errs[p]}
		if a.big[p] && len(cmd.Pods) > 1 {
			m = protocol.PodMetrics{Pod: p, Alone: true}
		}
		out = append(out, m)
	}
	b, _ := json.Marshal(out)
	return protocol.Result{OK: true, Output: string(b)}, nil
}

func pods(cluster string) ([]protocol.Pod, bool) { return shopPods, cluster == "prod" }

func addTarget(t *testing.T, c *Collector, x settings.CollectTarget) settings.CollectTarget {
	t.Helper()
	saved, err := c.Add(context.Background(), x)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func selectAll(t *testing.T, c *Collector, name string) []tsdb.Series {
	t.Helper()
	m, _ := tsdb.NewMatcher(tsdb.MatchEqual, tsdb.MetricName, name)
	got, err := c.db.Select(0, time.Now().Add(time.Hour).UnixMilli(), tsdb.Match(m))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRoundStoresWithLabels(t *testing.T) {
	c := newCollector(t)
	a := &agent{
		pages: map[string]string{"web-1": "# TYPE http_requests_total counter\nhttp_requests_total{code=\"200\",namespace=\"other\"} 5\n# TYPE go_goroutines gauge\ngo_goroutines 10\n"},
		errs:  map[string]string{"web-2": "connection refused"},
	}
	c.Attach(pods, a.ask)
	x := addTarget(t, c, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090", Include: "http_.*"})
	c.Round(context.Background())

	if len(a.asks) != 1 || !slices.Equal(a.asks[0], []string{"web-1", "web-2"}) {
		t.Fatalf("asked %v, want the two running pods", a.asks)
	}
	got := selectAll(t, c, "http_requests_total")
	if len(got) != 1 {
		t.Fatalf("got %d series, want 1", len(got))
	}
	want := map[string]string{"code": "200", "exported_namespace": "other",
		"cluster": "prod", "namespace": "shop", "pod": "web-1", "workload": "Deployment/web"}
	if m := got[0].Labels.Map(); !mapsEqual(m, want) {
		t.Errorf("labels %v, want %v", m, want)
	}
	if got[0].Type != "counter" || len(got[0].Points) != 1 || got[0].Points[0].V != 5 {
		t.Errorf("series %+v", got[0])
	}
	if g := selectAll(t, c, "go_goroutines"); len(g) != 0 {
		t.Errorf("go_goroutines was stored, though not included")
	}
	ups := map[string]float64{}
	for _, s := range selectAll(t, c, "up") {
		ups[s.Labels.Get("pod")] = s.Points[0].V
	}
	if ups["web-1"] != 1 || ups["web-2"] != 0 || len(ups) != 2 {
		t.Errorf("up = %v, want web-1 1 and web-2 0", ups)
	}
	list := c.List(func(settings.CollectTarget) bool { return true })
	if len(list) != 1 || list[0].ID != x.ID || list[0].Pods != 1 || list[0].Failed != 1 || list[0].Samples != 1 ||
		!strings.Contains(list[0].Error, "connection refused") || list[0].Path != "/metrics" {
		t.Errorf("status %+v", list)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestRoundAsksForBigPodsAlone(t *testing.T) {
	c := newCollector(t)
	a := &agent{
		pages: map[string]string{"web-1": "a 1\n", "web-2": "a 2\n"},
		big:   map[string]bool{"web-1": true},
	}
	c.Attach(pods, a.ask)
	addTarget(t, c, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090"})
	c.Round(context.Background())
	if len(a.asks) != 2 || !slices.Equal(a.asks[1], []string{"web-1"}) {
		t.Fatalf("asked %v, want web-1 again alone", a.asks)
	}
	if got := selectAll(t, c, "a"); len(got) != 2 {
		t.Errorf("got %d series, want both pods'", len(got))
	}
	if st := c.List(func(settings.CollectTarget) bool { return true })[0]; st.Pods != 2 || st.Error != "" {
		t.Errorf("status %+v", st)
	}
}

func TestRoundReportsMissingPodsAndAgents(t *testing.T) {
	c := newCollector(t)
	c.Attach(pods, (&agent{}).ask)
	addTarget(t, c, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/gone", Port: "9090"})
	addTarget(t, c, settings.CollectTarget{Cluster: "test", Namespace: "shop", Target: "Deployment/web", Port: "9090"})
	c.Round(context.Background())
	errs := map[string]string{}
	for _, st := range c.List(func(settings.CollectTarget) bool { return true }) {
		errs[st.Cluster] = st.Error
	}
	if !strings.Contains(errs["prod"], "no running pod") || !strings.Contains(errs["test"], "not connected") {
		t.Errorf("errors %v", errs)
	}
}

func TestTargetsAreCheckedAndScoped(t *testing.T) {
	c := newCollector(t)
	ctx := context.Background()
	x := addTarget(t, c, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090"})
	var invalid *settings.InvalidError
	if _, err := c.Add(ctx, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090", Path: "/metrics"}); !errors.As(err, &invalid) {
		t.Errorf("a second target reading the same pages: %v, want refused", err)
	}
	if _, err := c.Add(ctx, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090", Include: "("}); !errors.As(err, &invalid) {
		t.Errorf("a broken pattern: %v, want refused", err)
	}
	elsewhere := func(o settings.CollectTarget) bool { return o.Namespace == "other" }
	if _, err := c.Remove(ctx, x.ID, elsewhere); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing another namespace's target: %v, want not found", err)
	}
	x.Port = "8080"
	if _, err := c.Change(ctx, x.ID, x, func(settings.CollectTarget) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Remove(ctx, x.ID, func(settings.CollectTarget) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if n := len(c.keeper.Get().Collect.Targets); n != 0 {
		t.Errorf("%d targets left", n)
	}
	if _, err := c.Configure(ctx, 5, 0); !errors.As(err, &invalid) {
		t.Errorf("a 5 second interval: %v, want refused", err)
	}
	if cfg, err := c.Configure(ctx, 60, 7); err != nil || cfg.Interval != 60 || cfg.RetentionDays != 7 {
		t.Errorf("configure: %+v %v", cfg, err)
	}
}

func TestPruneRemovesDaysPastRetention(t *testing.T) {
	c := newCollector(t)
	if err := c.db.Append(time.Now(), []tsdb.Sample{{Labels: tsdb.FromMap("a", nil), Value: 1}}); err != nil {
		t.Fatal(err)
	}
	c.prune(0)
	if len(c.db.Days()) != 1 {
		t.Fatal("kept forever, a day was removed")
	}
	c.Now = func() time.Time { return time.Now().AddDate(0, 0, 2) }
	c.pruned = time.Time{}
	c.prune(3)
	if len(c.db.Days()) != 1 {
		t.Fatal("a day within the retention was removed")
	}
	c.Now = func() time.Time { return time.Now().AddDate(0, 0, 10) }
	c.pruned = time.Time{}
	c.prune(3)
	// Today stays open for writing, empty.
	if got := selectAll(t, c, "a"); len(got) != 0 {
		t.Errorf("%d series left, want none", len(got))
	}
}

func TestPatternsMatchWholeNames(t *testing.T) {
	f := newFilter(settings.CollectTarget{Include: "http_.*|go_goroutines", Exclude: "http_request_duration_.*"})
	for name, want := range map[string]bool{
		"http_requests_total": true, "go_goroutines": true, "http_request_duration_seconds": false,
		"process_go_goroutines": false, "go_goroutines_total": false,
	} {
		if f.keep(name) != want {
			t.Errorf("keep(%s) = %v", name, !want)
		}
	}
	x := settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090", Include: "a)|(b"}
	if err := x.Normalize(); err == nil {
		t.Error("a pattern that would break out of the collector's wrapping was accepted")
	}
}

func TestClashingLabelsAreKept(t *testing.T) {
	fams := []protocol.MetricFamily{{Name: "kube_pod_info", Type: "gauge", Samples: []protocol.Sample{{Name: "kube_pod_info",
		Labels: map[string]string{"namespace": "other", "exported_namespace": "older", "pod": "x"}, Value: 1}}}}
	x := settings.CollectTarget{Namespace: "shop", Target: "Deployment/ksm"}
	got := Samples(fams, "prod", x, "ksm-1", "Deployment/ksm")[0].Labels
	for k, want := range map[string]string{"namespace": "shop", "exported_namespace": "older", "exported_exported_namespace": "other",
		"pod": "ksm-1", "exported_pod": "x", "cluster": "prod", "workload": "Deployment/ksm"} {
		if v := got.Get(k); v != want {
			t.Errorf("%s = %q, want %q (labels %v)", k, v, want, got)
		}
	}
}

// A round cut short by the server stopping records no pod as down.
func TestStoppingRecordsNothing(t *testing.T) {
	c := newCollector(t)
	ctx, cancel := context.WithCancel(context.Background())
	c.Attach(pods, func(ctx context.Context, cluster string, cmd protocol.Command) (protocol.Result, error) {
		cancel()
		return protocol.Result{}, ctx.Err()
	})
	addTarget(t, c, settings.CollectTarget{Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9090"})
	c.Round(ctx)
	if got := selectAll(t, c, "up"); len(got) != 0 {
		t.Errorf("up recorded while stopping: %+v", got)
	}
}
