package logwatch

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/fakees"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// setup is a monitor over a made-up Elasticsearch, and a Prometheus that a
// rule cannot count in.
func setup(t *testing.T) (m *Monitor, alerts *alert.Manager, es, prom string) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(&fakees.Server{Now: func() time.Time { return now }})
	t.Cleanup(srv.Close)
	keeper := settings.NewKeeper(ctx, settings.Memory{}, nil)
	sources := datasource.NewManager(keeper)
	e, err := sources.Add(ctx, settings.DataSource{Name: "Logs", Type: settings.SourceElasticsearch, URL: srv.URL, Index: "logs-*"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := sources.Add(ctx, settings.DataSource{Name: "Metrics", Type: settings.SourcePrometheus, URL: "http://prometheus.example.org:9090"})
	if err != nil {
		t.Fatal(err)
	}
	alerts = alert.NewManager(time.Minute, nil)
	m = New(keeper, sources, alerts, nil)
	m.Now = func() time.Time { return now }
	return m, alerts, e.ID, p.ID
}

func logAlerts(a *alert.Manager) []alert.Alert {
	var out []alert.Alert
	for _, x := range a.State().Active {
		if x.Kind == alert.LogLimit {
			out = append(out, x)
		}
	}
	return out
}

func TestRulesBecomeAlerts(t *testing.T) {
	m, alerts, es, prom := setup(t)
	ctx := context.Background()

	for name, bad := range map[string]settings.LogRule{
		"no name":             {Source: es, Query: "log.level:ERROR"},
		"no query":            {Name: "x", Source: es},
		"every line":          {Name: "x", Source: es, Query: "*"},
		"a window of seconds": {Name: "x", Source: es, Query: "a", Window: 5},
		"an unknown severity": {Name: "x", Source: es, Query: "a", Severity: "fatal"},
		"no such source":      {Name: "x", Source: "nowhere", Query: "a"},
		"a Prometheus":        {Name: "x", Source: prom, Query: "a"},
	} {
		var invalid *settings.InvalidError
		if _, err := m.Add(ctx, bad); !errors.As(err, &invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The made-up logs have errors every few minutes; none are fatal.
	noisy, err := m.Add(ctx, settings.LogRule{Name: "Errors", Source: es, Query: "log.level:ERROR", Window: 1800, Above: 3, Severity: "critical"})
	if err != nil || noisy.ID == "" {
		t.Fatalf("add: %+v %v", noisy, err)
	}
	quiet, err := m.Add(ctx, settings.LogRule{Name: "Fatal", Source: es, Query: "log.level:FATAL"})
	if err != nil || quiet.Window != 300 || quiet.Severity != "warning" {
		t.Fatalf("add with defaults: %+v %v", quiet, err)
	}
	if _, err := m.Add(ctx, settings.LogRule{Name: "errors", Source: es, Query: "x"}); err == nil {
		t.Error("two rules of one name")
	}
	// Not counted yet.
	if list := m.List(); len(list) != 2 || list[0].Name != "Errors" || list[0].Last != nil || list[0].SourceName != "Logs" {
		t.Fatalf("before the first round: %+v", list)
	}

	m.Round(ctx)
	list := m.List()
	if !list[0].Firing || list[0].Last == nil || list[0].Last.Count <= 3 || list[1].Firing || list[1].Last.Count != 0 {
		t.Fatalf("after a round: %+v %+v", list[0].Last, list[1].Last)
	}
	found := logAlerts(alerts)
	if len(found) != 1 || found[0].Object != "Errors" || found[0].Severity != "critical" || found[0].Cluster != "" ||
		!strings.Contains(found[0].Detail, "in the last 30m, more than 3") {
		t.Fatalf("alerts: %+v", found)
	}
	since := found[0].Since

	// An Elasticsearch that does not answer leaves the rules as they were.
	real := m.Count
	m.Count = func(context.Context, settings.DataSource, settings.LogRule, time.Time, time.Time) (int64, error) {
		return 0, errors.New("the source answered 503: unavailable")
	}
	m.Round(ctx)
	list = m.List()
	if !list[0].Firing || !strings.Contains(list[0].Last.Error, "503") || list[1].Firing {
		t.Errorf("while the source is away: %+v %+v", list[0], list[1])
	}
	if found := logAlerts(alerts); len(found) != 1 || !found[0].Since.Equal(since) {
		t.Errorf("alerts while the source is away: %+v", found)
	}
	// So does one that is away when the server starts again and knows
	// nothing of what the rules counted.
	fresh := New(m.keeper, m.sources, alerts, nil)
	fresh.Now, fresh.Count = m.Now, m.Count
	fresh.Round(ctx)
	if found := logAlerts(alerts); len(found) != 1 || !found[0].Since.Equal(since) {
		t.Errorf("alerts after a restart while the source is away: %+v", found)
	}
	m.Count = real

	// A limit the lines stay under resolves the alert; a changed rule has
	// no count until it is counted again.
	noisy.Above = 1_000_000
	if _, err := m.Change(ctx, noisy.ID, noisy); err != nil {
		t.Fatal(err)
	}
	if list := m.List(); list[0].Last != nil || list[0].Firing {
		t.Errorf("a changed rule keeps its old count: %+v", list[0])
	}
	m.Round(ctx)
	if found := logAlerts(alerts); len(found) != 0 {
		t.Errorf("under its limit: %+v", found)
	}

	// Trying a rule counts once and saves nothing.
	res, err := m.Try(ctx, settings.LogRule{Name: "t", Source: es, Query: "log.level:ERROR", Window: 1800})
	if err != nil || res.Error != "" || res.Count == 0 || len(m.List()) != 2 {
		t.Errorf("try: %+v %v", res, err)
	}
	if _, err := m.Try(ctx, settings.LogRule{Name: "t", Source: prom, Query: "x"}); err == nil {
		t.Error("tried in a Prometheus")
	}

	// A removed rule takes its alert with it.
	noisy.Above = 0
	m.Change(ctx, noisy.ID, noisy)
	m.Round(ctx)
	if len(logAlerts(alerts)) != 1 {
		t.Fatal("not firing again")
	}
	if gone, err := m.Remove(ctx, noisy.ID); err != nil || gone.Name != "Errors" {
		t.Fatalf("remove: %+v %v", gone, err)
	}
	m.Round(ctx)
	if found := logAlerts(alerts); len(found) != 0 || len(m.List()) != 1 {
		t.Errorf("after removing: %+v", found)
	}
	if _, err := m.Remove(ctx, noisy.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removed twice: %v", err)
	}
	if _, err := m.Change(ctx, noisy.ID, noisy); !errors.Is(err, ErrNotFound) {
		t.Errorf("changed after removing: %v", err)
	}
}

func TestSpan(t *testing.T) {
	for seconds, want := range map[int]string{60: "1m", 300: "5m", 3600: "1h", 86400: "24h", 90: "90s"} {
		if got := span(seconds); got != want {
			t.Errorf("%d seconds: %s, want %s", seconds, got, want)
		}
	}
}
