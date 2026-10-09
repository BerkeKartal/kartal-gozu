package api

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/collect"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// The store answers as a Prometheus: the data source client, which talks
// to real ones, reads it with a user's token and sees what the user may.
func TestPrometheusAPI(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	dir := t.TempDir()
	db, err := tsdb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	grant, _ := auth.ParseGrant("viewer@prod/team-a")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users:       map[string]auth.User{teamTok: auth.NewUser("takim", []auth.Grant{grant})},
		AdminToken:  adminTok,
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Collect: collect.New(keeper, db, dir, log),
	}, store.New("prod"), log)
	srv := httptest.NewServer(s)
	defer srv.Close()

	now := time.Now().Truncate(time.Minute)
	for k := 0; k < 10; k++ {
		at := now.Add(time.Duration(k-10) * time.Minute)
		for _, ns := range []string{"team-a", "team-b"} {
			ls := tsdb.FromMap("http_requests_total", map[string]string{"cluster": "prod", "namespace": ns, "pod": "web-1"})
			if err := db.Append(at, []tsdb.Sample{{Labels: ls, Type: "counter", Value: float64(60 * k)}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := datasource.New(nil)
	ctx := context.Background()
	as := func(tok string) settings.DataSource {
		return settings.DataSource{Type: "prometheus", URL: srv.URL + "/prometheus", Auth: "bearer", Token: tok}
	}
	start, end := now.Add(-5*time.Minute).UnixMilli(), now.Add(-time.Minute).UnixMilli()
	for tok, want := range map[string]float64{adminTok: 2, teamTok: 1} {
		res, err := c.PromRange(ctx, as(tok), `sum(rate(http_requests_total[5m]))`, start, end, 60_000)
		if err != nil {
			t.Fatalf("%s: %v", tok, err)
		}
		if len(res.Series) != 1 || len(res.Series[0].Values.V) != 5 || res.Series[0].Values.V[4] != want {
			t.Errorf("%s: %+v", tok, res.Series)
		}
	}
	values, err := c.PromLabelValues(ctx, as(teamTok), "namespace", "", start, end)
	if err != nil || strings.Join(values, ",") != "team-a" {
		t.Errorf("namespaces the team sees: %v %v", values, err)
	}
	metrics, err := c.PromMetrics(ctx, as(adminTok), "", start, end)
	if err != nil || len(metrics) != 1 || metrics[0].Type != "counter" {
		t.Errorf("metrics %+v %v", metrics, err)
	}
	if names, err := c.PromLabels(ctx, as(adminTok), `{namespace="team-b"}`, start, end); err != nil || strings.Join(names, ",") != "cluster,namespace,pod" {
		t.Errorf("labels %v %v", names, err)
	}
	if v, err := c.Test(ctx, as(adminTok)); err != nil || !strings.HasPrefix(v, "Prometheus") {
		t.Errorf("test %q %v", v, err)
	}
	if _, err := c.PromRange(ctx, as(adminTok), `sum(`, start, end, 60_000); err == nil {
		t.Error("a bad query passed")
	}
	if _, err := c.Test(ctx, as("wrong")); err == nil {
		t.Error("a wrong token passed")
	}
	// Instant queries, as Grafana's tables make.
	for q, want := range map[string]string{
		`count(http_requests_total)`: `"resultType":"vector"`,
		`2 * 3`:                      `"resultType":"scalar"`,
		`1 + 1`:                      `"result":[`,
	} {
		rec := do(s, "GET", "/prometheus/api/v1/query?query="+url.QueryEscape(q)+"&time="+seconds(now), adminTok, "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
	rec := do(s, "GET", "/prometheus/api/v1/series?match[]=http_requests_total&start="+seconds(now.Add(-time.Hour))+"&end="+seconds(now), teamTok, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "team-b") || !strings.Contains(rec.Body.String(), "team-a") {
		t.Errorf("series for the team: %d %s", rec.Code, rec.Body)
	}
}

// seconds writes a time as Prometheus's API takes it.
func seconds(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// The Prometheus API works below a prefix, and the UI's API below one
// that happens to end in /prometheus.
func TestPrometheusAPIPrefixes(t *testing.T) {
	for path, want := range map[string]bool{
		"/prometheus/api/v1/query_range":                  true,
		"/devops/kartal/prometheus/api/v1/labels":         true,
		"/devops/kartal/prometheus/api/v1/label/a/values": true,
		"/prometheus/api/v1/clusters":                     false,
		"/x/prometheus/api/v1/me":                         false,
	} {
		i := routeStart(path)
		got := i >= 0 && strings.HasPrefix(path[i:], promRoot)
		if got != want {
			t.Errorf("%s: route at %d, Prometheus %v", path, i, got)
		}
	}
}
