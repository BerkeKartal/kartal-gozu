package fakees_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/fakees"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// The demo's Elasticsearch answers the searches the client makes.
func TestSearches(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(&fakees.Server{Now: func() time.Time { return now }})
	defer srv.Close()
	src := settings.DataSource{Name: "logs", Type: "elasticsearch", URL: srv.URL, Index: "logs-*"}
	if err := src.Normalize(); err != nil {
		t.Fatal(err)
	}
	c := datasource.New(nil)
	ctx := context.Background()
	start, end, step := now.Add(-time.Hour).UnixMilli(), now.UnixMilli(), int64(5*60_000)

	// Errors by namespace: team-03 fails far more than the others.
	res, err := c.ESSeries(ctx, src, datasource.ESQuery{Query: "log.level:ERROR", GroupBy: "kubernetes.namespace", Start: start, End: end, Step: step}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) == 0 || res.Series[0].Labels["kubernetes.namespace"] != "team-03" {
		t.Fatalf("errors by namespace: %+v", res.Series)
	}
	sum := func(i int) (n float64) {
		for _, v := range res.Series[i].Values.V {
			n += v
		}
		return n
	}
	if len(res.Series) > 1 && sum(0) < 5*sum(1) {
		t.Errorf("team-03 has %v errors, the next %v", sum(0), sum(1))
	}
	// The 95th percentile of durations, for one namespace only.
	res, err = c.ESSeries(ctx, src, datasource.ESQuery{Metric: "p95", Field: "event.duration", Start: start, End: end, Step: step}, datasource.Scope{"team-01"})
	if err != nil || len(res.Series) != 1 || !res.Series[0].Values.OK[1] || res.Series[0].Values.V[1] < 20 {
		t.Fatalf("p95: %+v %v", res, err)
	}
	logs, err := c.ESLogs(ctx, src, datasource.ESLogsQuery{Query: `NOT log.level:INFO AND "/api/"`, Size: 20, Start: start, End: end, Step: step}, datasource.Scope{"team-02"})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Lines) == 0 || logs.Total == 0 || logs.Lines[0].T > end {
		t.Fatalf("logs %+v", logs)
	}
	for i, l := range logs.Lines {
		if strings.Contains(l.Message, " 200 ") || !strings.Contains(string(l.Source), `"team-02"`) || (i > 0 && l.T > logs.Lines[i-1].T) {
			t.Errorf("line %d: %s %s", i, l.Message, l.Source)
		}
	}
	// A range that does not start on a multiple of the step still fills
	// every step.
	off := start + 7_000
	res, err = c.ESSeries(ctx, src, datasource.ESQuery{Start: off, End: end, Step: step}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, ok := range res.Series[0].Values.OK[:len(res.Series[0].Values.OK)-1] {
		if !ok || res.Series[0].Values.V[i] == 0 {
			t.Errorf("step %d of a range starting off the step: %v %v", i, ok, res.Series[0].Values.V[i])
		}
	}
	fields, err := c.ESFields(ctx, src, "")
	if err != nil || len(fields) != 10 {
		t.Errorf("fields %+v %v", fields, err)
	}
	if v, err := c.Test(ctx, src); err != nil || v != "Elasticsearch 8.13.0" {
		t.Errorf("version %q %v", v, err)
	}
}
