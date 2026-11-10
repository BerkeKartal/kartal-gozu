package datasource

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/fakees"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

func TestESCount(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(&fakees.Server{Now: func() time.Time { return now }})
	defer srv.Close()
	src := settings.DataSource{Name: "e", Type: "elasticsearch", URL: srv.URL, Index: "logs-*", NamespaceLabel: "kubernetes.namespace", Cluster: "prod"}
	if err := src.Normalize(); err != nil {
		t.Fatal(err)
	}
	c := New(nil)
	ctx := context.Background()
	start, end := now.Add(-30*time.Minute).UnixMilli(), now.UnixMilli()

	all, err := c.ESCount(ctx, src, "", "*", start, end, nil)
	if err != nil || all == 0 {
		t.Fatalf("every line: %d, %v", all, err)
	}
	errors, err := c.ESCount(ctx, src, "", "log.level:ERROR", start, end, nil)
	if err != nil || errors == 0 || errors >= all {
		t.Fatalf("errors: %d of %d, %v", errors, all, err)
	}
	// As many as a search of the same lines finds.
	logs, err := c.ESLogs(ctx, src, ESLogsQuery{Query: "log.level:ERROR", Start: start, End: end, Step: 60_000}, nil)
	if err != nil || logs.Total != errors {
		t.Errorf("a search finds %d, the count %d (%v)", logs.Total, errors, err)
	}
	// A scope keeps the lines of its namespaces.
	one, err := c.ESCount(ctx, src, "", "log.level:ERROR", start, end, Scope{"team-03"})
	if err != nil || one == 0 || one >= errors {
		t.Errorf("errors of one namespace: %d of %d, %v", one, errors, err)
	}
	if n, err := c.ESCount(ctx, src, "", "log.level:ERROR", start, end, Scope{}); err != nil || n != 0 {
		t.Errorf("errors of no namespace: %d, %v", n, err)
	}
	for name, bad := range map[string]func() (int64, error){
		"an index with a slash": func() (int64, error) { return c.ESCount(ctx, src, "a/b", "*", start, end, nil) },
		"a range backwards":     func() (int64, error) { return c.ESCount(ctx, src, "", "*", end, start, nil) },
	} {
		if _, err := bad(); err == nil {
			t.Errorf("%s was counted", name)
		}
	}
}
