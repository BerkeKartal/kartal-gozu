package query

import (
	"context"
	"testing"
	"time"
)

// FuzzQuery checks that no query, however malformed, crashes the engine.
func FuzzQuery(f *testing.F) {
	for _, q := range []string{
		`sum by (code) (rate(http_requests_total[1m]))`, `histogram_quantile(0.9, sum by (le) (rate(lat_bucket[1m])))`,
		`mem / on (pod) group_left mem`, `topk(1, mem)`, `-2 ^ 2`, `label_replace(mem, "x", "$1", "pod", "(.*)")`,
		`mem offset 1m > bool 3`, `absent(nope{job="x"})`, `{__name__=~"m.*"}`, `quantile_over_time(0.5, mem[1m])`,
		`predict_linear(mem[2m], 60)`, `clamp(mem, 1, 0)`, `mem or on (pod) gone unless mem`, `count(mem) by (pod) # x`,
	} {
		f.Add(q)
	}
	e := NewEngine(testDB())
	e.MaxPoints = 100_000
	f.Fuzz(func(t *testing.T, q string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		e.Range(ctx, q, 0, 600*sec, 60*sec, nil)
		if expr, err := Parse(q); err == nil {
			// What a query prints must parse again.
			if _, err := Parse(expr.String()); err != nil {
				t.Errorf("%q prints as %q, which does not parse: %v", q, expr.String(), err)
			}
		}
	})
}

// FuzzRange checks that no range or step, however far off, crashes the
// engine.
func FuzzRange(f *testing.F) {
	f.Add(`rate(http_requests_total[1m]) offset 5m`, int64(0), int64(600_000), int64(60_000))
	f.Add(`mem`, int64(-1), int64(9223372036854775807), int64(1))
	f.Add(`sum(mem) by (pod)`, int64(9223372036854775000), int64(9223372036854775807), int64(9223372036854775807))
	e := NewEngine(testDB())
	e.MaxPoints = 100_000
	f.Fuzz(func(t *testing.T, q string, start, end, step int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		e.Range(ctx, q, start, end, step, nil)
	})
}
