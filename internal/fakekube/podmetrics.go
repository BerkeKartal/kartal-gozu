package fakekube

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// started is when the demo's counters start counting.
var started = time.Now()

// servePodMetrics answers what the API server proxies to a pod
// (/api/v1/namespaces/<ns>/pods/<pod>:<port>/proxy/<path>). The generated
// teams' web pods expose metrics on port 9100 at /metrics; other ports
// refuse the connection, and other paths answer as such a pod would.
func (f *Server) servePodMetrics(w http.ResponseWriter, r *http.Request) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/")
	if !ok {
		return false
	}
	ns, rest, ok := strings.Cut(rest, "/pods/")
	if !ok {
		return false
	}
	target, path, ok := strings.Cut(rest, "/proxy")
	if !ok {
		return false
	}
	pod, port, _ := strings.Cut(target, ":")
	var team, replica int
	n, _ := fmt.Sscanf(strings.TrimPrefix(pod, "web-5d8c-"), "%2d%1d", &team, &replica)
	if !strings.HasPrefix(ns, "team-") || n != 2 || port != "9100" {
		writeStatus(w, http.StatusServiceUnavailable, "ServiceUnavailable",
			fmt.Sprintf("error trying to reach service: dial tcp 10.1.%d.%d:%s: connect: connection refused", team, replica, port))
		return true
	}
	if path != "/metrics" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404 page not found\n")
		return true
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	io.WriteString(w, appMetrics(team, replica, time.Since(started).Seconds()))
	return true
}

// appMetrics is the page of one web pod, t seconds into the demo. Every
// third team's app fails a share of its requests, as its pods crash.
func appMetrics(team, replica int, t float64) string {
	seed := float64(team*3 + replica)
	// grown counts what happened by t at a rate of base plus a slow wave,
	// so that the rate itself moves.
	grown := func(base, wave, period float64) float64 {
		return 1000 + base*t + wave*period*(1-math.Cos(t/period+seed))
	}
	failing := 0.02
	if team%3 == 0 {
		failing = 0.6
	}
	get, post := grown(4+seed/5, 2, 90), grown(1, 0.5, 150)
	errors := grown(failing, failing/2, 60)
	count := get + post + errors
	var b strings.Builder
	b.WriteString("# HELP http_requests_total Requests handled, by method and status code.\n# TYPE http_requests_total counter\n")
	fmt.Fprintf(&b, "http_requests_total{method=\"GET\",code=\"200\"} %.0f\n", get)
	fmt.Fprintf(&b, "http_requests_total{method=\"POST\",code=\"201\"} %.0f\n", post)
	fmt.Fprintf(&b, "http_requests_total{method=\"GET\",code=\"500\"} %.0f\n", errors)
	b.WriteString("# HELP http_request_duration_seconds How long requests took.\n# TYPE http_request_duration_seconds histogram\n")
	share := 0.0
	for i, le := range []string{"0.05", "0.1", "0.25", "0.5", "1"} {
		share += []float64{0.55, 0.25, 0.12, 0.05, 0.02}[i]
		fmt.Fprintf(&b, "http_request_duration_seconds_bucket{le=%q} %.0f\n", le, count*share)
	}
	fmt.Fprintf(&b, "http_request_duration_seconds_bucket{le=\"+Inf\"} %.0f\n", count)
	fmt.Fprintf(&b, "http_request_duration_seconds_sum %.3f\nhttp_request_duration_seconds_count %.0f\n", count*0.087, count)
	b.WriteString("# HELP app_queue_depth Jobs waiting in the queue.\n# TYPE app_queue_depth gauge\n")
	fmt.Fprintf(&b, "app_queue_depth %.0f\n", math.Max(0, 26+18*math.Sin(t/120+seed)+3*math.Sin(t/17)))
	b.WriteString("# HELP process_resident_memory_bytes Resident memory size in bytes.\n# TYPE process_resident_memory_bytes gauge\n")
	fmt.Fprintf(&b, "process_resident_memory_bytes %.0f\n", (90+seed*4+6*math.Sin(t/300+seed))*(1<<20))
	b.WriteString("# HELP go_goroutines Number of goroutines that currently exist.\n# TYPE go_goroutines gauge\n")
	fmt.Fprintf(&b, "go_goroutines %d\n", 30+team+replica)
	return b.String()
}
