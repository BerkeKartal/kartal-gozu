package promtext

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const page = `# HELP http_requests_total Requests served, by method and code.
# TYPE http_requests_total counter
http_requests_total{method="GET",code="200"} 1027 1395066363000
http_requests_total{method="POST", code="500",} 3
# HELP request_seconds How long requests took.
# TYPE request_seconds histogram
request_seconds_bucket{le="0.1"} 20
request_seconds_bucket{le="+Inf"} 25
request_seconds_sum 3.5
request_seconds_count 25
# A comment that says nothing.
queue_depth 7
# TYPE rpc_latency summary
rpc_latency{quantile="0.99"} NaN
rpc_latency_sum 0
rpc_latency_count 0
escaped{path="C:\\dir\\file",msg="say \"hi\"\nbye"} -Inf
`

func TestParse(t *testing.T) {
	fams, truncated, err := Parse(strings.NewReader(page), 100)
	if err != nil || truncated {
		t.Fatalf("parse: %v (truncated %v)", err, truncated)
	}
	byName := map[string]protocol.MetricFamily{}
	var order []string
	for _, f := range fams {
		byName[f.Name] = f
		order = append(order, f.Name+":"+f.Type)
	}
	if got := strings.Join(order, " "); got != "http_requests_total:counter request_seconds:histogram queue_depth:untyped rpc_latency:summary escaped:untyped" {
		t.Errorf("families: %s", got)
	}
	reqs := byName["http_requests_total"]
	if reqs.Help != "Requests served, by method and code." || len(reqs.Samples) != 2 ||
		reqs.Samples[0].Value != 1027 || reqs.Samples[1].Labels["code"] != "500" || reqs.Samples[1].Labels["method"] != "POST" {
		t.Errorf("counter: %+v", reqs)
	}
	hist := byName["request_seconds"]
	if len(hist.Samples) != 4 || hist.Samples[1].Labels["le"] != "+Inf" || hist.Samples[3].Name != "request_seconds_count" {
		t.Errorf("histogram: %+v", hist)
	}
	if v := float64(byName["rpc_latency"].Samples[0].Value); !math.IsNaN(v) {
		t.Errorf("NaN quantile: %v", v)
	}
	esc := byName["escaped"].Samples[0]
	if esc.Labels["path"] != `C:\dir\file` || esc.Labels["msg"] != "say \"hi\"\nbye" || !math.IsInf(float64(esc.Value), -1) {
		t.Errorf("escapes: %+v", esc)
	}
	// What JSON cannot hold travels as text, and comes back.
	b, err := json.Marshal(fams)
	if err != nil || !strings.Contains(string(b), `"value":"NaN"`) || !strings.Contains(string(b), `"value":"-Inf"`) {
		t.Fatalf("json: %v %s", err, b)
	}
	var back []protocol.MetricFamily
	if err := json.Unmarshal(b, &back); err != nil || !math.IsNaN(float64(back[3].Samples[0].Value)) || back[0].Samples[0].Value != 1027 {
		t.Errorf("round trip: %v %+v", err, back)
	}
}

func TestOpenMetrics(t *testing.T) {
	fams, _, err := Parse(strings.NewReader(`# TYPE jobs counter
# HELP jobs Jobs done.
jobs_total{queue="mail"} 4 # {trace_id="abc"} 1.0
jobs_created{queue="mail"} 1.7e9
# EOF
this is past the end and never read
`), 100)
	if err != nil || len(fams) != 1 || fams[0].Type != "counter" || len(fams[0].Samples) != 2 || fams[0].Samples[0].Value != 4 {
		t.Fatalf("openmetrics: %v %+v", err, fams)
	}
}

// A name that also appears in "HELP" does not cut the text short.
func TestShortNames(t *testing.T) {
	fams, _, err := Parse(strings.NewReader("# HELP E Errors seen.\n# TYPE E counter\nE 3\n# HELP L\nL 1\n"), 10)
	if err != nil || len(fams) != 2 || fams[0].Help != "Errors seen." || fams[0].Type != "counter" || fams[1].Help != "" {
		t.Errorf("%v %+v", err, fams)
	}
}

func TestRefusesOtherPages(t *testing.T) {
	for _, body := range []string{
		"<!doctype html>\n<html><body>secret page</body></html>\n",
		`{"status": "ok"}`,
		"metric{label=\"unterminated} 1\n",
		"metric 1 2 3\n",
		"metric{1abc=\"x\"} 1\n",
		"# TYPE metric thing\nmetric 1\n",
	} {
		_, _, err := Parse(strings.NewReader(body), 100)
		if !errors.Is(err, ErrFormat) {
			t.Errorf("%q: %v", body, err)
			continue
		}
		// The error never repeats the page.
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "status") {
			t.Errorf("error repeats the page: %v", err)
		}
	}
}

func TestKeepsAtMost(t *testing.T) {
	var b strings.Builder
	for range 50 {
		b.WriteString("x 1\n")
	}
	fams, truncated, err := Parse(strings.NewReader(b.String()), 10)
	if err != nil || !truncated || len(fams[0].Samples) != 10 {
		t.Errorf("%v %v %d", err, truncated, len(fams[0].Samples))
	}
	if fams, _, err := Parse(strings.NewReader(""), 10); err != nil || len(fams) != 0 {
		t.Errorf("empty page: %v %v", fams, err)
	}
}
