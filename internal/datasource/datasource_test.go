package datasource

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/query"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// fakeProm answers as a Prometheus with one series, and tells what it was
// asked.
func fakeProm(t *testing.T, asked *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		*asked = append(*asked, r.Method+" "+r.URL.Path+" "+r.Form.Encode()+" "+r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/prom/api/v1/query_range":
			if r.Form.Get("query") == "bad(" {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"status":"error","errorType":"bad_data","error":"1:5: parse error: unclosed left parenthesis"}`)
				return
			}
			// Values at the first and third steps (60 and 180 s), one NaN.
			io.WriteString(w, `{"status":"success","warnings":["careful"],"data":{"resultType":"matrix","result":[
				{"metric":{"__name__":"up","pod":"a"},"values":[[60,"1"],[180.000,"NaN"]]}]}}`)
		case "/prom/api/v1/labels":
			io.WriteString(w, `{"status":"success","data":["__name__","namespace","pod"]}`)
		case "/prom/api/v1/label/__name__/values":
			io.WriteString(w, `{"status":"success","data":["http_requests_total","lat_bucket","up"]}`)
		case "/prom/api/v1/metadata":
			io.WriteString(w, `{"status":"success","data":{"http_requests_total":[{"type":"counter"}],"lat":[{"type":"histogram"}]}}`)
		case "/prom/api/v1/status/buildinfo":
			io.WriteString(w, `{"status":"success","data":{"version":"2.53.0"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestPrometheus(t *testing.T) {
	var asked []string
	srv := fakeProm(t, &asked)
	defer srv.Close()
	src := settings.DataSource{Name: "p", Type: "prometheus", URL: srv.URL + "/prom", Auth: "bearer", Token: "tok"}
	c := New(nil)
	ctx := context.Background()
	res, err := c.PromRange(ctx, src, "up", 60_000, 180_000, 60_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) != 1 || res.Series[0].Labels["pod"] != "a" || len(res.Warnings) != 1 {
		t.Fatalf("result %+v", res)
	}
	v := res.Series[0].Values
	if !v.OK[0] || v.V[0] != 1 || v.OK[1] || !v.OK[2] || !math.IsNaN(v.V[2]) {
		t.Errorf("values %+v", v)
	}
	if asked[0] != "POST /prom/api/v1/query_range end=180&query=up&start=60&step=60 Bearer tok" {
		t.Errorf("asked %q", asked[0])
	}
	if _, err := c.PromRange(ctx, src, "bad(", 0, 60_000, 60_000); err == nil || !strings.Contains(err.Error(), "unclosed left parenthesis") {
		t.Errorf("a bad query: %v", err)
	}
	if names, err := c.PromLabels(ctx, src, `{namespace="x"}`, 0, 1000); err != nil || strings.Join(names, ",") != "namespace,pod" {
		t.Errorf("labels %v %v", names, err)
	}
	if !strings.Contains(asked[len(asked)-1], "match%5B%5D=%7Bnamespace%3D%22x%22%7D") {
		t.Errorf("labels asked %q", asked[len(asked)-1])
	}
	metrics, err := c.PromMetrics(ctx, src, "", 0, 1000)
	if err != nil || len(metrics) != 3 || metrics[0].Type != "counter" || metrics[1].Type != "histogram" || metrics[2].Type != "" {
		t.Errorf("metrics %+v %v", metrics, err)
	}
	if v, err := c.Test(ctx, src); v != "Prometheus 2.53.0" || err != nil {
		t.Errorf("test: %q %v", v, err)
	}
	if _, err := c.Test(ctx, settings.DataSource{Type: "prometheus", URL: srv.URL + "/nothing"}); err == nil {
		t.Error("an address that is no Prometheus passed the test")
	}
}

// Through an agent, the request travels in a command.
func TestThroughAnAgent(t *testing.T) {
	var asked []string
	srv := fakeProm(t, &asked)
	defer srv.Close()
	var cluster string
	c := New(func(ctx context.Context, cl string, cmd protocol.Command) (protocol.Result, error) {
		cluster = cl
		r := cmd.HTTP
		req, _ := http.NewRequest(r.Method, r.URL, strings.NewReader(string(r.Body)))
		for k, v := range r.Header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return protocol.Result{}, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		out, _ := json.Marshal(protocol.HTTPResponse{Status: resp.StatusCode, Body: b})
		return protocol.Result{OK: true, Output: string(out)}, nil
	})
	src := settings.DataSource{Type: "prometheus", URL: srv.URL + "/prom", Via: "prod", Auth: "basic", Username: "u", Password: "p"}
	if _, err := c.PromRange(context.Background(), src, "up", 60_000, 60_000, 1000); err != nil {
		t.Fatal(err)
	}
	if cluster != "prod" || !strings.HasSuffix(asked[0], "Basic dTpw") {
		t.Errorf("through %q, asked %q", cluster, asked)
	}
}

func TestScopePromQL(t *testing.T) {
	q := `sum by (pod) (rate(http_requests_total{code="500"}[5m])) / ignoring (code) group_left sum by (pod) (rate(http_requests_total[5m] offset 1h))`
	scoped, err := ScopePromQL(q, "namespace", []string{"shop", "a.b"})
	if err != nil {
		t.Fatal(err)
	}
	expr, err := query.Parse(scoped)
	if err != nil {
		t.Fatalf("%s: %v", scoped, err)
	}
	n := 0
	query.Inspect(expr, func(e query.Expr) {
		vs, ok := e.(*query.VectorSelector)
		if !ok {
			return
		}
		n++
		last := vs.Matchers[len(vs.Matchers)-1]
		if last.Name != "namespace" || !last.Matches("shop") || !last.Matches("a.b") || last.Matches("axb") || last.Matches("shopping") {
			t.Errorf("selector %s", vs)
		}
	})
	if n != 2 {
		t.Errorf("%d selectors in %s", n, scoped)
	}
	if _, err := ScopePromQL(`rate(x[5m:1m])`, "namespace", []string{"a"}); err == nil {
		t.Error("a query the parser cannot read was let through")
	}
	if _, err := ScopePromQL(`up`, "namespace", nil); err != ErrNoNamespace {
		t.Errorf("no namespaces: %v", err)
	}
	if m, _ := ScopeMatch("", "namespace", []string{"a", "b"}); m != `{namespace=~"a|b"}` {
		t.Errorf("match %s", m)
	}
}

// fakeES answers searches as an Elasticsearch does, and keeps the bodies.
func fakeES(t *testing.T, bodies *[]map[string]any, oldVersion bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/":
			io.WriteString(w, `{"version":{"number":"8.13.0"},"tagline":"You Know, for Search"}`)
		case strings.HasSuffix(r.URL.Path, "/_field_caps"):
			io.WriteString(w, `{"indices":["logs-1"],"fields":{"_id":{"_id":{"aggregatable":true}},
				"event.duration":{"long":{"aggregatable":true}},"message":{"text":{"aggregatable":false}},
				"kubernetes.pod.name":{"keyword":{"aggregatable":true}}}}`)
		case strings.HasSuffix(r.URL.Path, "/_search"):
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			*bodies = append(*bodies, body)
			raw, _ := json.Marshal(body)
			if oldVersion && strings.Contains(string(raw), "fixed_interval") {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"error":{"root_cause":[{"type":"x_content_parse_exception","reason":"[date_histogram] unknown field [fixed_interval]"}],"type":"x_content_parse_exception","reason":"[1:120] [date_histogram] unknown field [fixed_interval]"},"status":400}`)
				return
			}
			if body["size"].(float64) == 0 {
				io.WriteString(w, `{"aggregations":{"g":{"buckets":[
					{"key":"web-1","doc_count":3,"t":{"buckets":[{"key":60000,"doc_count":2,"m":{"values":{"95.0":12.5}}},{"key":120000,"doc_count":1,"m":{"values":{"95.0":null}}}]}},
					{"key":"web-2","doc_count":1,"t":{"buckets":[{"key":120000,"doc_count":1,"m":{"values":{"95.0":7}}}]}}]}}}`)
				return
			}
			io.WriteString(w, `{"hits":{"total":{"value":10000,"relation":"gte"},"hits":[
				{"_index":"logs-1","_id":"a","_source":{"@timestamp":"2026-10-08T10:00:00Z","log":{"message":"boom"}},"sort":[120000]},
				{"_index":"logs-1","_id":"b","_source":{"@timestamp":"2026-10-08T09:59:00Z","level":"INFO"},"sort":[60000]}]},
				"aggregations":{"t":{"buckets":[{"key":60000,"doc_count":4},{"key":120000,"doc_count":6}]}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestElasticsearch(t *testing.T) {
	var bodies []map[string]any
	srv := fakeES(t, &bodies, true)
	defer srv.Close()
	src := settings.DataSource{Name: "e", Type: "elasticsearch", URL: srv.URL, Index: "logs-*"}
	if err := src.Normalize(); err != nil {
		t.Fatal(err)
	}
	src.MessageField = "log.message"
	c := New(nil)
	ctx := context.Background()
	res, err := c.ESSeries(ctx, src, ESQuery{Query: "level:ERROR", Metric: "p95", Field: "event.duration", GroupBy: "kubernetes.pod.name",
		Size: 5, Start: 60_000, End: 180_000, Step: 60_000}, Scope{"shop"})
	if err != nil {
		t.Fatal(err)
	}
	// The first try used fixed_interval, which this old version refused.
	if len(bodies) != 2 || !strings.Contains(jsonText(bodies[1]), `"interval":"60000ms"`) {
		t.Fatalf("bodies %v", bodies)
	}
	filters := jsonText(bodies[1]["query"])
	for _, want := range []string{`"gte":60000`, `"lte":180000`, `"query":"level:ERROR"`, `"kubernetes.namespace":["shop"]`} {
		if !strings.Contains(filters, want) {
			t.Errorf("the filter %s has no %s", filters, want)
		}
	}
	if len(res.Series) != 2 || res.Series[0].Labels["kubernetes.pod.name"] != "web-1" || res.Series[0].Labels[tsdb.MetricName] != "p95(event.duration)" {
		t.Fatalf("series %+v", res.Series)
	}
	a, b := res.Series[0].Values, res.Series[1].Values
	if !a.OK[0] || a.V[0] != 12.5 || a.OK[1] || a.OK[2] || !b.OK[1] || b.V[1] != 7 {
		t.Errorf("values %+v %+v", a, b)
	}
	for _, bad := range []ESQuery{
		{Metric: "avg", Start: 0, End: 60_000, Step: 1000},
		{Metric: "median", Field: "x", Start: 0, End: 60_000, Step: 1000},
		{Index: "a/b", Start: 0, End: 60_000, Step: 1000},
		{GroupBy: "kubernetes.pod.name", Size: 50, Start: 0, End: 86_400_000, Step: 1000},
	} {
		if _, err := c.ESSeries(ctx, src, bad, nil); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	srv2 := fakeES(t, &bodies, false)
	defer srv2.Close()
	src.URL = srv2.URL
	logs, err := c.ESLogs(ctx, src, ESLogsQuery{Query: "*", Start: 60_000, End: 120_000, Step: 60_000}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if logs.Total != 10000 || !logs.TotalMore || len(logs.Lines) != 2 || logs.Lines[0].T != 120000 || logs.Lines[0].Message != "boom" ||
		!strings.Contains(logs.Lines[1].Message, `"level":"INFO"`) {
		t.Errorf("logs %+v", logs)
	}
	if c := logs.Counts.Series[0].Values; c.V[0] != 4 || c.V[1] != 6 {
		t.Errorf("counts %+v", c)
	}
	if strings.Contains(jsonText(bodies[len(bodies)-1]["query"]), "query_string") {
		t.Errorf("* became a query: %v", bodies[len(bodies)-1])
	}
	fields, err := c.ESFields(ctx, src, "")
	if err != nil || len(fields) != 3 || fields[0].Name != "event.duration" || !fields[0].Aggregatable || fields[2].Aggregatable {
		t.Errorf("fields %+v %v", fields, err)
	}
	if v, err := c.Test(ctx, src); v != "Elasticsearch 8.13.0" || err != nil {
		t.Errorf("test %q %v", v, err)
	}
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestErrorText(t *testing.T) {
	for body, want := range map[string]string{
		`{"status":"error","error":"bad query"}`:                                                        "bad query",
		`{"error":{"reason":"all shards failed","root_cause":[{"reason":"No mapping found for [x]"}]}}`: "all shards failed: No mapping found for [x]",
		`<html>Bad Gateway</html>`:                                                                      "<html>Bad Gateway</html>",
		``:                                                                                              "Bad Gateway",
	} {
		if got := errorText(http.StatusBadGateway, []byte(body)); got != want {
			t.Errorf("%s: %q, want %q", body, got, want)
		}
	}
	if !strings.Contains(errorText(http.StatusFound, nil), "redirect") {
		t.Error("a redirect is not explained")
	}
}
