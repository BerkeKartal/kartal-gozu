package agent

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/fakekube"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/promtext"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// teamsKube is the fake API with three generated teams, whose web pods
// expose metrics on port 9100.
func teamsKube(t *testing.T) *kube.Client {
	t.Helper()
	srv := httptest.NewServer(&fakekube.Server{Extra: 3})
	t.Cleanup(srv.Close)
	return kube.New(srv.URL, fakekube.Token, false)
}

func TestScrapePod(t *testing.T) {
	e := &Executor{Kube: teamsKube(t), AllowScrape: true}
	if !strings.Contains(strings.Join(e.Capabilities(), ","), protocol.CapabilityScrape) {
		t.Errorf("capabilities: %v", e.Capabilities())
	}
	res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandScrape, Namespace: "team-01", Name: "web-5d8c-011", Port: "9100"})
	if !res.OK {
		t.Fatalf("scrape: %+v", res)
	}
	var page protocol.Scrape
	if err := json.Unmarshal([]byte(res.Output), &page); err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, f := range page.Families {
		types[f.Name] = f.Type
	}
	if types["http_requests_total"] != "counter" || types["http_request_duration_seconds"] != "histogram" || types["app_queue_depth"] != "gauge" {
		t.Errorf("families: %v", types)
	}
}

func TestScrapeTellsNothingOfOtherPages(t *testing.T) {
	e := &Executor{Kube: teamsKube(t), AllowScrape: true}
	for _, c := range []struct{ port, path, want string }{
		// The pod's own error page is not repeated, only its status.
		{"9100", "/admin", "with HTTP status 404"},
		// The API server's refusal says what went wrong.
		{"8080", "/metrics", "connection refused"},
	} {
		res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandScrape, Namespace: "team-01", Name: "web-5d8c-011", Port: c.port, Path: c.path})
		if res.OK || !strings.Contains(res.Error, c.want) || strings.Contains(res.Error, "page not found") {
			t.Errorf("%s%s: %+v", c.port, c.path, res)
		}
	}
}

func TestSampleReadsOnlyWhatIsAsked(t *testing.T) {
	e := &Executor{Kube: teamsKube(t), AllowScrape: true}
	res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandSample, Namespace: "team-01", Port: "9100",
		Pods: []string{"web-5d8c-011", "web-5d8c-012", "gone"}, Metrics: []string{"app_queue_depth"}})
	if !res.OK {
		t.Fatalf("sample: %+v", res)
	}
	var got []protocol.PodSamples
	if err := json.Unmarshal([]byte(res.Output), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || len(got[0].Samples) != 1 || got[0].Samples[0].Name != "app_queue_depth" || len(got[1].Samples) != 1 ||
		got[2].Error == "" || len(got[2].Samples) != 0 {
		t.Errorf("samples: %+v", got)
	}
}

func TestScrapeIsChecked(t *testing.T) {
	kc := teamsKube(t)
	off := &Executor{Kube: kc}
	res := off.Run(context.Background(), protocol.Command{Type: protocol.CommandScrape, Namespace: "team-01", Name: "web-5d8c-011", Port: "9100"})
	if res.OK || !strings.Contains(res.Error, "KARTAL_POD_METRICS") {
		t.Errorf("without opt-in: %+v", res)
	}
	on := &Executor{Kube: kc, AllowScrape: true, Namespaces: []string{"team-01"}}
	for _, cmd := range []protocol.Command{
		{Type: protocol.CommandScrape, Namespace: "team-01", Name: "web-5d8c-011", Port: "metrics"},
		{Type: protocol.CommandScrape, Namespace: "team-01", Name: "web-5d8c-011", Port: "9100", Path: "/../../api/v1/secrets"},
		{Type: protocol.CommandScrape, Namespace: "team-01", Name: "web-5d8c-011", Port: "9100", Path: "/metrics?x=1"},
		{Type: protocol.CommandScrape, Namespace: "team-02", Name: "web-5d8c-021", Port: "9100"},
		{Type: protocol.CommandSample, Namespace: "team-01", Port: "9100", Pods: []string{"web-5d8c-011"}},
		{Type: protocol.CommandSample, Namespace: "team-01", Port: "9100", Pods: []string{"../x"}, Metrics: []string{"up"}},
		{Type: protocol.CommandSample, Namespace: "team-01", Port: "9100", Pods: []string{"web-5d8c-011"}, Metrics: []string{"no-dashes"}},
		{Type: protocol.CommandCollect, Namespace: "team-01", Port: "9100", Pods: []string{"../x"}},
		{Type: protocol.CommandCollect, Namespace: "team-01", Port: "9100"},
		{Type: protocol.CommandCollect, Namespace: "team-02", Port: "9100", Pods: []string{"web-5d8c-021"}},
		{Type: protocol.CommandCollect, Namespace: "team-01", Port: "9100", Path: "/../x", Pods: []string{"web-5d8c-011"}},
	} {
		if res := on.Run(context.Background(), cmd); res.OK {
			t.Errorf("accepted %+v", cmd)
		}
	}
}

func TestFindMetrics(t *testing.T) {
	e := &Executor{Kube: teamsKube(t), AllowScrape: true}
	res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandFindMetrics})
	if !res.OK {
		t.Fatalf("find: %+v", res)
	}
	var got protocol.MetricsSources
	if err := json.Unmarshal([]byte(res.Output), &got); err != nil {
		t.Fatal(err)
	}
	// Each team's web pods answer on 9100; their port 8080 does not, and
	// pods without ports are not asked at all.
	var where []string
	for _, s := range got.Sources {
		where = append(where, s.Namespace+" "+s.Workload+" :"+s.Port+s.Path)
		if s.Metrics != 5 || !strings.HasPrefix(s.Pod, "web-5d8c-") {
			t.Errorf("source: %+v", s)
		}
	}
	if strings.Join(where, ",") != "team-01 Deployment/web :9100/metrics,team-02 Deployment/web :9100/metrics,team-03 Deployment/web :9100/metrics" ||
		got.Tried != 3 || got.Unfinished {
		t.Errorf("found: %v (tried %d, unfinished %v)", where, got.Tried, got.Unfinished)
	}
	one := e.Run(context.Background(), protocol.Command{Type: protocol.CommandFindMetrics, Namespace: "team-02"})
	if !one.OK || strings.Count(one.Output, `"workload"`) != 1 {
		t.Errorf("one namespace: %+v", one)
	}
	if res := (&Executor{Kube: e.Kube}).Run(context.Background(), protocol.Command{Type: protocol.CommandFindMetrics}); res.OK {
		t.Error("found metrics without KARTAL_POD_METRICS")
	}
}

func TestMetricsPorts(t *testing.T) {
	var p metricsPod
	p.Metadata.Annotations = map[string]string{"prometheus.io/port": "9102"}
	if err := json.Unmarshal([]byte(`{"containers":[
		{"ports":[{"name":"http","containerPort":8080},{"name":"postgres","containerPort":5433},{"containerPort":6379}]},
		{"ports":[{"name":"dns","containerPort":53,"protocol":"UDP"},{"name":"http-metrics","containerPort":9100},{"name":"grpc","containerPort":9090}]}]}`), &p.Spec); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(metricsPorts(p), ","); got != "9102,9100,8080" {
		t.Errorf("ports: %s", got)
	}
}

func TestCollectReadsWholePages(t *testing.T) {
	e := &Executor{Kube: teamsKube(t), AllowScrape: true}
	if !strings.Contains(strings.Join(e.Capabilities(), ","), protocol.CapabilityCollect) {
		t.Errorf("capabilities: %v", e.Capabilities())
	}
	res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandCollect, Namespace: "team-01", Port: "9100",
		Pods: []string{"web-5d8c-011", "web-5d8c-012", "gone"}})
	if !res.OK {
		t.Fatalf("collect: %+v", res)
	}
	var got []protocol.PodMetrics
	if err := json.Unmarshal([]byte(res.Output), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].Pod != "gone" || got[2].Error == "" || got[2].Text != "" {
		t.Fatalf("pages: %+v", got)
	}
	for _, p := range got[:2] {
		fams, _, err := promtext.Parse(strings.NewReader(p.Text), 1000)
		if err != nil || p.Error != "" || len(fams) < 5 {
			t.Errorf("%s: %d families, %v %s", p.Pod, len(fams), err, p.Error)
		}
		// Help texts are left out; types stay.
		if strings.Contains(p.Text, "# HELP") || !strings.Contains(p.Text, "# TYPE http_requests_total counter") {
			t.Errorf("%s page:\n%s", p.Pod, p.Text)
		}
	}
}
