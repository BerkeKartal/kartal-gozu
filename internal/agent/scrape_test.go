package agent

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/fakekube"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
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
	} {
		if res := on.Run(context.Background(), cmd); res.OK {
			t.Errorf("accepted %+v", cmd)
		}
	}
}
