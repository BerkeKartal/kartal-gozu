package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestDataSourceRequests(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		if r.URL.Path == "/prom/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"success"}`)
	}))
	defer srv.Close()
	allowed, err := ParseDataSourceURLs([]string{srv.URL + "/prom/"})
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{DataSourceURLs: allowed}
	if !strings.Contains(strings.Join(e.Capabilities(), ","), protocol.CapabilityDataSource) {
		t.Errorf("capabilities: %v", e.Capabilities())
	}
	run := func(r protocol.HTTPRequest) protocol.Result {
		return e.Run(context.Background(), protocol.Command{Type: protocol.CommandHTTP, HTTP: &r})
	}
	res := run(protocol.HTTPRequest{Method: "POST", URL: srv.URL + "/prom/api/v1/query_range", Body: []byte("query=up"),
		Header: map[string]string{"authorization": "Bearer x", "content-type": "application/x-www-form-urlencoded"}})
	var answer protocol.HTTPResponse
	if !res.OK || json.Unmarshal([]byte(res.Output), &answer) != nil || answer.Status != 200 || string(answer.Body) != `{"status":"success"}` {
		t.Fatalf("request: %+v %+v", res, answer)
	}
	if len(got) != 1 || got[0] != "POST /prom/api/v1/query_range Bearer x query=up" {
		t.Errorf("the source saw %q", got)
	}
	// A redirect is handed back, not followed.
	res = run(protocol.HTTPRequest{Method: "GET", URL: srv.URL + "/prom/redirect"})
	json.Unmarshal([]byte(res.Output), &answer)
	if !res.OK || answer.Status != http.StatusFound || len(got) != 2 {
		t.Errorf("redirect: %+v %+v %q", res, answer, got)
	}
	for _, r := range []protocol.HTTPRequest{
		{Method: "GET", URL: srv.URL + "/other"},
		{Method: "GET", URL: srv.URL + "/promx"},
		{Method: "GET", URL: srv.URL + "/prom/../other"},
		{Method: "GET", URL: srv.URL + "/prom/%2e%2e/other"},
		{Method: "GET", URL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/prom/x"},
		{Method: "GET", URL: strings.Replace(srv.URL, "http://", "https://", 1) + "/prom/x"},
		{Method: "GET", URL: "http://user:pw@" + strings.TrimPrefix(srv.URL, "http://") + "/prom/x"},
		{Method: "DELETE", URL: srv.URL + "/prom/x"},
		{Method: "GET", URL: srv.URL + "/prom/x", Header: map[string]string{"Cookie": "a=b"}},
		{Method: "GET", URL: srv.URL + "/prom/x", Header: map[string]string{"Authorization": "a\r\nX-Injected: 1"}},
	} {
		if res := run(r); res.OK {
			t.Errorf("allowed %s %s %v", r.Method, r.URL, r.Header)
		}
	}
	if len(got) != 2 {
		t.Errorf("refused requests reached the source: %q", got)
	}
	off := &Executor{}
	if res := off.Run(context.Background(), protocol.Command{Type: protocol.CommandHTTP, HTTP: &protocol.HTTPRequest{Method: "GET", URL: srv.URL + "/prom/x"}}); res.OK || !strings.Contains(res.Error, "KARTAL_DATASOURCE_URLS") {
		t.Errorf("without data sources: %+v", res)
	}
}

func TestParseDataSourceURLs(t *testing.T) {
	for _, bad := range []string{"prometheus:9090", "ftp://x", "http://", "http://u:p@x", "http://x/?a=1"} {
		if _, err := ParseDataSourceURLs([]string{bad}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	got, err := ParseDataSourceURLs([]string{" http://prometheus.monitoring.svc:9090/ ", "https://elastic.example.org"})
	if err != nil || len(got) != 2 || got[0].Path != "" || hostPort(got[1]) != "elastic.example.org:443" {
		t.Errorf("%v %v", got, err)
	}
}
