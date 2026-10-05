package uptime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

func check(url string) settings.Check {
	c := settings.Check{URL: url, Timeout: 1, Interval: 30}
	c.Normalize()
	return c
}

func TestProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("all good")) })
	mux.HandleFunc("/down", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusServiceUnavailable) })
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()

	if r := Probe(ctx, check(srv.URL+"/ok")); !r.OK || r.Status != 200 || r.Cert != nil {
		t.Errorf("ok: %+v", r)
	}
	if r := Probe(ctx, check(srv.URL+"/down")); r.OK || r.Error != "answered 503 Service Unavailable" {
		t.Errorf("down: %+v", r)
	}
	if r := Probe(ctx, check(srv.URL+"/moved")); !r.OK || r.Status != 200 {
		t.Errorf("a redirect is followed: %+v", r)
	}
	c := check(srv.URL + "/moved")
	c.Status = 302
	if r := Probe(ctx, c); r.OK || !strings.Contains(r.Error, "answered 200 OK, expected 302") {
		t.Errorf("status: %+v", r)
	}
	c = check(srv.URL + "/ok")
	c.Contains = "good"
	if r := Probe(ctx, c); !r.OK {
		t.Errorf("contains: %+v", r)
	}
	c.Contains = "bad"
	if r := Probe(ctx, c); r.OK || r.Error != `the answer does not contain "bad"` {
		t.Errorf("does not contain: %+v", r)
	}
	if r := Probe(ctx, check(srv.URL+"/slow")); r.OK || r.Error != "no answer within 1s" {
		t.Errorf("slow: %+v", r)
	}
	if r := Probe(ctx, check("http://127.0.0.1:1/")); r.OK || r.Error != "connection refused: nothing listens there" {
		t.Errorf("nothing listening: %+v", r)
	}

	// Over https, the certificate is described even when it is not trusted.
	tlsSrv := httptest.NewTLSServer(mux)
	defer tlsSrv.Close()
	r := Probe(ctx, check(tlsSrv.URL+"/ok"))
	if r.OK || r.Error != "the certificate is not signed by a trusted authority" || r.Cert == nil || r.Cert.NotAfter.IsZero() {
		t.Errorf("untrusted: %+v", r)
	}
	c = check(tlsSrv.URL + "/ok")
	c.Insecure = true
	if r := Probe(ctx, c); !r.OK || r.Cert == nil {
		t.Errorf("insecure: %+v", r)
	}
}

// fakeProbe answers from a table, and counts.
type fakeProbe struct {
	mu      sync.Mutex
	answers map[string]Result
	calls   int
}

func (f *fakeProbe) probe(_ context.Context, c settings.Check) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	r := f.answers[c.URL]
	r.Time = time.Now().UTC()
	return r
}

func (f *fakeProbe) set(url string, r Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[url] = r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestMonitor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts := alert.NewManager(0, nil)
	keeper := settings.NewKeeper(ctx, settings.Memory{}, nil)
	m := New(keeper, alerts, nil)
	fake := &fakeProbe{answers: map[string]Result{
		"https://web.example.org": {OK: true, Status: 200, Millis: 40, Cert: &Cert{Subject: "web.example.org", NotAfter: time.Now().Add(5 * 24 * time.Hour)}},
		"https://api.example.org": {Status: 503, Error: "answered 503 Service Unavailable"},
	}}
	m.Probe, m.Jitter = fake.probe, func(time.Duration) time.Duration { return 0 }
	m.Start(ctx)

	web, err := m.Add(ctx, settings.Check{Name: "Web", URL: "https://web.example.org"})
	if err != nil || web.ID == "" || web.Interval != 60 {
		t.Fatalf("add: %+v %v", web, err)
	}
	var invalid *settings.InvalidError
	if _, err := m.Add(ctx, settings.Check{Name: "web", URL: "https://other.example.org"}); !errors.As(err, &invalid) {
		t.Errorf("a second check of the same name: %v", err)
	}
	api, err := m.Add(ctx, settings.Check{Name: "API", URL: "https://api.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	// A result is listed a moment before the alerts hear of it.
	waitFor(t, "both checks' first results and their alerts", func() bool {
		l := m.List()
		return len(l) == 2 && l[0].Last != nil && l[1].Last != nil && len(alerts.State().Active) == 2
	})
	l := m.List()
	if l[0].Name != "API" || l[0].Last.OK || *l[0].Uptime != 0 || l[1].Name != "Web" || *l[1].Uptime != 100 || l[1].AvgMillis != 40 {
		t.Errorf("list: %+v", l)
	}
	if n := l[1].Hours[23].Checks; n != 1 {
		t.Errorf("this hour's checks: %d", n)
	}
	// The API is down and the web's certificate expires in five days.
	st := alerts.State()
	kinds := map[string]string{}
	for _, a := range st.Active {
		kinds[a.Kind] = a.Object + " " + a.Detail
	}
	if !strings.HasPrefix(kinds["URLDown"], "API answered 503") || !strings.HasPrefix(kinds["CertificateExpiring"], "Web web.example.org: expires in 4 days") {
		t.Errorf("alerts: %v", kinds)
	}

	// A new address starts over; a removed check takes its alert along.
	fake.set("https://www.example.org", Result{OK: true, Status: 200, Millis: 10})
	if _, err := m.Change(ctx, web.ID, settings.Check{Name: "Web", URL: "https://www.example.org"}); err != nil {
		t.Fatal(err)
	}
	if l := m.List(); l[1].URL != "https://www.example.org" || (l[1].Last != nil && l[1].Last.Millis != 10) {
		t.Errorf("changed: %+v", l[1])
	}
	waitFor(t, "the new address's result", func() bool { l := m.List(); return l[1].Last != nil })
	if _, err := m.Remove(ctx, api.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Remove(ctx, api.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removed twice: %v", err)
	}
	waitFor(t, "the alerts to go", func() bool { return alerts.ActiveCount("", nil) == 0 })
	if got := keeper.Get().Checks; len(got) != 1 || got[0].URL != "https://www.example.org" {
		t.Errorf("kept: %+v", got)
	}
}

func TestProbeSchemeMismatch(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if r := Probe(context.Background(), check(strings.Replace(srv.URL, "http://", "https://", 1))); r.Error != "the address answers over http, not https" {
		t.Errorf("%+v", r)
	}
}
