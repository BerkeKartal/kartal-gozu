package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const agentTok = "agent-token-0123456789"

func newTestServer() (*store.Store, http.Handler) {
	st := store.New("demo")
	h := New(Config{
		AgentTokens:    map[string]string{agentTok: "demo"},
		StaleAfter:     time.Minute,
		MaxPollWait:    time.Second,
		CommandTimeout: time.Second,
	}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return st, h
}

func TestRouteStart(t *testing.T) {
	cases := map[string]int{
		"/api/v1/clusters":                                        0,
		"/devops/kartal/api/v1/clusters":                          14,
		"/x/agent/v1/commands":                                    2,
		"/p/api/v1/clusters/c/namespaces/agent/pods/api/logs":     2,
		"/api/v1/clusters/c/namespaces/api/v1/pods/agent/v1/logs": 0,
		"/healthz":        0,
		"/deep/a/healthz": 7,
		"/other":          -1,
	}
	for path, want := range cases {
		if got := routeStart(path); got != want {
			t.Errorf("routeStart(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestReportTrustsTheTokenNotThePayload(t *testing.T) {
	st, h := newTestServer()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	io.WriteString(zw, `{"cluster":"someone-else","kubeVersion":"v1.33.11"}`)
	zw.Close()

	req := httptest.NewRequest(http.MethodPost, "/some/prefix/agent/v1/report", &buf)
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	ci, _ := st.Cluster("demo")
	if ci.Snapshot == nil || ci.Snapshot.Cluster != "demo" || ci.Snapshot.KubeVersion != "v1.33.11" {
		t.Fatalf("snapshot = %+v", ci.Snapshot)
	}
}

func TestEscapedNamesSurviveThePrefix(t *testing.T) {
	_, h := newTestServer()
	// %2F must stay part of the name instead of becoming a path separator.
	req := httptest.NewRequest(http.MethodGet, "/x/api/v1/clusters/demo/namespaces/ns/pods/a%2Fb/logs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable { // routed to the logs handler; the agent is offline
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestCommandsRefusedForOfflineCluster(t *testing.T) {
	_, h := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/demo/resources", nil)
	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Error("should fail fast instead of waiting for a missing agent")
	}
}

func TestPollWaitIsCapped(t *testing.T) {
	_, h := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/agent/v1/commands?wait=600", nil)
	req.Header.Set("Authorization", "Bearer "+agentTok)
	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("poll held for %v despite MaxPollWait=1s", took)
	}
}
