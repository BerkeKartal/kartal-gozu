package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestPageAtAnyPath(t *testing.T) {
	_, h := newTestServer()
	cases := []struct {
		path, loc, ctype string
		code             int
	}{
		{"/", "", "text/html", http.StatusOK},
		{"/devops/kartal/", "", "text/html", http.StatusOK},
		{"/devops/kartal", "./kartal/", "", http.StatusFound},
		{"/devops/kartal?x=1", "./kartal/?x=1", "", http.StatusFound},
		// A redirect never leaves the site, even for a segment that looks like a URL.
		{"/https:evil", "./https:evil/", "", http.StatusFound},
		{"/devops/kartal/_ui/app.js", "", "text/javascript", http.StatusOK},
		{"/_ui/app.css", "", "text/css", http.StatusOK},
		{"/api/v1/nope", "", "application/json", http.StatusNotFound},
		{"/devops/kartal/api/v1/nope", "", "application/json", http.StatusNotFound},
		{"/favicon.ico", "", "application/json", http.StatusNotFound},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.code || rec.Header().Get("Location") != c.loc || !strings.HasPrefix(rec.Header().Get("Content-Type"), c.ctype) {
			t.Errorf("%s: %d Location=%q Content-Type=%q", c.path, rec.Code, rec.Header().Get("Location"), rec.Header().Get("Content-Type"))
		}
		if c.ctype == "text/html" && !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: page served without its content security policy", c.path)
		}
	}
}

func TestNamespaceCountsAndConditionalRequests(t *testing.T) {
	st, h := newTestServer()
	st.PutSnapshot("demo", &protocol.Snapshot{
		Namespaces: []protocol.Namespace{{Name: "a"}, {Name: "b"}},
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "ok", Phase: "Running", Ready: 1, Total: 1},
			{Namespace: "a", Name: "stuck", Phase: "Pending", Total: 1},
		},
		Workloads: []protocol.Workload{{Kind: "Deployment", Namespace: "b", Name: "web", Desired: 2, Ready: 1}},
		Events:    []protocol.Event{{Namespace: "a", Reason: "BackOff"}},
	}, time.Now())
	get := func(etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/demo/namespaces", nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := get("")
	var got []namespaceSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 2 {
		t.Fatalf("%d %s (%v)", rec.Code, rec.Body, err)
	}
	a, b := got[0], got[1]
	if a.Name != "a" || a.Pods != 2 || a.PodsUnhealthy != 1 || a.Warnings != 1 || b.Workloads != 1 || b.WorkloadsDegraded != 1 {
		t.Errorf("counts: %+v", got)
	}

	etag := rec.Header().Get("ETag")
	if again := get(etag); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Errorf("unchanged snapshot: %d with %d bytes, want an empty 304", again.Code, again.Body.Len())
	}
	// Agents resend everything every interval; the same content keeps its ETag.
	st.PutSnapshot("demo", &protocol.Snapshot{
		Namespaces: []protocol.Namespace{{Name: "a"}, {Name: "b"}},
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "ok", Phase: "Running", Ready: 1, Total: 1},
			{Namespace: "a", Name: "stuck", Phase: "Pending", Total: 1},
		},
		Workloads: []protocol.Workload{{Kind: "Deployment", Namespace: "b", Name: "web", Desired: 2, Ready: 1}},
		Events:    []protocol.Event{{Namespace: "a", Reason: "BackOff"}},
	}, time.Now())
	if again := get(etag); again.Code != http.StatusNotModified {
		t.Errorf("resent identical snapshot answered %d, want 304", again.Code)
	}
	st.PutSnapshot("demo", &protocol.Snapshot{Namespaces: []protocol.Namespace{{Name: "a"}}}, time.Now())
	if fresh := get(etag); fresh.Code != http.StatusOK {
		t.Errorf("changed snapshot answered %d to the old ETag", fresh.Code)
	}
}

func TestProblemsFilter(t *testing.T) {
	st, h := newTestServer()
	st.PutSnapshot("demo", &protocol.Snapshot{
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "ok", Phase: "Running", Ready: 1, Total: 1},
			{Namespace: "a", Name: "crash", Phase: "Running", Total: 1, Reason: "CrashLoopBackOff"},
			{Namespace: "b", Name: "done", Phase: "Succeeded", Total: 1},
			{Namespace: "b", Name: "pending", Phase: "Pending", Total: 1},
			{Namespace: "b", Name: "evicted", Phase: "Failed", Reason: "Evicted", Total: 1, Owner: "Deployment/web"},
		},
	}, time.Now())
	get := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/clusters/demo/"+query, nil))
		return rec
	}
	names := func(rec *httptest.ResponseRecorder) string {
		var pods []protocol.Pod
		json.Unmarshal(rec.Body.Bytes(), &pods)
		var out []string
		for _, p := range pods {
			out = append(out, p.Name)
		}
		return strings.Join(out, ",")
	}
	for query, want := range map[string]string{
		"pods":                             "ok,crash,done,pending,evicted",
		"pods?problems=true":               "crash,pending",
		"pods?problems=false":              "ok,crash,done,pending,evicted",
		"pods?problems=true&namespace=b":   "pending",
		"pods?namespace=a&problems=1":      "crash",
		"workloads?problems=true":          "",
		"pods?problems=true&namespace=zzz": "",
	} {
		if rec := get(query); rec.Code != http.StatusOK || names(rec) != want {
			t.Errorf("%s: %d %q, want %q", query, rec.Code, names(rec), want)
		}
	}
	for _, query := range []string{"pods?problems=maybe", "services?problems=true"} {
		if rec := get(query); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", query, rec.Code)
		}
	}
}
