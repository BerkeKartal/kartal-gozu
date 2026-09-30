package agent_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/agent"
	"github.com/BerkeKartal/kartal-gozu/internal/api"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const (
	agentToken = "agent-token-0123456789"
	adminToken = "admin-token-0123456789"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func call(t *testing.T, method, url, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestAgentAndServer runs a real agent against a real server, with a fake
// Kubernetes API behind the agent. The agent talks to the server under a
// sub-path while the checks below also use the root: both must work without
// any configuration.
func TestAgentAndServer(t *testing.T) {
	_, kc := agent.NewFakeKube(t)
	st := store.New("demo")
	srv := httptest.NewServer(api.New(api.Config{
		AgentTokens:    map[string]string{agentToken: "demo"},
		AdminToken:     adminToken,
		StaleAfter:     time.Minute,
		MaxPollWait:    2 * time.Second,
		CommandTimeout: 5 * time.Second,
	}, st, quiet))
	defer srv.Close()

	a := &agent.Agent{
		ServerURL:   srv.URL + "/devops/kartal",
		Token:       agentToken,
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		Collector:   &agent.Collector{Kube: kc, Version: "test"},
		Executor:    &agent.Executor{Kube: kc},
		Interval:    200 * time.Millisecond,
		PollWait:    time.Second,
		Concurrency: 2,
		Log:         quiet,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	root := srv.URL + "/api/v1"
	sub := srv.URL + "/any/depth/prefix/api/v1"
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := call(t, http.MethodGet, root+"/clusters", adminToken)
		var clusters []struct {
			Status string `json:"status"`
			Counts struct {
				Nodes         int `json:"nodes"`
				NodesNotReady int `json:"nodesNotReady"`
				Pods          int `json:"pods"`
				PodsUnhealthy int `json:"podsUnhealthy"`
			} `json:"counts"`
		}
		json.Unmarshal([]byte(body), &clusters)
		if code == http.StatusOK && len(clusters) == 1 && clusters[0].Status == "online" && clusters[0].Counts.Pods == 2 {
			c := clusters[0].Counts
			if c.PodsUnhealthy != 1 || c.Nodes != 2 || c.NodesNotReady != 1 {
				t.Errorf("summary counts: %s", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cluster never came online: %d %s", code, body)
		}
		time.Sleep(50 * time.Millisecond)
	}

	for _, base := range []string{root, sub} {
		if code, body := call(t, http.MethodGet, base+"/clusters/demo/nodes", adminToken); code != http.StatusOK || !strings.Contains(body, `"control-plane"`) {
			t.Errorf("nodes via %s: %d %s", base, code, body)
		}
	}
	if code, body := call(t, http.MethodGet, root+"/clusters/demo/pods?namespace=demo", adminToken); code != http.StatusOK || strings.Count(body, `"name"`) != 1 {
		t.Errorf("namespace filter: %d %s", code, body)
	}

	// Commands travel server -> agent (long-poll) -> fake API -> server.
	start := time.Now()
	code, body := call(t, http.MethodGet, sub+"/clusters/demo/namespaces/demo/pods/api-7c9f-abcde/logs?tail=100", adminToken)
	if code != http.StatusOK || body != "line1\nline2\n" {
		t.Fatalf("logs: %d %q", code, body)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("command waited for the poll timeout instead of waking it: %v", took)
	}
	if code, body := call(t, http.MethodGet, root+"/clusters/demo/resources", adminToken); code != http.StatusOK || !strings.Contains(body, `"ingressroutes"`) {
		t.Errorf("discovery: %d %s", code, body)
	}
	if code, body := call(t, http.MethodGet, root+"/clusters/demo/resources/traefik.io/v1alpha1/ingressroutes?namespace=demo", adminToken); code != http.StatusOK || !strings.Contains(body, `"web"`) {
		t.Errorf("CRD list: %d %s", code, body)
	}
	code, body = call(t, http.MethodGet, root+"/clusters/demo/resources/core/v1/secrets/db?namespace=demo", adminToken)
	if code != http.StatusOK || strings.Contains(body, "c3VwZXItc2VjcmV0") || !strings.Contains(body, "<redacted>") {
		t.Errorf("secret through the whole chain: %d %s", code, body)
	}
	if code, body := call(t, http.MethodPost, root+"/clusters/demo/namespaces/demo/workloads/deployment/api/restart", adminToken); code != http.StatusBadGateway || !strings.Contains(body, "disabled") {
		t.Errorf("restart on a read-only agent: %d %s", code, body)
	}
	for url, want := range map[string]string{
		"/clusters/demo/object-events?kind=Pod&namespace=demo&name=api-7c9f-abcde": `"reason":"BackOff"`,
		"/clusters/demo/namespaces/demo/deployments/api/history":                   `"current":2`,
		"/clusters/demo/helm": `"chart":"traefik"`,
		"/clusters/demo/namespaces/demo/pods/api-7c9f-abcde/logs?previous=true": "connection refused",
		"/clusters/demo/metrics?kind=node&name=cp1":                             `"cpu":250`,
		"/clusters/demo": `"requests":{"cpuMilli":200`,
	} {
		if code, body := call(t, http.MethodGet, root+url, adminToken); code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("%s: %d %s", url, code, body)
		}
	}
	code, body = call(t, http.MethodGet, root+"/audit", adminToken)
	if code != http.StatusOK || !strings.Contains(body, `"action":"restart"`) || !strings.Contains(body, `"ok":false`) {
		t.Errorf("the refused restart should be in the audit log: %d %s", code, body)
	}

	checks := []struct {
		name, method, url, token string
		want                     int
	}{
		{"no admin token", http.MethodGet, root + "/clusters", "", http.StatusUnauthorized},
		{"agent token is not an admin token", http.MethodGet, sub + "/clusters", agentToken, http.StatusUnauthorized},
		{"wrong agent token", http.MethodGet, srv.URL + "/x/agent/v1/commands", "nope", http.StatusUnauthorized},
		{"unknown cluster", http.MethodGet, root + "/clusters/prod", adminToken, http.StatusNotFound},
		{"unknown API route", http.MethodGet, sub + "/something-else", adminToken, http.StatusNotFound},
		{"UI under any prefix", http.MethodGet, srv.URL + "/devops/kartal/", "", http.StatusOK},
		{"probe at root", http.MethodGet, srv.URL + "/healthz", "", http.StatusOK},
		{"probe under a prefix", http.MethodGet, srv.URL + "/devops/kartal/healthz", "", http.StatusOK},
	}
	for _, c := range checks {
		if code, body := call(t, c.method, c.url, c.token); code != c.want {
			t.Errorf("%s: got %d want %d (%s)", c.name, code, c.want, body)
		}
	}
}
