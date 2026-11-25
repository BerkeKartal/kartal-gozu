package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const teamOperatorTok = "team-operator-token-0123456789"

// newMCPServer is the role server's users, an operator of namespace a only,
// and a snapshot of cluster demo.
func newMCPServer(t *testing.T) (*store.Store, *Server) {
	t.Helper()
	grant, err := auth.ParseGrant("operator@demo/a")
	if err != nil {
		t.Fatal(err)
	}
	st := store.New("demo")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"},
		Users: map[string]auth.User{
			viewerTok:       {Name: "ekip", Role: auth.Viewer},
			operatorTok:     {Name: "nobet", Role: auth.Operator},
			teamOperatorTok: auth.User{Name: "takim"}.Add(grant),
		},
		AdminToken: adminTok, StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		Version: "7804c92",
	}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	snap := &protocol.Snapshot{AgentVersion: "7804c92", KubeVersion: "v1.30.14",
		Nodes:      []protocol.Node{{Name: "n1", Ready: true, KubeletVersion: "v1.30.14"}},
		Namespaces: []protocol.Namespace{{Name: "a"}, {Name: "b"}},
		Pods: []protocol.Pod{{Name: "web-1", Namespace: "a", Phase: "Running"}, {Name: "db-1", Namespace: "b", Phase: "Running"},
			{Name: "api-1", Namespace: "a", Phase: "Pending", Reason: "CrashLoopBackOff"}},
		Capabilities: []string{"write"},
	}
	if err := st.PutSnapshot("demo", snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	return st, s
}

type rpcAnswer struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func rpc(t *testing.T, h http.Handler, token, body string, header ...string) (*httptest.ResponseRecorder, rpcAnswer) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/devops/kartal/api/v1/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var a rpcAnswer
	if rec.Body.Len() > 0 && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		json.Unmarshal(rec.Body.Bytes(), &a)
	}
	return rec, a
}

// call runs a tool and returns its text and whether it failed.
func call(t *testing.T, h http.Handler, token, name string, args map[string]any) (string, bool) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	rec, a := rpc(t, h, token, string(b))
	if rec.Code != 200 || a.Error != nil {
		t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
	}
	var res toolResult
	if err := json.Unmarshal(a.Result, &res); err != nil || len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("%s: result %s", name, a.Result)
	}
	return res.Content[0].Text, res.IsError
}

func TestMCPHandshake(t *testing.T) {
	_, s := newMCPServer(t)
	rec, a := rpc(t, s, viewerTok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools *struct{} `json:"tools"`
		} `json:"capabilities"`
		ServerInfo struct {
			Name, Version string
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	if err := json.Unmarshal(a.Result, &init); rec.Code != 200 || err != nil || string(a.ID) != "1" || init.ProtocolVersion != "2025-06-18" ||
		init.Capabilities.Tools == nil || init.ServerInfo.Name != "kartal-gozu" || init.ServerInfo.Version != "7804c92" || init.Instructions == "" {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body)
	}
	// A version it does not speak gets its newest.
	_, a = rpc(t, s, viewerTok, `{"jsonrpc":"2.0","id":"x","method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	json.Unmarshal(a.Result, &init)
	if init.ProtocolVersion != mcpVersions[0] || string(a.ID) != `"x"` {
		t.Errorf("fallback: %s", a.Result)
	}
	if rec, _ := rpc(t, s, viewerTok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("notification: %d %q", rec.Code, rec.Body)
	}
	if _, a := rpc(t, s, viewerTok, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, "MCP-Protocol-Version", "2025-06-18"); a.Error != nil || string(a.Result) != "{}" {
		t.Errorf("ping: %+v %s", a.Error, a.Result)
	}
	if _, a := rpc(t, s, viewerTok, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`); a.Error == nil || a.Error.Code != rpcNoMethod {
		t.Errorf("unknown method: %+v", a)
	}

	for name, c := range map[string]struct {
		token, body string
		header      []string
		code        int
		rpc         int
	}{
		"no token":      {"", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil, 401, 0},
		"not json":      {viewerTok, `{"jsonrpc":`, nil, 400, rpcParseError},
		"batch":         {viewerTok, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil, 400, rpcInvalidRequest},
		"not 2.0":       {viewerTok, `{"jsonrpc":"1.0","id":1,"method":"ping"}`, nil, 400, rpcInvalidRequest},
		"not an object": {viewerTok, `"ping"`, nil, 400, rpcInvalidRequest},
		"a number":      {viewerTok, `42`, nil, 400, rpcInvalidRequest},
		"too big":       {viewerTok, `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", maxMCPBody) + `"}}`, nil, 413, rpcParseError},
		"old protocol":  {viewerTok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"MCP-Protocol-Version", "2024-11-05"}, 400, 0},
		"foreign page":  {viewerTok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"Origin", "https://evil.example"}, 403, 0},
		"its own page":  {viewerTok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"Origin", "http://example.com"}, 200, 0},
		"through proxy": {viewerTok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"Origin", "https://panel.example.org", "X-Forwarded-Host", "panel.example.org"}, 200, 0},
	} {
		rec, a := rpc(t, s, c.token, c.body, c.header...)
		if rec.Code != c.code || (c.rpc != 0 && (a.Error == nil || a.Error.Code != c.rpc)) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// Nothing streams, and there is no session to end.
	for _, m := range []string{"GET", "DELETE"} {
		if rec := do(s, m, "/api/v1/mcp", viewerTok, ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Errorf("%s: %d", m, rec.Code)
		}
	}
}

func TestMCPToolsByRole(t *testing.T) {
	_, s := newMCPServer(t)
	names := func(token string) map[string]bool {
		_, a := rpc(t, s, token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		var res struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				InputSchema struct {
					Type       string         `json:"type"`
					Properties map[string]any `json:"properties"`
					Required   []string       `json:"required"`
				} `json:"inputSchema"`
				Annotations struct {
					ReadOnly *bool `json:"readOnlyHint"`
				} `json:"annotations"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(a.Result, &res); err != nil {
			t.Fatal(err, string(a.Result))
		}
		out := map[string]bool{}
		for _, tl := range res.Tools {
			if out[tl.Name] || tl.Description == "" || tl.InputSchema.Type != "object" || tl.InputSchema.Required == nil || tl.Annotations.ReadOnly == nil {
				t.Errorf("tool %+v", tl)
			}
			for _, r := range tl.InputSchema.Required {
				if _, ok := tl.InputSchema.Properties[r]; !ok {
					t.Errorf("%s requires %s, which it does not have", tl.Name, r)
				}
			}
			out[tl.Name] = true
		}
		return out
	}
	viewer, operator := names(viewerTok), names(operatorTok)
	if !viewer["list_clusters"] || !viewer["pod_logs"] || viewer["restart_workload"] || viewer["audit_log"] {
		t.Errorf("viewer's tools: %v", viewer)
	}
	if !operator["restart_workload"] || !operator["delete_pod"] || !operator["audit_log"] || len(operator) != len(mcpTools) {
		t.Errorf("operator's tools: %v", operator)
	}
	// Editing YAML and the console are not offered to anyone.
	for name := range names(adminTok) {
		if strings.Contains(name, "exec") || strings.Contains(name, "apply") || strings.Contains(name, "edit") {
			t.Errorf("offered %s", name)
		}
	}
	if text, failed := call(t, s, viewerTok, "restart_workload", map[string]any{"cluster": "demo", "namespace": "a", "kind": "Deployment", "name": "web"}); !failed ||
		!strings.Contains(text, "operator role") {
		t.Errorf("viewer restarted: %q", text)
	}
	if _, a := rpc(t, s, viewerTok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`); a.Error == nil || a.Error.Code != rpcInvalidParams {
		t.Errorf("unknown tool: %+v", a)
	}
}

func TestMCPToolsCallTheAPI(t *testing.T) {
	st, s := newMCPServer(t)
	text, failed := call(t, s, viewerTok, "list_clusters", nil)
	if failed || !strings.Contains(text, `"name":"demo"`) {
		t.Errorf("list_clusters: %q", text)
	}
	text, failed = call(t, s, viewerTok, "list_objects", map[string]any{"cluster": "demo", "kind": "PODS", "namespace": "a", "problems": true})
	if failed || !strings.Contains(text, "api-1") || strings.Contains(text, "web-1") || strings.Contains(text, "db-1") {
		t.Errorf("list_objects: %q", text)
	}
	// A namespace's operator sees only that namespace.
	text, failed = call(t, s, teamOperatorTok, "list_objects", map[string]any{"cluster": "demo", "kind": "pods"})
	if failed || !strings.Contains(text, "web-1") || strings.Contains(text, "db-1") {
		t.Errorf("team's pods: %q", text)
	}
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"list_objects", map[string]any{"cluster": "demo", "kind": "everything"}, "kind must be one of"},
		{"list_objects", map[string]any{"cluster": "demo"}, "kind is required"},
		{"list_objects", map[string]any{"cluster": "demo", "kind": "pods", "colour": "red"}, `no argument "colour"`},
		{"pod_logs", map[string]any{"cluster": "demo", "namespace": "a", "pod": "web-1", "tail": 2.5}, "whole number"},
		{"pod_logs", map[string]any{"cluster": "demo", "namespace": "a", "pod": "web-1", "tail": 9999}, "between 1 and 5000"},
		{"get_resource", map[string]any{"cluster": "demo", "kind": "gizmo"}, "unknown kind"},
		{"list_objects", map[string]any{"cluster": "nowhere", "kind": "pods"}, "404 Not Found: unknown cluster"},
		// The team's operator acts only in its namespace.
		{"delete_pod", map[string]any{"cluster": "demo", "namespace": "b", "pod": "db-1"}, "403"},
	} {
		token := viewerTok
		if c.tool == "delete_pod" {
			token = teamOperatorTok
		}
		if text, failed := call(t, s, token, c.tool, c.args); !failed || !strings.Contains(text, c.want) {
			t.Errorf("%s %v: %v %q", c.tool, c.args, failed, text)
		}
	}

	// What the cluster is asked live goes to its agent, which answers here.
	agent := func(check func(protocol.Command) string) {
		go func() {
			cmds, _ := st.TakeCommands(context.Background(), "demo", 2*time.Second)
			for _, c := range cmds {
				if out := check(c); out != "" {
					st.Deliver("demo", protocol.Result{CommandID: c.ID, OK: true, Output: out})
				} else {
					st.Deliver("demo", protocol.Result{CommandID: c.ID, Error: "unexpected command"})
				}
			}
		}()
	}
	agent(func(c protocol.Command) string {
		if c.Type == protocol.CommandGet && c.Group == "apps" && c.Version == "v1" && c.Resource == "deployments" && c.Name == "web" && c.Namespace == "a" {
			return `{"kind":"Deployment","metadata":{"name":"web"}}`
		}
		return ""
	})
	if text, failed := call(t, s, viewerTok, "get_resource", map[string]any{"cluster": "demo", "kind": "deploy", "name": "web", "namespace": "a"}); failed ||
		!strings.Contains(text, `"kind":"Deployment"`) {
		t.Errorf("get_resource: %v %q", failed, text)
	}
	agent(func(c protocol.Command) string {
		if c.Type == protocol.CommandLogs && c.Name == "web-1" && c.TailLines == 200 && !c.Previous {
			return "line 1\nline 2\n"
		}
		return ""
	})
	if text, failed := call(t, s, viewerTok, "pod_logs", map[string]any{"cluster": "demo", "namespace": "a", "pod": "web-1"}); failed || text != "line 1\nline 2\n" {
		t.Errorf("pod_logs: %v %q", failed, text)
	}
	agent(func(c protocol.Command) string {
		if c.Type == protocol.CommandEvents && c.Kind == "Pod" && c.Name == "api-1" && c.Namespace == "a" {
			return `[{"reason":"BackOff"}]`
		}
		return ""
	})
	if text, failed := call(t, s, viewerTok, "object_events", map[string]any{"cluster": "demo", "kind": "pods", "name": "api-1", "namespace": "a"}); failed ||
		!strings.Contains(text, "BackOff") {
		t.Errorf("object_events: %v %q", failed, text)
	}
}

func TestMCPActionIsAudited(t *testing.T) {
	st, s := newMCPServer(t)
	go func() {
		cmds, _ := st.TakeCommands(context.Background(), "demo", 2*time.Second)
		for _, c := range cmds {
			if c.Type == protocol.CommandScale && c.Kind == "deployment" && c.Name == "web" && c.Replicas != nil && *c.Replicas == 3 {
				st.Deliver("demo", protocol.Result{CommandID: c.ID, OK: true, Output: "deployment/web scaled to 3"})
			}
		}
	}()
	text, failed := call(t, s, teamOperatorTok, "scale_workload", map[string]any{"cluster": "demo", "namespace": "a", "kind": "deployment", "name": "web", "replicas": 3})
	if failed || !strings.Contains(text, "scaled to 3") {
		t.Fatalf("scale: %v %q", failed, text)
	}
	var audit []AuditEntry
	json.Unmarshal(do(s, "GET", "/api/v1/audit", adminTok, "").Body.Bytes(), &audit)
	if len(audit) != 1 || audit[0].Via != "mcp" || audit[0].User != "takim" || audit[0].Action != protocol.CommandScale || audit[0].Detail != "replicas=3" || !audit[0].OK {
		t.Errorf("audit: %+v", audit)
	}
	// The UI's own calls are not marked.
	if text, failed := call(t, s, operatorTok, "audit_log", nil); failed || !strings.Contains(text, `"via":"mcp"`) {
		t.Errorf("audit_log: %q", text)
	}
}

// An MCP client whose token is refused looks for OAuth's metadata; it gets
// a plain 404, not the UI.
func TestWellKnownIsNotTheUI(t *testing.T) {
	_, s := newMCPServer(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
		"/devops/kartal/.well-known/oauth-protected-resource/", "/.well-known/openid-configuration"} {
		rec := do(s, "GET", p, "", "")
		if rec.Code != http.StatusNotFound || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %s", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	// With the token in the path's place, discovery reaches the endpoint,
	// which does not answer GET.
	if rec := do(s, "GET", "/.well-known/oauth-protected-resource/devops/kartal/api/v1/mcp", "", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("path-inserted discovery: %d", rec.Code)
	}
	if rec := do(s, "GET", "/devops/kartal/", "", ""); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("the UI: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestToolTextIsCut(t *testing.T) {
	rec := &toolResponse{header: http.Header{}, status: 200}
	// "ü" is two bytes; the cut falls inside one.
	rec.Write([]byte(strings.Repeat("a", maxToolText-1)))
	rec.Write([]byte(strings.Repeat("ü", 30000)))
	text := rec.text()
	body, note, ok := strings.Cut(text, "\n\n[cut: ")
	if !ok || !utf8.ValidString(text) || len(body) != maxToolText-1 || !strings.Contains(note, "of 159999 bytes") {
		t.Errorf("%d bytes, note %q", len(body), note)
	}
	small := &toolResponse{header: http.Header{}, status: 200}
	small.Write([]byte("ok"))
	if small.text() != "ok" {
		t.Error(small.text())
	}
}

func TestResolveKind(t *testing.T) {
	for in, want := range map[string][2]string{
		"Deployment": {"Deployment", "apps/v1/deployments"}, "deployments": {"Deployment", "apps/v1/deployments"},
		"deploy": {"Deployment", "apps/v1/deployments"}, "hpa": {"HorizontalPodAutoscaler", "autoscaling/v2/horizontalpodautoscalers"},
		"v1/pods": {"", "core/v1/pods"}, "traefik.io/v1alpha1/middlewares": {"", "traefik.io/v1alpha1/middlewares"},
	} {
		kind, gvr, err := resolveKind(in)
		if err != nil || kind != want[0] || gvr != want[1] {
			t.Errorf("resolveKind(%q) = %q, %q, %v", in, kind, gvr, err)
		}
	}
	for _, bad := range []string{"", "gizmo", "a/b/c/d"} {
		if _, _, err := resolveKind(bad); err == nil {
			t.Errorf("resolveKind(%q) found something", bad)
		}
	}
}

// A tool's call is logged with the tool's name, and a failed one as a
// warning, though the endpoint answers 200.
func TestMCPToolsAreLogged(t *testing.T) {
	_, s := newMCPServer(t)
	var buf bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if _, failed := call(t, s, viewerTok, "list_clusters", nil); failed {
		t.Fatal("list_clusters failed")
	}
	if _, failed := call(t, s, viewerTok, "list_objects", map[string]any{"cluster": "nowhere", "kind": "pods"}); !failed {
		t.Fatal("an unknown cluster did not fail")
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "mcp tool" {
			lines = append(lines, m)
		}
	}
	if len(lines) != 2 || lines[0]["tool"] != "list_clusters" || lines[0]["level"] != "INFO" || lines[0]["user"] != "ekip" ||
		lines[1]["tool"] != "list_objects" || lines[1]["level"] != "WARN" || lines[1]["status"] != float64(404) {
		t.Errorf("logged: %v", lines)
	}
}
