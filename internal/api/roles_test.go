package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const (
	viewerTok   = "viewer-token-0123456789"
	operatorTok = "operator-token-0123456789"
	adminTok    = "admin-token-0123456789"
)

func newRoleServer() (*store.Store, *Server) {
	st := store.New("demo")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"},
		Users: map[string]auth.User{
			viewerTok:   {Name: "ekip", Role: auth.Viewer},
			operatorTok: {Name: "nobet", Role: auth.Operator},
		},
		AdminToken:     adminTok,
		StaleAfter:     time.Minute,
		MaxPollWait:    time.Second,
		CommandTimeout: time.Second,
	}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return st, s
}

func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRoles(t *testing.T) {
	// No agent has reported: an allowed action ends at "not connected" (503).
	_, s := newRoleServer()
	restart := "/api/v1/clusters/demo/namespaces/a/workloads/deployment/web/restart"
	exec := "/api/v1/clusters/demo/namespaces/a/pods/p/exec"
	cases := []struct {
		method, path, token, body string
		want                      int
	}{
		{"GET", "/api/v1/clusters", "", "", 401},
		{"GET", "/api/v1/clusters", "wrong-token-0123456789", "", 401},
		{"GET", "/api/v1/clusters", viewerTok, "", 200},
		{"POST", restart, viewerTok, "", 403},
		// An operator passes the role check; the agent is simply not connected.
		{"POST", restart, operatorTok, "", 503},
		{"DELETE", "/api/v1/clusters/demo/namespaces/a/pods/p", viewerTok, "", 403},
		{"POST", exec, operatorTok, `{"command":["ls"]}`, 403},
		{"POST", exec, adminTok, `{"command":["ls"]}`, 503},
		{"PUT", "/api/v1/clusters/demo/resources/core/v1/configmaps/c?namespace=a", operatorTok, "kind: ConfigMap", 403},
		{"GET", "/api/v1/audit", viewerTok, "", 403},
		{"GET", "/api/v1/audit", operatorTok, "", 200},
		{"POST", "/api/v1/alerts/test", operatorTok, "", 403},
	}
	for _, c := range cases {
		if rec := do(s, c.method, c.path, c.token, c.body); rec.Code != c.want {
			t.Errorf("%s %s as %q: %d, want %d (%s)", c.method, c.path, c.token, rec.Code, c.want, rec.Body)
		}
	}

	var me map[string]string
	json.Unmarshal(do(s, "GET", "/api/v1/me", operatorTok, "").Body.Bytes(), &me)
	if me["name"] != "nobet" || me["role"] != "operator" {
		t.Errorf("me: %v", me)
	}
	json.Unmarshal(do(s, "GET", "/api/v1/me", adminTok, "").Body.Bytes(), &me)
	if me["name"] != "admin" || me["role"] != "admin" {
		t.Errorf("the admin token is the admin user: %v", me)
	}

	// The operator's restart attempt is in the audit log, with its failure.
	var entries []AuditEntry
	json.Unmarshal(do(s, "GET", "/api/v1/audit", operatorTok, "").Body.Bytes(), &entries)
	if len(entries) != 2 || entries[0].User != "admin" || entries[0].Action != "exec" || entries[1].User != "nobet" ||
		entries[1].Action != "restart" || entries[1].OK || entries[1].Object != "deployment/web" ||
		entries[1].Error != "the agent of this cluster is not connected" {
		t.Errorf("audit: %+v", entries)
	}
}

func TestBadActionBodies(t *testing.T) {
	st, s := newRoleServer()
	st.PutSnapshot("demo", &protocol.Snapshot{}, time.Now())
	for path, body := range map[string]string{
		"/api/v1/clusters/demo/nodes/n1/cordon":                          `{}`,
		"/api/v1/clusters/demo/namespaces/a/cronjobs/c/suspend":          `{"suspend":"yes"}`,
		"/api/v1/clusters/demo/namespaces/a/deployments/d/rollback":      `{"revision":0}`,
		"/api/v1/clusters/demo/namespaces/a/pods/p/exec":                 `{"command":[]}`,
		"/api/v1/clusters/demo/resources/core/v1/configmaps/c?namespace": "",
	} {
		method := "POST"
		if strings.Contains(path, "/resources/") {
			method = "PUT"
		}
		if rec := do(s, method, path, adminTok, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s: %d, want 400 (%s)", method, body, rec.Code, rec.Body)
		}
	}
}

func TestDescribeExec(t *testing.T) {
	script := "cd \"$1\" 2>/dev/null || cd /\nls -la /app\n__kg=$?\nprintf '\\n\\037%s' \"$(pwd)\"\nexit $__kg"
	if got := describeExec("web", []string{"sh", "-c", script, "kartal", "/"}); got != "[web] ls -la /app" {
		t.Errorf("got %q", got)
	}
}
