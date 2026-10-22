package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Network checks reach any address from inside the cluster: admins only,
// and written to the audit log. NetworkPolicies are for whoever sees the
// namespace.
func TestNetworkRoutes(t *testing.T) {
	_, s := newRoleServer()
	checks := "/api/v1/clusters/demo/net-checks"
	body := `{"targets":["db.example.org:5432"],"agent":true,"nodes":["n1"]}`
	for _, c := range []struct {
		method, path, token, body string
		want                      int
	}{
		{"POST", checks, viewerTok, body, http.StatusForbidden},
		{"POST", checks, operatorTok, body, http.StatusForbidden},
		{"GET", checks + "/abcdef0123456789", operatorTok, "", http.StatusForbidden},
		{"POST", checks, adminTok, `{"targets":["db"]}`, http.StatusBadRequest},
		{"POST", checks, adminTok, `{"targets":[]}`, http.StatusBadRequest},
		{"POST", checks, adminTok, `{"targets":["a:1"],"nodes":[` + strings.Repeat(`"n",`, 64) + `"n"]}`, http.StatusBadRequest},
		// Allowed: the agent is simply not connected.
		{"POST", checks, adminTok, body, http.StatusServiceUnavailable},
		{"GET", checks + "/abcdef0123456789", adminTok, "", http.StatusServiceUnavailable},
		{"GET", "/api/v1/clusters/demo/namespaces/a/pods/p/network-policies?port=8082", viewerTok, "", http.StatusServiceUnavailable},
	} {
		if rec := do(s, c.method, c.path, c.token, c.body); rec.Code != c.want {
			t.Errorf("%s %s as %q: %d, want %d (%s)", c.method, c.path, c.token, rec.Code, c.want, rec.Body)
		}
	}
	var entries []AuditEntry
	json.Unmarshal(do(s, "GET", "/api/v1/audit", adminTok, "").Body.Bytes(), &entries)
	if len(entries) != 1 || entries[0].Action != protocol.CommandNetCheck || entries[0].Detail != "db.example.org:5432 from agent, n1" {
		t.Errorf("audit: %+v", entries)
	}
}

func TestNetCheckReachesAgent(t *testing.T) {
	st, s := newRoleServer()
	st.PutSnapshot("demo", &protocol.Snapshot{}, time.Now())
	got := make(chan protocol.Command, 1)
	go func() {
		cmds, err := st.TakeCommands(context.Background(), "demo", time.Second)
		if err != nil || len(cmds) != 1 {
			close(got)
			return
		}
		got <- cmds[0]
		st.Deliver("demo", protocol.Result{CommandID: cmds[0].ID, OK: true, Output: `{"agent":[]}`})
	}()
	rec := do(s, "POST", "/api/v1/clusters/demo/net-checks", adminTok, `{"targets":["db.example.org:05432"," db.example.org:5432"],"agent":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	cmd := <-got
	var req protocol.NetCheckRequest
	json.Unmarshal([]byte(cmd.Body), &req)
	if cmd.Type != protocol.CommandNetCheck || len(req.Targets) != 1 || req.Targets[0] != "db.example.org:5432" || !req.Agent {
		t.Errorf("command: %+v %+v", cmd, req)
	}
}
