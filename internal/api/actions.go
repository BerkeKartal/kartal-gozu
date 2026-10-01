package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/history"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	maxYAMLBytes  = 1 << 20
	maxExecArgs   = 64
	maxExecBytes  = 64 << 10
	keepAudit     = 1000
	defaultWindow = time.Hour
)

// routeActions adds everything beyond the snapshot lists: object details,
// the actions that change a cluster, metrics history, alerts and audit.
func (s *Server) routeActions(mux *http.ServeMux) {
	const c = "/api/v1/clusters/{cluster}"
	mux.HandleFunc("GET /api/v1/me", s.require(auth.Viewer, s.me))
	mux.HandleFunc("GET "+c+"/object-events", s.inCluster(auth.Viewer, queryNamespace, s.objectEvents))
	mux.HandleFunc("GET "+c+"/namespaces/{ns}/deployments/{name}/history", s.inCluster(auth.Viewer, pathNamespace, s.rolloutHistory))
	mux.HandleFunc("GET "+c+"/helm", s.inCluster(auth.Viewer, anywhere, s.helm))
	mux.HandleFunc("GET "+c+"/metrics", s.inCluster(auth.Viewer, anywhere, s.metrics))

	mux.HandleFunc("DELETE "+c+"/namespaces/{ns}/pods/{pod}", s.inCluster(auth.Operator, pathNamespace, s.deletePod))
	mux.HandleFunc("POST "+c+"/nodes/{node}/cordon", s.inCluster(auth.Operator, wholeCluster, s.cordon))
	mux.HandleFunc("POST "+c+"/namespaces/{ns}/cronjobs/{name}/suspend", s.inCluster(auth.Operator, pathNamespace, s.suspend))
	mux.HandleFunc("POST "+c+"/namespaces/{ns}/cronjobs/{name}/trigger", s.inCluster(auth.Operator, pathNamespace, s.trigger))
	mux.HandleFunc("POST "+c+"/namespaces/{ns}/deployments/{name}/rollback", s.inCluster(auth.Operator, pathNamespace, s.rollback))

	mux.HandleFunc("POST "+c+"/namespaces/{ns}/pods/{pod}/exec", s.inCluster(auth.Admin, pathNamespace, s.exec))
	mux.HandleFunc("PUT "+c+"/resources/{group}/{version}/{resource}/{name}", s.inCluster(auth.Admin, queryNamespace, s.apply))

	mux.HandleFunc("GET /api/v1/alerts", s.require(auth.Viewer, s.alerts))
	mux.HandleFunc("POST /api/v1/alerts/test", s.requireEverywhere(auth.Admin, s.testAlerts))
	mux.HandleFunc("GET /api/v1/audit", s.require(auth.Operator, s.auditEntries))
}

// ---------------------------------------------------------------- audit

// AuditEntry records one change someone made through Kartal Gözü.
type AuditEntry struct {
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace,omitempty"`
	Object    string    `json:"object"`
	Detail    string    `json:"detail,omitempty"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
}

// auditLog keeps the latest entries in memory; every entry is also logged,
// which is the record that survives a restart.
type auditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func newAuditLog() *auditLog { return &auditLog{} }

func (a *auditLog) add(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	if len(a.entries) > keepAudit {
		a.entries = a.entries[len(a.entries)-keepAudit:]
	}
}

func (a *auditLog) newestFirst() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEntry, 0, len(a.entries))
	for i := len(a.entries) - 1; i >= 0; i-- {
		out = append(out, a.entries[i])
	}
	return out
}

func (s *Server) record(r *http.Request, cmd protocol.Command, object, detail string, res protocol.Result, ok bool) {
	u := userOf(r)
	e := AuditEntry{
		Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: cmd.Type,
		Cluster: r.PathValue("cluster"), Namespace: cmd.Namespace, Object: object, Detail: detail, OK: ok,
	}
	if !ok {
		e.Error = res.Error
		if e.Error == "" {
			e.Error = "failed"
		}
	}
	s.audit.add(e)
	s.log.Info("audit", "user", e.User, "action", e.Action, "cluster", e.Cluster, "namespace", e.Namespace,
		"object", e.Object, "detail", e.Detail, "ok", e.OK, "error", e.Error)
}

// act dispatches a command that changes something, records it and answers
// with the agent's message.
func (s *Server) act(w http.ResponseWriter, r *http.Request, cmd protocol.Command, object, detail string) {
	res, ok := s.dispatch(w, r, cmd)
	s.record(r, cmd, object, detail, res, ok)
	if ok {
		writeJSON(w, http.StatusOK, map[string]string{"message": res.Output})
	}
}

// auditEntries shows each operator the changes made where they are one;
// changes to the server itself only to operators over everything.
func (s *Server) auditEntries(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	out := []AuditEntry{}
	for _, e := range s.audit.newestFirst() {
		role := u.Everywhere()
		if e.Cluster != "" {
			role = u.RoleIn(e.Cluster, e.Namespace)
		}
		if role >= auth.Operator {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- reads

type grantView struct {
	Role   string       `json:"role"`
	Scopes []auth.Scope `json:"scopes"`
}

// me tells the UI who is signed in and what they may do where, so it can
// offer only what the server will allow.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	grants := []grantView{}
	if u.Grants == nil {
		grants = append(grants, grantView{Role: u.Role.String(), Scopes: []auth.Scope{}})
	}
	for _, g := range u.Grants {
		scopes := g.Scopes
		if scopes == nil {
			scopes = []auth.Scope{}
		}
		grants = append(grants, grantView{Role: g.Role.String(), Scopes: scopes})
	}
	// The levels at which the UI marks volumes and certificates, as the
	// alerts do.
	volumeWarn, volumeCrit := s.cfg.Alerts.VolumeLevels()
	certWarn, certCrit := s.cfg.Alerts.CertificateLevels()
	writeJSON(w, http.StatusOK, map[string]any{"name": u.Name, "role": u.Role.String(), "everywhere": u.Everywhere().String(), "grants": grants,
		"levels": map[string]any{"volumeWarning": volumeWarn, "volumeCritical": volumeCrit,
			"certificateWarningDays": certWarn.Hours() / 24, "certificateCriticalDays": certCrit.Hours() / 24}})
}

func (s *Server) objectEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if res, ok := s.dispatch(w, r, protocol.Command{Type: protocol.CommandEvents, Kind: q.Get("kind"), Namespace: q.Get("namespace"), Name: q.Get("name")}); ok {
		writeRawJSON(w, r, res.Output)
	}
}

func (s *Server) rolloutHistory(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.dispatch(w, r, protocol.Command{Type: protocol.CommandHistory, Namespace: r.PathValue("ns"), Name: r.PathValue("name")}); ok {
		writeRawJSON(w, r, res.Output)
	}
}

// helm lists the Helm releases in the namespaces the user may see.
func (s *Server) helm(w http.ResponseWriter, r *http.Request) {
	res, ok := s.dispatch(w, r, protocol.Command{Type: protocol.CommandHelm})
	if !ok {
		return
	}
	u, cluster := userOf(r), r.PathValue("cluster")
	if u.RoleIn(cluster, "") >= auth.Viewer {
		writeRawJSON(w, r, res.Output)
		return
	}
	var all []protocol.HelmRelease
	if err := json.Unmarshal([]byte(res.Output), &all); err != nil {
		writeError(w, http.StatusBadGateway, "the agent's Helm list could not be read: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, keep(all, func(h protocol.HelmRelease) bool { return u.RoleIn(cluster, h.Namespace) >= auth.Viewer }))
}

// metrics answers with the recorded usage of the cluster, a node or a pod:
// ?kind=cluster|node|pod&namespace=&name=&hours=1..6.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("cluster")
	if _, ok := s.st.Cluster(name); !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return
	}
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind != "cluster" && kind != "node" && kind != "pod" {
		writeError(w, http.StatusBadRequest, "kind must be cluster, node or pod")
		return
	}
	// A pod's usage is its namespace's; a node's and the cluster's belong
	// to the whole cluster.
	where := ""
	if kind == "pod" {
		if where = q.Get("namespace"); where == "" {
			writeError(w, http.StatusBadRequest, "a pod's usage needs ?namespace=")
			return
		}
	}
	if userOf(r).RoleIn(name, where) < auth.Viewer {
		writeError(w, http.StatusForbidden, "you have no access to this usage")
		return
	}
	window := defaultWindow
	if v := q.Get("hours"); v != "" {
		h, err := strconv.Atoi(v)
		if err != nil || h < 1 || h > history.Points/60 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("hours must be between 1 and %d", history.Points/60))
			return
		}
		window = time.Duration(h) * time.Hour
	}
	pts := s.history.Query(name, history.Key(kind, q.Get("namespace"), q.Get("name")), window, s.now())
	body, _ := json.Marshal(map[string]any{"step": 60, "points": pts})
	w.Header().Set("Cache-Control", "no-store")
	writeRawJSON(w, r, string(body))
}

// ---------------------------------------------------------------- changes

// readJSON decodes a small request body or answers 400.
func readJSON(w http.ResponseWriter, r *http.Request, v any, hint string) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "body must be "+hint)
		return false
	}
	return true
}

func (s *Server) deletePod(w http.ResponseWriter, r *http.Request) {
	cmd := protocol.Command{Type: protocol.CommandDelete, Namespace: r.PathValue("ns"), Kind: "pod", Name: r.PathValue("pod")}
	s.act(w, r, cmd, "Pod/"+cmd.Name, "")
}

func (s *Server) cordon(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Unschedulable *bool `json:"unschedulable"`
	}
	if !readJSON(w, r, &body, `{"unschedulable": true|false}`) {
		return
	}
	if body.Unschedulable == nil {
		writeError(w, http.StatusBadRequest, `body must be {"unschedulable": true|false}`)
		return
	}
	cmd := protocol.Command{Type: protocol.CommandCordon, Name: r.PathValue("node"), Flag: body.Unschedulable}
	s.act(w, r, cmd, "Node/"+cmd.Name, fmt.Sprintf("unschedulable=%t", *body.Unschedulable))
}

func (s *Server) suspend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Suspend *bool `json:"suspend"`
	}
	if !readJSON(w, r, &body, `{"suspend": true|false}`) {
		return
	}
	if body.Suspend == nil {
		writeError(w, http.StatusBadRequest, `body must be {"suspend": true|false}`)
		return
	}
	cmd := protocol.Command{Type: protocol.CommandSuspend, Namespace: r.PathValue("ns"), Name: r.PathValue("name"), Flag: body.Suspend}
	s.act(w, r, cmd, "CronJob/"+cmd.Name, fmt.Sprintf("suspend=%t", *body.Suspend))
}

func (s *Server) trigger(w http.ResponseWriter, r *http.Request) {
	cmd := protocol.Command{Type: protocol.CommandTrigger, Namespace: r.PathValue("ns"), Name: r.PathValue("name")}
	s.act(w, r, cmd, "CronJob/"+cmd.Name, "")
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Revision int64 `json:"revision"`
	}
	if !readJSON(w, r, &body, `{"revision": N}`) {
		return
	}
	if body.Revision < 1 {
		writeError(w, http.StatusBadRequest, "revision must be a positive number")
		return
	}
	cmd := protocol.Command{Type: protocol.CommandRollback, Namespace: r.PathValue("ns"), Name: r.PathValue("name"), Revision: body.Revision}
	s.act(w, r, cmd, "Deployment/"+cmd.Name, fmt.Sprintf("revision=%d", body.Revision))
}

// exec runs a command in a container: {"container": "...", "command": [...]}.
func (s *Server) exec(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Container string   `json:"container"`
		Command   []string `json:"command"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxExecBytes)).Decode(&body); err != nil || len(body.Command) == 0 || len(body.Command) > maxExecArgs {
		writeError(w, http.StatusBadRequest, `body must be {"container": "...", "command": ["sh", "-c", "..."]}`)
		return
	}
	cmd := protocol.Command{Type: protocol.CommandExec, Namespace: r.PathValue("ns"), Name: r.PathValue("pod"), Container: body.Container, Exec: body.Command}
	res, ok := s.dispatch(w, r, cmd)
	s.record(r, cmd, "Pod/"+cmd.Name, describeExec(body.Container, body.Command), res, ok)
	if ok {
		writeRawJSON(w, r, res.Output)
	}
}

// describeExec shortens a command for the audit log, dropping the UI's
// wrapper around what the user typed.
func describeExec(container string, argv []string) string {
	text := strings.Join(argv, " ")
	if len(argv) == 5 && argv[0] == "sh" && argv[1] == "-c" {
		lines := strings.Split(argv[2], "\n")
		if len(lines) > 4 {
			text = strings.Join(lines[1:len(lines)-3], "; ")
		}
	}
	if len(text) > 500 {
		text = text[:500] + "…"
	}
	if container != "" {
		return "[" + container + "] " + text
	}
	return text
}

// apply replaces an object with the YAML body; ?dryRun=true only shows what
// the API server would save.
func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxYAMLBytes))
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		writeError(w, http.StatusBadRequest, "the body must be the object's YAML, at most 1 MiB")
		return
	}
	cmd := resourceCommand(r, protocol.CommandApply)
	cmd.Body = string(b)
	cmd.DryRun = r.URL.Query().Get("dryRun") == "true"
	res, ok := s.dispatch(w, r, cmd)
	if !cmd.DryRun {
		group := cmd.Group
		if group == "" {
			group = "core"
		}
		s.record(r, cmd, group+"/"+cmd.Resource+"/"+cmd.Name, "", res, ok)
	}
	if ok {
		writeRawJSON(w, r, res.Output)
	}
}

// ---------------------------------------------------------------- alerts

// alerts shows each user the problems where they have a role. The
// deliveries name only how many problems a message had, so they stay.
func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Alerts == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "active": []any{}, "recent": []any{}, "channels": []any{}, "deliveries": []any{}})
		return
	}
	u := userOf(r)
	st := s.cfg.Alerts.State()
	visibleTo := func(a alert.Alert) bool { return alertVisible(u, a) }
	st.Active, st.Recent = keep(st.Active, visibleTo), keep(st.Recent, visibleTo)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) testAlerts(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Alerts == nil || len(s.cfg.Alerts.Channels()) == 0 {
		writeError(w, http.StatusConflict, "no notification channel is configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	results := s.cfg.Alerts.Test(ctx)
	u := userOf(r)
	s.audit.add(AuditEntry{Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: "test-notification", Object: "alerts", OK: true})
	writeJSON(w, http.StatusOK, results)
}
