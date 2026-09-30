// Package api is the HTTP interface of the Kartal Gözü server: agent
// endpoints (report, command long-poll, results) and the management API.
package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/history"
	"github.com/BerkeKartal/kartal-gozu/internal/httpx"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/ui"
)

const (
	maxReportCompressed = 16 << 20
	maxReportDecoded    = 64 << 20
	maxResultBytes      = 8 << 20
)

type Config struct {
	// AgentTokens maps each agent token to the cluster it may report for.
	AgentTokens map[string]string
	// Users maps UI and API tokens to named users with a role. AdminToken,
	// if set, is one more user named "admin". With neither, everyone is let
	// in as an anonymous admin (local testing only).
	Users      map[string]auth.User
	AdminToken string
	// StaleAfter marks a cluster offline when its agent has been silent longer.
	StaleAfter time.Duration
	// MaxPollWait caps how long an agent's command poll is held open.
	MaxPollWait time.Duration
	// CommandTimeout is how long a management call waits for the agent's answer.
	CommandTimeout time.Duration
	// Alerts, if set, is shown every snapshot and every silent agent.
	Alerts *alert.Manager
	// History keeps the usage behind the charts; New makes one when it is nil.
	History *history.Store
	// Mail, when set, lets admins set up the e-mail channel in the UI.
	Mail *settings.Mail
}

type Server struct {
	cfg     Config
	st      *store.Store
	log     *slog.Logger
	now     func() time.Time
	users   *auth.Directory
	history *history.Store
	audit   *auditLog
	handler http.Handler
}

// New returns the server. It answers under any path prefix (see
// withAnyPrefix), so it can sit at the root of a host or below a path such
// as /devops/kartal without being told.
func New(cfg Config, st *store.Store, log *slog.Logger) *Server {
	users := map[string]auth.User{}
	for t, u := range cfg.Users {
		users[t] = u
	}
	if cfg.AdminToken != "" {
		users[cfg.AdminToken] = auth.User{Name: "admin", Role: auth.Admin}
	}
	hist := cfg.History
	if hist == nil {
		hist = history.New()
	}
	s := &Server{cfg: cfg, st: st, log: log, now: time.Now, users: auth.NewDirectory(users), history: hist, audit: newAuditLog()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)

	mux.HandleFunc("POST /agent/v1/report", s.agent(s.report))
	mux.HandleFunc("GET /agent/v1/commands", s.agent(s.commands))
	mux.HandleFunc("POST /agent/v1/results", s.agent(s.results))

	// Lists come from the latest snapshot. Namespaced kinds take ?namespace=;
	// those with a problem test also take ?problems=true.
	const c = "GET /api/v1/clusters/{cluster}"
	mux.HandleFunc("GET /api/v1/clusters", s.require(auth.Viewer, s.listClusters))
	mux.HandleFunc(c, s.require(auth.Viewer, s.getCluster))
	mux.HandleFunc(c+"/nodes", snapshotList(s, func(x *protocol.Snapshot) []protocol.Node { return x.Nodes }, nil,
		func(n protocol.Node) bool { return !n.Ready || len(n.Pressure) > 0 }))
	mux.HandleFunc(c+"/namespaces", s.require(auth.Viewer, s.namespaces))
	mux.HandleFunc(c+"/workloads", snapshotList(s, func(x *protocol.Snapshot) []protocol.Workload { return x.Workloads },
		func(x protocol.Workload) string { return x.Namespace }, protocol.Workload.Degraded))
	mux.HandleFunc(c+"/pods", snapshotList(s, func(x *protocol.Snapshot) []protocol.Pod { return x.Pods },
		func(x protocol.Pod) string { return x.Namespace }, func(p protocol.Pod) bool { return !p.Healthy() }))
	mux.HandleFunc(c+"/services", snapshotList(s, func(x *protocol.Snapshot) []protocol.Service { return x.Services },
		func(x protocol.Service) string { return x.Namespace }, nil))
	mux.HandleFunc(c+"/ingresses", snapshotList(s, func(x *protocol.Snapshot) []protocol.Ingress { return x.Ingresses },
		func(x protocol.Ingress) string { return x.Namespace }, nil))
	mux.HandleFunc(c+"/configmaps", snapshotList(s, func(x *protocol.Snapshot) []protocol.ObjectRef { return x.ConfigMaps }, refNamespace, nil))
	mux.HandleFunc(c+"/secrets", snapshotList(s, func(x *protocol.Snapshot) []protocol.ObjectRef { return x.Secrets }, refNamespace, nil))
	mux.HandleFunc(c+"/volumeclaims", snapshotList(s, func(x *protocol.Snapshot) []protocol.VolumeClaim { return x.VolumeClaims },
		func(x protocol.VolumeClaim) string { return x.Namespace }, func(v protocol.VolumeClaim) bool { return v.Phase != "Bound" }))
	mux.HandleFunc(c+"/jobs", snapshotList(s, func(x *protocol.Snapshot) []protocol.Job { return x.Jobs },
		func(x protocol.Job) string { return x.Namespace }, protocol.Job.HasFailed))
	mux.HandleFunc(c+"/cronjobs", snapshotList(s, func(x *protocol.Snapshot) []protocol.CronJob { return x.CronJobs },
		func(x protocol.CronJob) string { return x.Namespace }, nil))
	mux.HandleFunc(c+"/events", snapshotList(s, func(x *protocol.Snapshot) []protocol.Event { return x.Events },
		func(x protocol.Event) string { return x.Namespace }, nil))

	mux.HandleFunc(c+"/namespaces/{ns}/pods/{pod}/logs", s.require(auth.Viewer, s.podLogs))
	mux.HandleFunc("POST /api/v1/clusters/{cluster}/namespaces/{ns}/workloads/{kind}/{name}/restart", s.require(auth.Operator, s.restart))
	mux.HandleFunc("POST /api/v1/clusters/{cluster}/namespaces/{ns}/workloads/{kind}/{name}/scale", s.require(auth.Operator, s.scale))

	// Any resource type, CRDs included, fetched live from the agent.
	mux.HandleFunc(c+"/resources", s.require(auth.Viewer, s.discover))
	mux.HandleFunc(c+"/resources/{group}/{version}/{resource}", s.require(auth.Viewer, s.listResource))
	mux.HandleFunc(c+"/resources/{group}/{version}/{resource}/{name}", s.require(auth.Viewer, s.getResource))

	s.routeActions(mux)
	s.routeSettings(mux)

	// The web UI: its files below /_ui/, the page itself everywhere else.
	mux.Handle("GET /_ui/", ui.Assets())
	mux.HandleFunc("GET /", s.page)

	s.handler = withAnyPrefix(mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Watch runs the server's periodic work until ctx ends: it tells the alert
// manager which agents have gone silent.
func (s *Server) Watch(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.cfg.Alerts == nil {
			continue
		}
		now := s.now()
		for _, ci := range s.st.Clusters() {
			if st := s.status(ci); st != statusNever {
				s.cfg.Alerts.AgentStatus(ci.Name, st == statusOnline, ci.LastSeen, now)
			}
		}
	}
}

// routeMarkers are the fixed roots of every route. Whatever precedes the
// first one is a deployment prefix and is ignored.
var routeMarkers = []string{"/api/v1/", "/agent/v1/", "/_ui/"}

func routeStart(escapedPath string) int {
	start := -1
	for _, m := range routeMarkers {
		if i := strings.Index(escapedPath, m); i >= 0 && (start < 0 || i < start) {
			start = i
		}
	}
	if start < 0 && strings.HasSuffix(escapedPath, "/healthz") {
		start = len(escapedPath) - len("/healthz")
	}
	return start
}

// withAnyPrefix strips an unknown leading path so the same server works at
// "/", "/devops/kartal" or any other location, whether or not the reverse
// proxy strips the prefix itself.
func withAnyPrefix(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()
		i := routeStart(escaped)
		if i <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		rest := escaped[i:]
		path, err := url.PathUnescape(rest)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid path")
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = path
		r2.URL.RawPath = ""
		if path != rest {
			r2.URL.RawPath = rest
		}
		next.ServeHTTP(w, r2)
	})
}

// page serves the web UI at every path that ends in "/", so it shows up
// wherever the server is mounted. Other paths get the slash added: the page
// loads its files and the API through relative URLs, which depend on it.
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case routeStart(r.URL.EscapedPath()) >= 0:
		writeError(w, http.StatusNotFound, "no such route")
	case strings.HasSuffix(p, "/"):
		ui.Index(w, r)
	case strings.Contains(path.Base(p), "."):
		writeError(w, http.StatusNotFound, "not found")
	default:
		escaped := r.URL.EscapedPath()
		// "./" keeps the target relative: a bare "http:evil.example/"
		// would be read as a URL of its own and leave the site.
		loc := "./" + escaped[strings.LastIndex(escaped, "/")+1:] + "/"
		if r.URL.RawQuery != "" {
			loc += "?" + r.URL.RawQuery
		}
		// Set by hand: http.Redirect would make it absolute, which breaks
		// behind a proxy that strips a path prefix.
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}
}

// ---------------------------------------------------------------- auth

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) agentCluster(r *http.Request) (string, bool) {
	tok := bearerToken(r)
	if tok == "" {
		return "", false
	}
	cluster := ""
	// Compare against every token so timing does not reveal which one matched.
	for t, c := range s.cfg.AgentTokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
			cluster = c
		}
	}
	return cluster, cluster != ""
}

func (s *Server) agent(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cluster, ok := s.agentCluster(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid agent token")
			return
		}
		next(w, r, cluster)
	}
}

type userKey struct{}

// require lets through users whose role is at least role, and puts the user
// in the request context for the audit log.
func (s *Server) require(role auth.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.users.Lookup(bearerToken(r))
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid or missing token")
			return
		}
		if u.Role < role {
			writeError(w, http.StatusForbidden, "the "+u.Role.String()+" role may not do this; it needs "+role.String())
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}
}

func userOf(r *http.Request) auth.User {
	u, _ := r.Context().Value(userKey{}).(auth.User)
	return u
}

// ---------------------------------------------------------------- agent side

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "ok\n")
}

func (s *Server) report(w http.ResponseWriter, r *http.Request, cluster string) {
	body := http.MaxBytesReader(w, r.Body, maxReportCompressed)
	var rd io.Reader = body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer zr.Close()
		rd = io.LimitReader(zr, maxReportDecoded)
	}
	var snap protocol.Snapshot
	if err := json.NewDecoder(rd).Decode(&snap); err != nil {
		writeError(w, http.StatusBadRequest, "invalid snapshot: "+err.Error())
		return
	}
	// The token decides which cluster this is, never the payload.
	snap.Cluster = cluster
	now := s.now()
	if err := s.st.PutSnapshot(cluster, &snap, now); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.history.Record(cluster, &snap, now)
	if s.cfg.Alerts != nil {
		s.cfg.Alerts.Observe(cluster, &snap, now)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) commands(w http.ResponseWriter, r *http.Request, cluster string) {
	wait := time.Duration(0)
	if v := r.URL.Query().Get("wait"); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil || secs < 0 {
			writeError(w, http.StatusBadRequest, "wait must be a non-negative number of seconds")
			return
		}
		wait = min(time.Duration(secs)*time.Second, s.cfg.MaxPollWait)
	}
	s.st.Touch(cluster, s.now())
	cmds, err := s.st.TakeCommands(r.Context(), cluster, wait)
	if err != nil {
		if r.Context().Err() == nil {
			writeError(w, http.StatusNotFound, err.Error())
		}
		return
	}
	s.st.Touch(cluster, s.now())
	if len(cmds) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, cmds)
}

func (s *Server) results(w http.ResponseWriter, r *http.Request, cluster string) {
	var res protocol.Result
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxResultBytes)).Decode(&res); err != nil {
		writeError(w, http.StatusBadRequest, "invalid result: "+err.Error())
		return
	}
	if !s.st.Deliver(cluster, res) {
		writeError(w, http.StatusNotFound, "unknown or expired command")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- management side

type counts struct {
	Nodes         int `json:"nodes"`
	NodesNotReady int `json:"nodesNotReady"`
	Namespaces    int `json:"namespaces"`
	objectCounts
}

type clusterSummary struct {
	Name             string     `json:"name"`
	Status           string     `json:"status"`
	LastSeen         *time.Time `json:"lastSeen,omitempty"`
	CollectedAt      *time.Time `json:"collectedAt,omitempty"`
	KubeVersion      string     `json:"kubeVersion,omitempty"`
	AgentVersion     string     `json:"agentVersion,omitempty"`
	MetricsAvailable bool       `json:"metricsAvailable"`
	// Capacity, Requests and Usage are summed over all nodes: allocatable,
	// promised to running pods, and in use (which needs metrics-server).
	Capacity *protocol.Resources `json:"capacity,omitempty"`
	Requests *protocol.Resources `json:"requests,omitempty"`
	Usage    *protocol.Resources `json:"usage,omitempty"`
	Counts   counts              `json:"counts"`
	Errors   []string            `json:"errors,omitempty"`
	// Capabilities are the actions the cluster's agent accepts beyond reading.
	Capabilities []string `json:"capabilities"`
	// Alerts counts the cluster's active problems.
	Alerts int `json:"alerts"`
}

const (
	statusOnline  = "online"
	statusOffline = "offline"
	statusNever   = "never-seen"
)

func (s *Server) status(ci store.ClusterInfo) string {
	switch {
	case ci.LastSeen.IsZero():
		return statusNever
	case s.now().Sub(ci.LastSeen) <= s.cfg.StaleAfter:
		return statusOnline
	default:
		return statusOffline
	}
}

func (s *Server) summarize(ci store.ClusterInfo) clusterSummary {
	sum := clusterSummary{Name: ci.Name, Status: s.status(ci), Capabilities: []string{}}
	if s.cfg.Alerts != nil {
		sum.Alerts = s.cfg.Alerts.ActiveCount(ci.Name)
	}
	if !ci.LastSeen.IsZero() {
		t := ci.LastSeen.UTC()
		sum.LastSeen = &t
	}
	snap := ci.Snapshot
	if snap == nil {
		return sum
	}
	t := snap.CollectedAt
	sum.CollectedAt = &t
	sum.KubeVersion, sum.AgentVersion, sum.Errors = snap.KubeVersion, snap.AgentVersion, snap.Errors
	sum.MetricsAvailable = snap.MetricsAvailable
	if snap.Capabilities != nil {
		sum.Capabilities = snap.Capabilities
	}
	total, _ := tally(snap)
	sum.Counts = counts{Nodes: len(snap.Nodes), Namespaces: len(snap.Namespaces), objectCounts: total}
	if len(snap.Nodes) > 0 {
		var capacity, requests, usage protocol.Resources
		for _, n := range snap.Nodes {
			if !n.Ready {
				sum.Counts.NodesNotReady++
			}
			capacity.CPUMilli += n.Allocatable.CPUMilli
			capacity.MemoryBytes += n.Allocatable.MemoryBytes
			capacity.Pods += n.Allocatable.Pods
			if n.Requests != nil {
				requests.CPUMilli += n.Requests.CPUMilli
				requests.MemoryBytes += n.Requests.MemoryBytes
			}
			if n.Usage != nil {
				usage.CPUMilli += n.Usage.CPUMilli
				usage.MemoryBytes += n.Usage.MemoryBytes
			}
		}
		sum.Capacity, sum.Requests = &capacity, &requests
		if snap.MetricsAvailable {
			sum.Usage = &usage
		}
	}
	return sum
}

func (s *Server) listClusters(w http.ResponseWriter, _ *http.Request) {
	all := s.st.Clusters()
	out := make([]clusterSummary, 0, len(all))
	for _, ci := range all {
		out = append(out, s.summarize(ci))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getCluster(w http.ResponseWriter, r *http.Request) {
	ci, ok := s.st.Cluster(r.PathValue("cluster"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return
	}
	writeJSON(w, http.StatusOK, s.summarize(ci))
}

// fromSnapshot answers from the cluster's latest snapshot. The ETag is a hash
// of the response itself: agents resend everything every interval, but a
// client that already holds the same content gets a bodiless 304, so the UI
// can refresh often and lists that did not change cost next to nothing.
func (s *Server) fromSnapshot(w http.ResponseWriter, r *http.Request, build func(*protocol.Snapshot) any) {
	ci, ok := s.st.Cluster(r.PathValue("cluster"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return
	}
	if ci.Snapshot == nil {
		writeError(w, http.StatusServiceUnavailable, "no data received from this cluster's agent yet")
		return
	}
	body, err := json.Marshal(build(ci.Snapshot))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode response: "+err.Error())
		return
	}
	body = append(body, '\n')
	sum := sha256.Sum256(body)
	etag := `W/"` + hex.EncodeToString(sum[:12]) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "private, no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		h.Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	httpx.Write(w, r, http.StatusOK, "application/json", body)
}

func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || strings.TrimPrefix(t, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
	}
	return false
}

func refNamespace(x protocol.ObjectRef) string { return x.Namespace }

// snapshotList serves one list from the latest snapshot. nsOf enables the
// ?namespace= filter and is nil for cluster-scoped kinds; problem enables
// ?problems=true, which keeps only the items that need attention.
func snapshotList[T any](s *Server, pick func(*protocol.Snapshot) []T, nsOf func(T) string, problem func(T) bool) http.HandlerFunc {
	return s.require(auth.Viewer, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ns := q.Get("namespace")
		onlyProblems := false
		if v := q.Get("problems"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil || (b && problem == nil) {
				writeError(w, http.StatusBadRequest, "problems must be true or false, and is only supported for nodes, workloads, pods, volumeclaims and jobs")
				return
			}
			onlyProblems = b
		}
		s.fromSnapshot(w, r, func(snap *protocol.Snapshot) any {
			items := pick(snap)
			out := make([]T, 0, len(items))
			for _, it := range items {
				if (ns == "" || nsOf == nil || nsOf(it) == ns) && (!onlyProblems || problem(it)) {
					out = append(out, it)
				}
			}
			return out
		})
	})
}

// namespaceSummary is a namespace with its per-kind counts, which the UI shows
// in its navigation and namespace list without downloading every object.
type namespaceSummary struct {
	protocol.Namespace
	objectCounts
}

func (s *Server) namespaces(w http.ResponseWriter, r *http.Request) {
	s.fromSnapshot(w, r, func(snap *protocol.Snapshot) any {
		_, byNS := tally(snap)
		out := make([]namespaceSummary, len(snap.Namespaces))
		for i, n := range snap.Namespaces {
			out[i].Namespace = n
			if c := byNS[n.Name]; c != nil {
				out[i].objectCounts = *c
			}
		}
		return out
	})
}

func (s *Server) podLogs(w http.ResponseWriter, r *http.Request) {
	tail := 0
	if v := r.URL.Query().Get("tail"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "tail must be a non-negative integer")
			return
		}
		tail = n
	}
	res, ok := s.dispatch(w, r, protocol.Command{
		Type:      protocol.CommandLogs,
		Namespace: r.PathValue("ns"),
		Name:      r.PathValue("pod"),
		Container: r.URL.Query().Get("container"),
		Previous:  r.URL.Query().Get("previous") == "true",
		TailLines: tail,
	})
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.Write(w, r, http.StatusOK, "text/plain; charset=utf-8", []byte(res.Output))
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	cmd := protocol.Command{
		Type:      protocol.CommandRestart,
		Namespace: r.PathValue("ns"),
		Kind:      r.PathValue("kind"),
		Name:      r.PathValue("name"),
	}
	s.act(w, r, cmd, cmd.Kind+"/"+cmd.Name, "")
}

func (s *Server) scale(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Replicas *int32 `json:"replicas"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil || body.Replicas == nil {
		writeError(w, http.StatusBadRequest, `body must be {"replicas": <number>}`)
		return
	}
	cmd := protocol.Command{
		Type:      protocol.CommandScale,
		Namespace: r.PathValue("ns"),
		Kind:      r.PathValue("kind"),
		Name:      r.PathValue("name"),
		Replicas:  body.Replicas,
	}
	s.act(w, r, cmd, cmd.Kind+"/"+cmd.Name, fmt.Sprintf("replicas=%d", *body.Replicas))
}

func (s *Server) discover(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.dispatch(w, r, protocol.Command{Type: protocol.CommandResources}); ok {
		writeRawJSON(w, r, res.Output)
	}
}

// resourceCommand reads the group/version/resource path; "core" names the
// core API group, which has no name of its own.
func resourceCommand(r *http.Request, typ string) protocol.Command {
	group := r.PathValue("group")
	if group == "core" {
		group = ""
	}
	return protocol.Command{
		Type:      typ,
		Group:     group,
		Version:   r.PathValue("version"),
		Resource:  r.PathValue("resource"),
		Name:      r.PathValue("name"),
		Namespace: r.URL.Query().Get("namespace"),
	}
}

func (s *Server) listResource(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.dispatch(w, r, resourceCommand(r, protocol.CommandList)); ok {
		writeRawJSON(w, r, res.Output)
	}
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.dispatch(w, r, resourceCommand(r, protocol.CommandGet)); ok {
		writeRawJSON(w, r, res.Output)
	}
}

// dispatch sends a command to the cluster's agent and waits for its result.
// On failure it writes the error response itself and returns false, with the
// reason in the result for the audit log.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, cmd protocol.Command) (protocol.Result, bool) {
	fail := func(status int, msg string) (protocol.Result, bool) {
		writeError(w, status, msg)
		return protocol.Result{Error: msg}, false
	}
	name := r.PathValue("cluster")
	ci, ok := s.st.Cluster(name)
	if !ok {
		return fail(http.StatusNotFound, "unknown cluster")
	}
	if s.status(ci) != statusOnline {
		return fail(http.StatusServiceUnavailable, "the agent of this cluster is not connected")
	}
	cmd.ID = newID()
	ch, cancel, err := s.st.Enqueue(name, cmd)
	if err != nil {
		return fail(http.StatusNotFound, err.Error())
	}
	// A command the agent has not taken yet is withdrawn; one it has taken
	// can still finish after this call has given up.
	defer cancel()

	ctx, stop := context.WithTimeout(r.Context(), s.cfg.CommandTimeout)
	defer stop()
	select {
	case res := <-ch:
		if !res.OK {
			writeError(w, http.StatusBadGateway, res.Error)
			return res, false
		}
		return res, true
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fail(http.StatusGatewayTimeout, "the agent did not answer in time; the command may still have run")
		}
		return protocol.Result{Error: "the request was cancelled"}, false
	}
}

// ---------------------------------------------------------------- helpers

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeRawJSON passes through JSON the agent already produced.
func writeRawJSON(w http.ResponseWriter, r *http.Request, body string) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.Write(w, r, http.StatusOK, "application/json", []byte(body))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
