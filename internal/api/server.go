// Package api is the HTTP interface of the Kartal Gözü server: agent
// endpoints (report, command long-poll, results) and the management API.
package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const (
	maxReportCompressed = 16 << 20
	maxReportDecoded    = 64 << 20
	maxResultBytes      = 8 << 20
)

type Config struct {
	// AgentTokens maps each agent token to the cluster it may report for.
	AgentTokens map[string]string
	// AdminToken protects the management API; empty disables the check.
	AdminToken string
	// StaleAfter marks a cluster offline when its agent has been silent longer.
	StaleAfter time.Duration
	// MaxPollWait caps how long an agent's command poll is held open.
	MaxPollWait time.Duration
	// CommandTimeout is how long a management call waits for the agent's answer.
	CommandTimeout time.Duration
}

type Server struct {
	cfg Config
	st  *store.Store
	log *slog.Logger
	now func() time.Time
}

// New returns the server's handler. It answers under any path prefix
// (see withAnyPrefix), so it can sit at the root of a host or below a path
// such as /devops/kartal without being told.
func New(cfg Config, st *store.Store, log *slog.Logger) http.Handler {
	s := &Server{cfg: cfg, st: st, log: log, now: time.Now}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)

	mux.HandleFunc("POST /agent/v1/report", s.agent(s.report))
	mux.HandleFunc("GET /agent/v1/commands", s.agent(s.commands))
	mux.HandleFunc("POST /agent/v1/results", s.agent(s.results))

	const c = "GET /api/v1/clusters/{cluster}"
	mux.HandleFunc("GET /api/v1/clusters", s.admin(s.listClusters))
	mux.HandleFunc(c, s.admin(s.getCluster))
	mux.HandleFunc(c+"/nodes", snapshotList(s, func(x *protocol.Snapshot) []protocol.Node { return x.Nodes }, nil))
	mux.HandleFunc(c+"/namespaces", snapshotList(s, func(x *protocol.Snapshot) []protocol.Namespace { return x.Namespaces }, nil))
	mux.HandleFunc(c+"/workloads", snapshotList(s, func(x *protocol.Snapshot) []protocol.Workload { return x.Workloads },
		func(x protocol.Workload) string { return x.Namespace }))
	mux.HandleFunc(c+"/pods", snapshotList(s, func(x *protocol.Snapshot) []protocol.Pod { return x.Pods },
		func(x protocol.Pod) string { return x.Namespace }))
	mux.HandleFunc(c+"/services", snapshotList(s, func(x *protocol.Snapshot) []protocol.Service { return x.Services },
		func(x protocol.Service) string { return x.Namespace }))
	mux.HandleFunc(c+"/ingresses", snapshotList(s, func(x *protocol.Snapshot) []protocol.Ingress { return x.Ingresses },
		func(x protocol.Ingress) string { return x.Namespace }))
	mux.HandleFunc(c+"/configmaps", snapshotList(s, func(x *protocol.Snapshot) []protocol.ObjectRef { return x.ConfigMaps }, refNamespace))
	mux.HandleFunc(c+"/secrets", snapshotList(s, func(x *protocol.Snapshot) []protocol.ObjectRef { return x.Secrets }, refNamespace))
	mux.HandleFunc(c+"/volumeclaims", snapshotList(s, func(x *protocol.Snapshot) []protocol.VolumeClaim { return x.VolumeClaims },
		func(x protocol.VolumeClaim) string { return x.Namespace }))
	mux.HandleFunc(c+"/jobs", snapshotList(s, func(x *protocol.Snapshot) []protocol.Job { return x.Jobs },
		func(x protocol.Job) string { return x.Namespace }))
	mux.HandleFunc(c+"/cronjobs", snapshotList(s, func(x *protocol.Snapshot) []protocol.CronJob { return x.CronJobs },
		func(x protocol.CronJob) string { return x.Namespace }))
	mux.HandleFunc(c+"/events", snapshotList(s, func(x *protocol.Snapshot) []protocol.Event { return x.Events },
		func(x protocol.Event) string { return x.Namespace }))

	mux.HandleFunc(c+"/namespaces/{ns}/pods/{pod}/logs", s.admin(s.podLogs))
	mux.HandleFunc("POST /api/v1/clusters/{cluster}/namespaces/{ns}/workloads/{kind}/{name}/restart", s.admin(s.restart))
	mux.HandleFunc("POST /api/v1/clusters/{cluster}/namespaces/{ns}/workloads/{kind}/{name}/scale", s.admin(s.scale))

	// Any resource type, CRDs included, fetched live from the agent.
	mux.HandleFunc(c+"/resources", s.admin(s.discover))
	mux.HandleFunc(c+"/resources/{group}/{version}/{resource}", s.admin(s.listResource))
	mux.HandleFunc(c+"/resources/{group}/{version}/{resource}/{name}", s.admin(s.getResource))

	return withAnyPrefix(mux)
}

// routeMarkers are the fixed roots of every route. Whatever precedes the
// first one is a deployment prefix and is ignored.
var routeMarkers = []string{"/api/v1/", "/agent/v1/"}

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

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken != "" && subtle.ConstantTimeCompare([]byte(bearerToken(r)), []byte(s.cfg.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		next(w, r)
	}
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
	if err := s.st.PutSnapshot(cluster, &snap, s.now()); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
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
	Nodes             int `json:"nodes"`
	NodesNotReady     int `json:"nodesNotReady"`
	Namespaces        int `json:"namespaces"`
	Workloads         int `json:"workloads"`
	WorkloadsDegraded int `json:"workloadsDegraded"`
	Pods              int `json:"pods"`
	PodsUnhealthy     int `json:"podsUnhealthy"`
	Warnings          int `json:"warnings"`
}

type clusterSummary struct {
	Name             string     `json:"name"`
	Status           string     `json:"status"`
	LastSeen         *time.Time `json:"lastSeen,omitempty"`
	CollectedAt      *time.Time `json:"collectedAt,omitempty"`
	KubeVersion      string     `json:"kubeVersion,omitempty"`
	AgentVersion     string     `json:"agentVersion,omitempty"`
	MetricsAvailable bool       `json:"metricsAvailable"`
	// Capacity and Usage are summed over all nodes; Usage needs metrics-server.
	Capacity *protocol.Resources `json:"capacity,omitempty"`
	Usage    *protocol.Resources `json:"usage,omitempty"`
	Counts   counts              `json:"counts"`
	Errors   []string            `json:"errors,omitempty"`
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
	sum := clusterSummary{Name: ci.Name, Status: s.status(ci)}
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
	sum.Counts = counts{
		Nodes:      len(snap.Nodes),
		Namespaces: len(snap.Namespaces),
		Workloads:  len(snap.Workloads),
		Pods:       len(snap.Pods),
		Warnings:   len(snap.Events),
	}
	if len(snap.Nodes) > 0 {
		var capacity, usage protocol.Resources
		for _, n := range snap.Nodes {
			if !n.Ready {
				sum.Counts.NodesNotReady++
			}
			capacity.CPUMilli += n.Allocatable.CPUMilli
			capacity.MemoryBytes += n.Allocatable.MemoryBytes
			capacity.Pods += n.Allocatable.Pods
			if n.Usage != nil {
				usage.CPUMilli += n.Usage.CPUMilli
				usage.MemoryBytes += n.Usage.MemoryBytes
			}
		}
		sum.Capacity = &capacity
		if snap.MetricsAvailable {
			sum.Usage = &usage
		}
	}
	for _, wl := range snap.Workloads {
		if wl.Degraded() {
			sum.Counts.WorkloadsDegraded++
		}
	}
	for _, p := range snap.Pods {
		if !p.Healthy() {
			sum.Counts.PodsUnhealthy++
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

// snapshot fetches the latest snapshot or answers the request with an error.
func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) (*protocol.Snapshot, bool) {
	ci, ok := s.st.Cluster(r.PathValue("cluster"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return nil, false
	}
	if ci.Snapshot == nil {
		writeError(w, http.StatusServiceUnavailable, "no data received from this cluster's agent yet")
		return nil, false
	}
	return ci.Snapshot, true
}

func refNamespace(x protocol.ObjectRef) string { return x.Namespace }

// snapshotList serves one list from the latest snapshot. nsOf enables the
// ?namespace= filter; it is nil for cluster-scoped kinds.
func snapshotList[T any](s *Server, pick func(*protocol.Snapshot) []T, nsOf func(T) string) http.HandlerFunc {
	return s.admin(func(w http.ResponseWriter, r *http.Request) {
		snap, ok := s.snapshot(w, r)
		if !ok {
			return
		}
		items := pick(snap)
		ns := r.URL.Query().Get("namespace")
		out := make([]T, 0, len(items))
		for _, it := range items {
			if ns == "" || nsOf == nil || nsOf(it) == ns {
				out = append(out, it)
			}
		}
		writeJSON(w, http.StatusOK, out)
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
		TailLines: tail,
	})
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, res.Output)
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	res, ok := s.dispatch(w, r, protocol.Command{
		Type:      protocol.CommandRestart,
		Namespace: r.PathValue("ns"),
		Kind:      r.PathValue("kind"),
		Name:      r.PathValue("name"),
	})
	if ok {
		writeJSON(w, http.StatusOK, map[string]string{"message": res.Output})
	}
}

func (s *Server) scale(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Replicas *int32 `json:"replicas"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil || body.Replicas == nil {
		writeError(w, http.StatusBadRequest, `body must be {"replicas": <number>}`)
		return
	}
	res, ok := s.dispatch(w, r, protocol.Command{
		Type:      protocol.CommandScale,
		Namespace: r.PathValue("ns"),
		Kind:      r.PathValue("kind"),
		Name:      r.PathValue("name"),
		Replicas:  body.Replicas,
	})
	if ok {
		writeJSON(w, http.StatusOK, map[string]string{"message": res.Output})
	}
}

func (s *Server) discover(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.dispatch(w, r, protocol.Command{Type: protocol.CommandResources}); ok {
		writeRawJSON(w, res.Output)
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
		writeRawJSON(w, res.Output)
	}
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.dispatch(w, r, resourceCommand(r, protocol.CommandGet)); ok {
		writeRawJSON(w, res.Output)
	}
}

// dispatch sends a command to the cluster's agent and waits for its result.
// On failure it writes the error response itself and returns false.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, cmd protocol.Command) (protocol.Result, bool) {
	name := r.PathValue("cluster")
	ci, ok := s.st.Cluster(name)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return protocol.Result{}, false
	}
	if s.status(ci) != statusOnline {
		writeError(w, http.StatusServiceUnavailable, "the agent of this cluster is not connected")
		return protocol.Result{}, false
	}
	cmd.ID = newID()
	ch, cancel, err := s.st.Enqueue(name, cmd)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return protocol.Result{}, false
	}
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
			writeError(w, http.StatusGatewayTimeout, "the agent did not answer in time")
		}
		return protocol.Result{}, false
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
func writeRawJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
