package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/collect"
	"github.com/BerkeKartal/kartal-gozu/internal/query"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// routeStore adds the metric store: what it holds, the workloads whose
// metrics it collects, and deleting a range of it. Viewers see their part;
// operators choose what is collected in their namespaces; how often, how
// long and deleting are for admins.
func (s *Server) routeStore(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/store", s.require(auth.Viewer, s.storeStats))
	mux.HandleFunc("PUT /api/v1/store/config", s.requireEverywhere(auth.Admin, s.storeConfig))
	mux.HandleFunc("POST /api/v1/store/delete", s.requireEverywhere(auth.Admin, s.storeDelete))
	mux.HandleFunc("GET /api/v1/store/metrics", s.require(auth.Viewer, s.storeMetrics))
	mux.HandleFunc("GET /api/v1/store/targets", s.require(auth.Viewer, s.collectList))
	mux.HandleFunc("GET /api/v1/store/query_range", s.require(auth.Viewer, s.queryRange))
	mux.HandleFunc("GET /api/v1/store/query", s.require(auth.Viewer, s.queryInstant))
	mux.HandleFunc("GET /api/v1/store/labels", s.require(auth.Viewer, s.labelNames))
	mux.HandleFunc("GET /api/v1/store/labels/{name}/values", s.require(auth.Viewer, s.labelValues))
	const ns = "/api/v1/clusters/{cluster}/namespaces/{ns}/collect"
	mux.HandleFunc("POST "+ns, s.inCluster(auth.Operator, pathNamespace, s.addCollect))
	mux.HandleFunc("PUT "+ns+"/{id}", s.inCluster(auth.Operator, pathNamespace, s.changeCollect))
	mux.HandleFunc("DELETE "+ns+"/{id}", s.inCluster(auth.Operator, pathNamespace, s.removeCollect))
}

const collectFields = `{"target", "port", "path", "include", "exclude"}`

func (s *Server) collector(w http.ResponseWriter) *collect.Collector {
	if s.cfg.Collect == nil {
		writeError(w, http.StatusNotFound, "the metric store is off on this server; give it a directory (KARTAL_DATA_DIR)")
	}
	return s.cfg.Collect
}

// sees keeps the stored series of the namespaces a user may see; nil when
// the user sees them all.
func sees(u auth.User) func(tsdb.Labels) bool {
	if u.Everywhere() >= auth.Viewer {
		return nil
	}
	return func(ls tsdb.Labels) bool {
		return u.RoleIn(ls.Get(collect.LabelCluster), ls.Get(collect.LabelNamespace)) >= auth.Viewer
	}
}

// storeStats describes the store; of the targets, it counts those the user
// sees.
func (s *Server) storeStats(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	u := userOf(r)
	st := c.Stats()
	st.Targets = len(c.List(func(x settings.CollectTarget) bool { return u.RoleIn(x.Cluster, x.Namespace) >= auth.Viewer }))
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) storeConfig(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	var body struct {
		Interval      int `json:"interval"`
		RetentionDays int `json:"retentionDays"`
	}
	if !readJSON(w, r, &body, `{"interval": seconds, "retentionDays": days or 0 to keep everything}`) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cfg, err := c.Configure(ctx, body.Interval, body.RetentionDays)
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.note(r, "store-config", "store", fmt.Sprintf("every %ds, kept %d days", body.Interval, body.RetentionDays), err)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the settings could not be saved: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// storeDelete removes the samples within a range of time, in Unix
// milliseconds, both ends included.
func (s *Server) storeDelete(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	var body struct {
		From *int64 `json:"from"`
		To   *int64 `json:"to"`
	}
	const hint = `{"from": ms, "to": ms}`
	if !readJSON(w, r, &body, hint) {
		return
	}
	if body.From == nil || body.To == nil || *body.From < 0 || *body.From > *body.To {
		writeError(w, http.StatusBadRequest, "body must be "+hint+", from before to")
		return
	}
	res, err := c.Delete(*body.From, *body.To)
	detail := time.UnixMilli(*body.From).UTC().Format(time.RFC3339) + " to " + time.UnixMilli(*body.To).UTC().Format(time.RFC3339)
	if err == nil {
		detail += fmt.Sprintf(", %d bytes freed", res.Freed)
	}
	s.note(r, "store-delete", "store", detail, err)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the range could not be deleted: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// timeRange reads ?from= and ?to= (Unix milliseconds); without them, the
// last hour.
func timeRange(r *http.Request, now time.Time) (int64, int64, error) {
	from, to := now.Add(-time.Hour).UnixMilli(), now.UnixMilli()
	for name, v := range map[string]*int64{"from": &from, "to": &to} {
		if q := r.URL.Query().Get(name); q != "" {
			n, err := strconv.ParseInt(q, 10, 64)
			if err != nil || n < 0 {
				return 0, 0, fmt.Errorf("%s must be Unix milliseconds", name)
			}
			*v = n
		}
	}
	if from > to {
		return 0, 0, errors.New("from must come before to")
	}
	return from, to, nil
}

// storeMetrics lists the stored metrics the user may see, in a range of
// time, optionally of one cluster and namespace.
func (s *Server) storeMetrics(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	from, to, err := timeRange(r, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sel, err := storeSelector(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, l := range []string{collect.LabelCluster, collect.LabelNamespace} {
		if v := r.URL.Query().Get(l); v != "" {
			m, _ := tsdb.NewMatcher(tsdb.MatchEqual, l, v)
			sel.Matchers = append(sel.Matchers, m)
		}
	}
	list, err := c.DB().Metrics(from, to, sel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// collectList lists the collected targets the user may see, optionally of
// one cluster and namespace.
func (s *Server) collectList(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	u, q := userOf(r), r.URL.Query()
	cluster, ns := q.Get("cluster"), q.Get("namespace")
	list := c.List(func(x settings.CollectTarget) bool {
		return (cluster == "" || x.Cluster == cluster) && (ns == "" || x.Namespace == ns) && u.RoleIn(x.Cluster, x.Namespace) >= auth.Viewer
	})
	writeJSON(w, http.StatusOK, list)
}

// collectHere keeps a request to the targets of the cluster and namespace
// in its path.
func collectHere(r *http.Request) func(settings.CollectTarget) bool {
	cluster, ns := r.PathValue("cluster"), r.PathValue("ns")
	return func(x settings.CollectTarget) bool { return x.Cluster == cluster && x.Namespace == ns }
}

// collectError answers for a change that failed; it reports whether one
// did.
func collectError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, collect.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the targets could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) readCollect(w http.ResponseWriter, r *http.Request) (settings.CollectTarget, bool) {
	var x settings.CollectTarget
	if !readJSON(w, r, &x, collectFields) {
		return x, false
	}
	// A target belongs where the request points, whatever the body says.
	x.Cluster, x.Namespace = r.PathValue("cluster"), r.PathValue("ns")
	if _, ok := s.st.Cluster(x.Cluster); !ok {
		writeError(w, http.StatusNotFound, store.ErrUnknownCluster.Error())
		return x, false
	}
	return x, true
}

func (s *Server) addCollect(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	x, ok := s.readCollect(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := c.Add(ctx, x)
	s.noteCollect(r, "add-collect", x, err)
	if !collectError(w, err) {
		writeJSON(w, http.StatusCreated, saved)
	}
}

func (s *Server) changeCollect(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	x, ok := s.readCollect(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := c.Change(ctx, r.PathValue("id"), x, collectHere(r))
	s.noteCollect(r, "change-collect", x, err)
	if !collectError(w, err) {
		writeJSON(w, http.StatusOK, saved)
	}
}

func (s *Server) removeCollect(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	x, err := c.Remove(ctx, r.PathValue("id"), collectHere(r))
	if x.Target == "" {
		x.Target, x.Cluster, x.Namespace = r.PathValue("id"), r.PathValue("cluster"), r.PathValue("ns")
	}
	s.noteCollect(r, "remove-collect", x, err)
	if !collectError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "no longer collecting " + x.Target})
	}
}

// noteCollect adds a change to the collected targets to the audit log,
// unless it was refused before anything was tried.
func (s *Server) noteCollect(r *http.Request, action string, x settings.CollectTarget, err error) {
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) || errors.Is(err, collect.ErrNotFound) {
		return
	}
	u := userOf(r)
	e := AuditEntry{Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: action, Cluster: x.Cluster,
		Namespace: x.Namespace, Object: x.Target, Detail: ":" + x.Port + x.Path, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	s.audit.add(e)
	s.log.Info("audit", "user", e.User, "action", e.Action, "cluster", e.Cluster, "namespace", e.Namespace, "object", e.Object, "ok", e.OK, "error", e.Error)
}

// queryTimeout bounds a query's work.
const queryTimeout = 30 * time.Second

// maxQuery bounds a query's text.
const maxQuery = 16 << 10

// msParam reads a time or a step in Unix milliseconds, or def without one.
func msParam(r *http.Request, name string, def int64) (int64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be Unix milliseconds", name)
	}
	return n, nil
}

// queryRange evaluates a query at every step of a range of time: ?query=,
// ?start= and ?end= in Unix milliseconds (the last hour by default), and
// ?step= in milliseconds (about 300 steps by default).
func (s *Server) queryRange(w http.ResponseWriter, r *http.Request) {
	now := s.now().UnixMilli()
	end, err := msParam(r, "end", now)
	var start, step int64
	if err == nil {
		start, err = msParam(r, "start", end-time.Hour.Milliseconds())
	}
	if err == nil {
		step, err = msParam(r, "step", max(1000, (end-start)/300/1000*1000))
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.runQuery(w, r, start, end, step)
}

// queryInstant evaluates a query at one moment, ?time= (now by default).
func (s *Server) queryInstant(w http.ResponseWriter, r *http.Request) {
	at, err := msParam(r, "time", s.now().UnixMilli())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.runQuery(w, r, at, at, 1)
}

func (s *Server) runQuery(w http.ResponseWriter, r *http.Request, start, end, step int64) {
	c := s.collector(w)
	if c == nil {
		return
	}
	q := r.URL.Query().Get("query")
	if q == "" {
		writeError(w, http.StatusBadRequest, "give a query, such as ?query=up")
		return
	}
	if len(q) > maxQuery {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("the query is longer than %d KiB", maxQuery>>10))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	res, err := query.NewEngine(c.DB()).Range(ctx, q, start, end, step, sees(userOf(r)))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("the query took longer than %s; narrow it down", queryTimeout))
	case errors.Is(err, context.Canceled):
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// storeSelector is what ?match= (a selector such as {namespace="shop"})
// and the user's view pick.
func storeSelector(r *http.Request) (tsdb.Selector, error) {
	sel := tsdb.Selector{Keep: sees(userOf(r))}
	if m := r.URL.Query().Get("match"); m != "" {
		vs, err := query.ParseSelector(m)
		if err != nil {
			return sel, err
		}
		sel.Matchers = vs.Matchers
	}
	return sel, nil
}

// labelNames lists the label names of the stored series, for completion.
func (s *Server) labelNames(w http.ResponseWriter, r *http.Request) {
	s.labelList(w, r, func(db *tsdb.DB, from, to int64, sel tsdb.Selector) ([]string, error) {
		return db.LabelNames(from, to, sel)
	})
}

// labelValues lists a label's values among the stored series.
func (s *Server) labelValues(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.labelList(w, r, func(db *tsdb.DB, from, to int64, sel tsdb.Selector) ([]string, error) {
		return db.LabelValues(name, from, to, sel)
	})
}

func (s *Server) labelList(w http.ResponseWriter, r *http.Request, list func(*tsdb.DB, int64, int64, tsdb.Selector) ([]string, error)) {
	c := s.collector(w)
	if c == nil {
		return
	}
	from, to, err := timeRange(r, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sel, err := storeSelector(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := list(c.DB(), from, to, sel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
