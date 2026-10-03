package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/appmetrics"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

// routeWatches adds the metrics that pods expose: a pod's page of them,
// read live, and the watched ones the server reads on its own. Viewers see
// them; operators choose what is watched in their namespaces.
func (s *Server) routeWatches(mux *http.ServeMux) {
	const c = "/api/v1/clusters/{cluster}"
	mux.HandleFunc("GET "+c+"/namespaces/{ns}/pods/{pod}/scrape", s.inCluster(auth.Viewer, pathNamespace, s.scrapePod))
	mux.HandleFunc("GET "+c+"/watches", s.inCluster(auth.Viewer, anywhere, s.watchList))
	mux.HandleFunc("POST "+c+"/namespaces/{ns}/watches", s.inCluster(auth.Operator, pathNamespace, s.addWatch))
	mux.HandleFunc("PUT "+c+"/namespaces/{ns}/watches/{id}", s.inCluster(auth.Operator, pathNamespace, s.changeWatch))
	mux.HandleFunc("DELETE "+c+"/namespaces/{ns}/watches/{id}", s.inCluster(auth.Operator, pathNamespace, s.removeWatch))
}

const watchFields = `{"name", "target", "port", "path", "metric", "labels", "rate", "aggregate", "above", "below"}`

func (s *Server) scrapePod(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, ok := s.dispatch(w, r, protocol.Command{
		Type: protocol.CommandScrape, Namespace: r.PathValue("ns"), Name: r.PathValue("pod"),
		Port: q.Get("port"), Path: q.Get("path"),
	})
	if ok {
		writeRawJSON(w, r, res.Output)
	}
}

func (s *Server) watches(w http.ResponseWriter) *appmetrics.Monitor {
	if s.cfg.Watches == nil {
		writeError(w, http.StatusNotFound, "watching metrics is not available on this server")
	}
	return s.cfg.Watches
}

// watchList lists the cluster's watches in the namespaces the user sees,
// or in the one asked for, with the last 1 to 24 hours of their values.
func (s *Server) watchList(w http.ResponseWriter, r *http.Request) {
	m := s.watches(w)
	if m == nil {
		return
	}
	hours := 1
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 24 {
			writeError(w, http.StatusBadRequest, "hours must be 1 to 24")
			return
		}
		hours = n
	}
	u, cluster, ns := userOf(r), r.PathValue("cluster"), r.URL.Query().Get("namespace")
	list := m.List(func(x settings.Watch) bool {
		return x.Cluster == cluster && (ns == "" || x.Namespace == ns) && u.RoleIn(cluster, x.Namespace) >= auth.Viewer
	}, hours)
	writeJSON(w, http.StatusOK, map[string]any{"watches": list, "where": m.Where(), "loadError": m.LoadError()})
}

// here keeps a request to the watches of the cluster and namespace in its
// path.
func here(r *http.Request) func(settings.Watch) bool {
	cluster, ns := r.PathValue("cluster"), r.PathValue("ns")
	return func(x settings.Watch) bool { return x.Cluster == cluster && x.Namespace == ns }
}

// watchError answers for a change that failed; it reports whether one did.
func watchError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, appmetrics.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the watches could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) readWatch(w http.ResponseWriter, r *http.Request) (settings.Watch, bool) {
	var x settings.Watch
	if !readJSON(w, r, &x, watchFields) {
		return x, false
	}
	// A watch belongs where the request points, whatever the body says.
	x.Cluster, x.Namespace = r.PathValue("cluster"), r.PathValue("ns")
	if _, ok := s.st.Cluster(x.Cluster); !ok {
		writeError(w, http.StatusNotFound, store.ErrUnknownCluster.Error())
		return x, false
	}
	return x, true
}

func (s *Server) addWatch(w http.ResponseWriter, r *http.Request) {
	m := s.watches(w)
	if m == nil {
		return
	}
	x, ok := s.readWatch(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Add(ctx, x)
	s.noteWatch(r, "add-watch", x, err)
	if !watchError(w, err) {
		writeJSON(w, http.StatusCreated, saved)
	}
}

func (s *Server) changeWatch(w http.ResponseWriter, r *http.Request) {
	m := s.watches(w)
	if m == nil {
		return
	}
	x, ok := s.readWatch(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Change(ctx, r.PathValue("id"), x, here(r))
	s.noteWatch(r, "change-watch", x, err)
	if !watchError(w, err) {
		writeJSON(w, http.StatusOK, saved)
	}
}

func (s *Server) removeWatch(w http.ResponseWriter, r *http.Request) {
	m := s.watches(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	x, err := m.Remove(ctx, r.PathValue("id"), here(r))
	if x.Name == "" {
		x.Name, x.Cluster, x.Namespace = r.PathValue("id"), r.PathValue("cluster"), r.PathValue("ns")
	}
	s.noteWatch(r, "remove-watch", x, err)
	if !watchError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + x.Name})
	}
}

// noteWatch adds a change to the watches to the audit log, unless it was
// refused before anything was tried.
func (s *Server) noteWatch(r *http.Request, action string, x settings.Watch, err error) {
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) || errors.Is(err, appmetrics.ErrNotFound) {
		return
	}
	u := userOf(r)
	e := AuditEntry{Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: action, Cluster: x.Cluster,
		Namespace: x.Namespace, Object: "watch/" + x.Name, Detail: x.Target + " " + x.Metric, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	s.audit.add(e)
	s.log.Info("audit", "user", e.User, "action", e.Action, "cluster", e.Cluster, "namespace", e.Namespace, "object", e.Object, "ok", e.OK, "error", e.Error)
}

// snapshotPods are a connected cluster's pods, as its agent last reported.
func (s *Server) snapshotPods(cluster string) ([]protocol.Pod, bool) {
	ci, ok := s.st.Cluster(cluster)
	if !ok || ci.Snapshot == nil || s.status(ci) != statusOnline {
		return nil, false
	}
	return ci.Snapshot.Pods, true
}

// ask sends a command to a cluster's agent and waits for its result, for
// the server's own work.
func (s *Server) ask(ctx context.Context, cluster string, cmd protocol.Command) (protocol.Result, error) {
	ci, ok := s.st.Cluster(cluster)
	if !ok {
		return protocol.Result{}, store.ErrUnknownCluster
	}
	if s.status(ci) != statusOnline {
		return protocol.Result{}, errors.New("the agent of this cluster is not connected")
	}
	cmd.ID = newID()
	ch, cancel, err := s.st.Enqueue(cluster, cmd)
	if err != nil {
		return protocol.Result{}, err
	}
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, s.cfg.CommandTimeout)
	defer stop()
	select {
	case res := <-ch:
		if !res.OK {
			return res, errors.New(res.Error)
		}
		return res, nil
	case <-ctx.Done():
		return protocol.Result{}, errors.New("the agent did not answer in time")
	}
}
