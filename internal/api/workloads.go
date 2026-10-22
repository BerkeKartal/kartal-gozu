package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/rollout"
)

// routeWorkloads adds what the server learns about workloads over time: the
// requests and limits their usage suggests, and how their new versions
// rolled out. Also Traefik's IngressRoutes, next to the Ingresses.
func (s *Server) routeWorkloads(mux *http.ServeMux) {
	const c = "/api/v1/clusters/{cluster}"
	mux.HandleFunc("GET "+c+"/sizing", s.inCluster(auth.Viewer, anywhere, s.sizingList))
	mux.HandleFunc("GET "+c+"/routes", snapshotList(s, func(x *protocol.Snapshot) []protocol.Route { return x.Routes },
		func(x protocol.Route) string { return x.Namespace }, nil))
	mux.HandleFunc("GET /api/v1/rollouts", s.require(auth.Viewer, s.rolloutList))
}

// sizingList suggests requests and limits for the workloads the user sees,
// or those of ?namespace=.
func (s *Server) sizingList(w http.ResponseWriter, r *http.Request) {
	cluster, ns := r.PathValue("cluster"), r.URL.Query().Get("namespace")
	s.fromSnapshot(w, r, func(snap *protocol.Snapshot) any {
		return map[string]any{
			"workloads": s.sizing.Advise(cluster, snap, func(n string) bool { return ns == "" || n == ns }, s.now()),
			"metrics":   snap.MetricsAvailable,
			"kept":      s.sizing.Path() != "",
		}
	})
}

// rolloutList lists the rollouts of the namespaces the user sees, newest
// first; ?cluster=, ?namespace=, ?kind=, ?name= and ?state= narrow it down.
// For operators, a rollout started through Kartal Gözü (a restart, a
// rollback, saved YAML) says who started it.
func (s *Server) rolloutList(w http.ResponseWriter, r *http.Request) {
	u, q := userOf(r), r.URL.Query()
	cluster, ns, kind, name, state := q.Get("cluster"), q.Get("namespace"), q.Get("kind"), q.Get("name"), q.Get("state")
	limit := 500
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = min(v, 2000)
	}
	out := s.rollouts.Recent(func(x rollout.Rollout) bool {
		return (cluster == "" || x.Cluster == cluster) && (ns == "" || x.Namespace == ns) &&
			(kind == "" || strings.EqualFold(x.Kind, kind)) && (name == "" || x.Name == name) &&
			(state == "" || x.State == state) && u.RoleIn(x.Cluster, x.Namespace) >= auth.Viewer
	}, limit)
	type withBy struct {
		rollout.Rollout
		By string `json:"by,omitempty"`
	}
	entries := s.audit.newestFirst()
	list := make([]withBy, len(out))
	for i, x := range out {
		list[i].Rollout = x
		if u.RoleIn(x.Cluster, x.Namespace) < auth.Operator {
			continue
		}
		for _, e := range entries {
			// What people did shows in the next snapshot, within a minute or so.
			if e.OK && e.Cluster == x.Cluster && e.Namespace == x.Namespace && auditNames(e.Object, x.Kind, x.Name) &&
				startsRollout[e.Action] && !e.Time.After(x.Started.Add(30*time.Second)) && x.Started.Sub(e.Time) < 2*time.Minute {
				list[i].By = e.User
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, list)
}

// auditNames tells whether an audit entry's object is a workload: restarts
// and rollbacks name it Kind/name, saved YAML apps/kinds/name.
func auditNames(object, kind, name string) bool {
	return strings.EqualFold(object, kind+"/"+name) || object == "apps/"+strings.ToLower(kind)+"s/"+name
}

// startsRollout are the actions that give a workload new pods.
var startsRollout = map[string]bool{protocol.CommandRestart: true, protocol.CommandRollback: true, protocol.CommandApply: true}
