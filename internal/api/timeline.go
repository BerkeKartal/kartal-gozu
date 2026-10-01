package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/changes"
)

// routeTimeline adds the views across clusters: what changed, and which
// versions run where.
func (s *Server) routeTimeline(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/changes", s.require(auth.Viewer, s.changeList))
	mux.HandleFunc("GET /api/v1/releases", s.require(auth.Viewer, s.releases))
}

// changeVisible: a change in a namespace needs a role there; one of the
// cluster itself (a node) a role over all of it.
func changeVisible(u auth.User, c changes.Change) bool {
	return u.RoleIn(c.Cluster, c.Namespace) >= auth.Viewer
}

// changeList merges what the agents' snapshots showed changing with what
// people changed through Kartal Gözü, newest first. The latter, like the
// audit log, is for operators. ?cluster=, ?namespace=, ?kind= and ?name=
// narrow it down.
func (s *Server) changeList(w http.ResponseWriter, r *http.Request) {
	u, q := userOf(r), r.URL.Query()
	cluster, ns, kind, name := q.Get("cluster"), q.Get("namespace"), q.Get("kind"), q.Get("name")
	limit := 500
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = min(v, 2000)
	}
	wanted := func(c changes.Change) bool {
		return (cluster == "" || c.Cluster == cluster) && (ns == "" || c.Namespace == ns) &&
			(kind == "" || strings.EqualFold(c.Kind, kind)) && (name == "" || c.Name == name) && changeVisible(u, c)
	}
	out := s.changes.Recent(wanted, limit)
	var done []changes.Change
	for _, e := range s.audit.newestFirst() {
		if !e.OK || e.Cluster == "" || u.RoleIn(e.Cluster, e.Namespace) < auth.Operator {
			continue
		}
		if c := auditChange(e); wanted(c) {
			done = append(done, c)
		}
	}
	// A change made through Kartal Gözü shows in the next snapshot too; the
	// two become one, which says who made it.
	used := make([]bool, len(done))
	for i := range out {
		for j, d := range done {
			if !used[j] && sameChange(out[i], d) {
				out[i].By, used[j] = d.By, true
				break
			}
		}
	}
	for j, d := range done {
		if !used[j] {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, out)
}

// kindNames turns the kinds and resources in audit entries, as the URLs had
// them, into kinds.
var kindNames = map[string]string{
	"deployment": "Deployment", "deployments": "Deployment", "statefulset": "StatefulSet", "statefulsets": "StatefulSet",
	"daemonset": "DaemonSet", "daemonsets": "DaemonSet", "pod": "Pod", "pods": "Pod", "node": "Node", "nodes": "Node",
	"cronjob": "CronJob", "cronjobs": "CronJob", "job": "Job", "jobs": "Job", "services": "Service",
	"ingresses": "Ingress", "configmaps": "ConfigMap", "secrets": "Secret", "persistentvolumeclaims": "PersistentVolumeClaim",
	"namespaces": "Namespace",
}

// auditChange describes what a person did through Kartal Gözü as a change.
// Actions record Kind/name; a saved YAML group/resource/name.
func auditChange(e AuditEntry) changes.Change {
	c := changes.Change{Time: e.Time, Cluster: e.Cluster, Namespace: e.Namespace, What: e.Action, By: e.User}
	parts := strings.SplitN(e.Object, "/", 3)
	switch len(parts) {
	case 3:
		c.Kind, c.Name = parts[1], parts[2]
	case 2:
		c.Kind, c.Name = parts[0], parts[1]
	default:
		c.Name = e.Object
	}
	if k, ok := kindNames[strings.ToLower(c.Kind)]; ok {
		c.Kind = k
	}
	key, value, _ := strings.Cut(e.Detail, "=")
	switch {
	case e.Action == "cordon" && value == "false":
		c.What = "uncordon"
	case e.Action == "suspend" && value == "false":
		c.What = "resume"
	case e.Action == "scale" && key == "replicas", e.Action == "rollback" && key == "revision":
		c.To = value
	case e.Action == "exec":
		c.To = e.Detail
	}
	return c
}

// sameChange tells whether what an agent saw is what a person did through
// Kartal Gözü shortly before.
func sameChange(seen, done changes.Change) bool {
	if seen.By != "" || seen.Cluster != done.Cluster || seen.Namespace != done.Namespace || seen.Kind != done.Kind || seen.Name != done.Name {
		return false
	}
	if seen.Time.Before(done.Time) || seen.Time.Sub(done.Time) > 2*time.Minute {
		return false
	}
	switch done.What {
	case "restart":
		return seen.What == "template"
	case "scale":
		return seen.What == "replicas"
	case "rollback":
		return seen.What == "image" || seen.What == "template"
	case "cordon", "uncordon":
		return seen.What == done.What+"ed"
	case "suspend":
		return seen.What == "suspended"
	case "resume":
		return seen.What == "resumed"
	case "apply":
		return seen.What != "created" && seen.What != "deleted"
	}
	return false
}

type release struct {
	Cluster   string   `json:"cluster"`
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Images    []string `json:"images"`
	Ready     int32    `json:"ready"`
	Desired   int32    `json:"desired"`
}

// releases lists every workload the user may see in every cluster, with its
// images, so the UI can put the versions of an app side by side.
func (s *Server) releases(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	out := []release{}
	for _, ci := range s.st.Clusters() {
		snap := visible(u, ci.Name, ci.Snapshot)
		if snap == nil || u.RoleSomewhere(ci.Name) < auth.Viewer {
			continue
		}
		for _, wl := range snap.Workloads {
			out = append(out, release{Cluster: ci.Name, Namespace: wl.Namespace, Kind: wl.Kind, Name: wl.Name, Images: wl.Images, Ready: wl.Ready, Desired: wl.Desired})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
