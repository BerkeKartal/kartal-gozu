package api

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/versions"
)

// agentVersionGrace is how long an agent may run another version than the
// server before it is an alert: the server and the agents are rarely
// updated in the same minute.
const agentVersionGrace = 30 * time.Minute

func (s *Server) routeVersions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/versions", s.require(auth.Viewer, s.versionsPage))
}

// kubeUse is one Kubernetes version of a cluster, with where it runs: the
// API server, nodes, or both.
type kubeUse struct {
	// Version is as the cluster reports it ("v1.33.11+k3s1"); Upstream the
	// Kubernetes release it stands for, which is what is looked up.
	Version   string   `json:"version"`
	Upstream  string   `json:"upstream"`
	APIServer bool     `json:"apiServer"`
	Nodes     []string `json:"nodes,omitempty"`
}

type clusterVersions struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	AgentVersion string `json:"agentVersion,omitempty"`
	// AgentDiffers says the agent was built from another version than the
	// server.
	AgentDiffers bool      `json:"agentDiffers"`
	Kubernetes   []kubeUse `json:"kubernetes"`
}

// kubeUses are the Kubernetes versions in a snapshot. Nodes are only in a
// snapshot that shows the whole cluster.
func kubeUses(snap *protocol.Snapshot) []kubeUse {
	out := []kubeUse{}
	at := map[string]int{}
	add := func(reported string) *kubeUse {
		up := versions.KubeVersion(reported)
		if up == "" {
			return nil
		}
		if i, ok := at[up]; ok {
			return &out[i]
		}
		at[up] = len(out)
		out = append(out, kubeUse{Version: reported, Upstream: up})
		return &out[len(out)-1]
	}
	if u := add(snap.KubeVersion); u != nil {
		u.APIServer = true
	}
	for _, n := range snap.Nodes {
		if u := add(n.KubeletVersion); u != nil {
			u.Nodes = append(u.Nodes, n.Name)
		}
	}
	return out
}

// agentDiffers tells whether an agent's version is another than the
// server's, when both are known.
func (s *Server) agentDiffers(agent string) bool {
	return versions.Known(s.cfg.Version) && versions.Known(agent) && !versions.Same(agent, s.cfg.Version)
}

// versionsPage tells the versions that run: the server's, with the
// repository it is built from, and each cluster's agent and Kubernetes
// versions. Whether newer ones exist the browser asks itself (see
// ui.LookupOrigins), as the server may not reach the internet.
func (s *Server) versionsPage(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	type server struct {
		Version string `json:"version"`
		Repo    string `json:"repo"`
		// Lookups says the browser may ask GitHub and OSV.dev.
		Lookups bool `json:"lookups"`
	}
	out := struct {
		Server   server            `json:"server"`
		Clusters []clusterVersions `json:"clusters"`
	}{Server: server{Version: s.cfg.Version, Repo: s.cfg.UpdateRepo, Lookups: s.cfg.VersionLookups}, Clusters: []clusterVersions{}}
	for _, ci := range s.st.Clusters() {
		if u.RoleSomewhere(ci.Name) < auth.Viewer {
			continue
		}
		cv := clusterVersions{Name: ci.Name, Status: s.status(ci), Kubernetes: []kubeUse{}}
		if snap := visible(u, ci.Name, ci.Snapshot); snap != nil {
			cv.AgentVersion, cv.AgentDiffers, cv.Kubernetes = snap.AgentVersion, s.agentDiffers(snap.AgentVersion), kubeUses(snap)
		}
		out.Clusters = append(out.Clusters, cv)
	}
	sort.Slice(out.Clusters, func(i, j int) bool { return out.Clusters[i].Name < out.Clusters[j].Name })
	writeJSON(w, http.StatusOK, out)
}

// watchVersions raises a cluster's alert about an agent that has run
// another version than the server for a while, and resolves it.
func (s *Server) watchVersions(ci store.ClusterInfo, now time.Time) {
	snap := ci.Snapshot
	if snap == nil || s.cfg.Alerts == nil {
		return
	}
	detail := ""
	if s.agentDiffers(snap.AgentVersion) {
		since, ok := s.agentSince[ci.Name]
		if !ok {
			since = now
			s.agentSince[ci.Name] = now
		}
		if now.Sub(since) < agentVersionGrace {
			// Too soon to tell, which is also the case right after a
			// restart: an alert kept from before stays as it is, neither
			// resolved nor told again.
			return
		}
		detail = fmt.Sprintf("the agent is %s, the server %s", snap.AgentVersion, s.cfg.Version)
	} else {
		delete(s.agentSince, ci.Name)
	}
	s.cfg.Alerts.ObserveAgentVersion(ci.Name, detail, now)
}
