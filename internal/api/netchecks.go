package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/netcheck"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// routeNetwork adds network checks, which try TCP connections from inside a
// cluster to addresses that admins give, and the NetworkPolicies that
// decide who reaches a pod's port.
func (s *Server) routeNetwork(mux *http.ServeMux) {
	const c = "/api/v1/clusters/{cluster}"
	// Checks reach any address the cluster reaches, so they are for the
	// admins of the whole cluster, and each is written to the audit log.
	mux.HandleFunc("POST "+c+"/net-checks", s.inCluster(auth.Admin, wholeCluster, s.netCheck))
	mux.HandleFunc("GET "+c+"/net-checks/{id}", s.inCluster(auth.Admin, wholeCluster, s.netCheckStatus))
	mux.HandleFunc("GET "+c+"/namespaces/{ns}/pods/{pod}/network-policies", s.inCluster(auth.Viewer, pathNamespace, s.podPolicies))
}

func (s *Server) netCheck(w http.ResponseWriter, r *http.Request) {
	var req protocol.NetCheckRequest
	if !readJSON(w, r, &req, `{"targets": ["db.example.org:5432"], "agent": true, "nodes": ["worker1"]}`) {
		return
	}
	targets, err := netcheck.ParseTargets(req.Targets)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Nodes) > protocol.MaxNetCheckNodes {
		writeError(w, http.StatusBadRequest, "at most "+strconv.Itoa(protocol.MaxNetCheckNodes)+" nodes at once")
		return
	}
	req.Targets = targets
	body, err := json.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cmd := protocol.Command{Type: protocol.CommandNetCheck, Body: string(body)}
	from := req.Nodes
	if req.Agent {
		from = append([]string{"agent"}, from...)
	}
	detail := strings.Join(targets, ", ") + " from " + strings.Join(from, ", ")
	res, ok := s.dispatch(w, r, cmd)
	s.record(r, cmd, "", detail, res, ok)
	if ok {
		writeRawJSON(w, r, res.Output)
	}
}

func (s *Server) netCheckStatus(w http.ResponseWriter, r *http.Request) {
	res, ok := s.dispatch(w, r, protocol.Command{Type: protocol.CommandNetCheckStatus, Name: r.PathValue("id")})
	if ok {
		writeRawJSON(w, r, res.Output)
	}
}

// podPolicies tells whether the namespace's NetworkPolicies let the
// API server, the nodes and other networks reach a port of a pod.
func (s *Server) podPolicies(w http.ResponseWriter, r *http.Request) {
	res, ok := s.dispatch(w, r, protocol.Command{
		Type: protocol.CommandNetworkPolicies, Namespace: r.PathValue("ns"), Name: r.PathValue("pod"), Port: r.URL.Query().Get("port"),
	})
	if ok {
		writeRawJSON(w, r, res.Output)
	}
}
