package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/silence"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

// routeSilences adds the silences of alerts: people see those over what
// they see; operators set and end them over what they operate.
func (s *Server) routeSilences(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/silences", s.require(auth.Viewer, s.silenceList))
	mux.HandleFunc("POST /api/v1/silences", s.require(auth.Operator, s.addSilence))
	mux.HandleFunc("DELETE /api/v1/silences/{id}", s.require(auth.Operator, s.removeSilence))
}

const silenceFields = `{"cluster", "namespace", "object", "kind", "comment", "starts", "ends"}`

func (s *Server) silences(w http.ResponseWriter) *silence.Manager {
	if s.cfg.Silences == nil {
		writeError(w, http.StatusNotFound, "silences are not available on this server")
	}
	return s.cfg.Silences
}

// maySilence tells whether a user may set or end a silence: an operator of
// all it covers. One of every cluster takes an operator everywhere; one of
// a whole cluster, or of namespaces by a pattern, one of the cluster.
func maySilence(u auth.User, x settings.Silence) bool {
	switch {
	case x.Cluster == "":
		return u.Everywhere() >= auth.Operator
	case x.Namespace == "" || strings.HasSuffix(x.Namespace, "*"):
		return u.RoleIn(x.Cluster, "") >= auth.Operator
	}
	return u.RoleIn(x.Cluster, x.Namespace) >= auth.Operator
}

// silenceVisible tells whether a user sees a silence: as the alerts it may
// cover are seen.
func silenceVisible(u auth.User, x settings.Silence) bool {
	switch {
	case x.Cluster == "":
		return true
	case x.Namespace != "" && !strings.HasSuffix(x.Namespace, "*"):
		return u.RoleIn(x.Cluster, x.Namespace) >= auth.Viewer
	}
	return u.RoleSomewhere(x.Cluster) >= auth.Viewer
}

// visibleSilences are the silences not over yet that the user sees.
func (s *Server) visibleSilences(u auth.User) []settings.Silence {
	return s.cfg.Silences.List(func(x settings.Silence) bool { return silenceVisible(u, x) })
}

func (s *Server) silenceList(w http.ResponseWriter, r *http.Request) {
	if m := s.silences(w); m != nil {
		writeJSON(w, http.StatusOK, map[string]any{"silences": s.visibleSilences(userOf(r)), "where": m.Where(), "loadError": m.LoadError()})
	}
}

// silenceError answers for a change that failed; it reports whether one
// did.
func silenceError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, silence.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, silence.ErrNotAllowed):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the silences could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) addSilence(w http.ResponseWriter, r *http.Request) {
	m := s.silences(w)
	var x settings.Silence
	if m == nil || !readJSON(w, r, &x, silenceFields) {
		return
	}
	u := userOf(r)
	if !maySilence(u, x) {
		writeError(w, http.StatusForbidden, "your role may not silence this: it needs an operator of all it covers")
		return
	}
	if x.Cluster != "" {
		if _, ok := s.st.Cluster(x.Cluster); !ok {
			writeError(w, http.StatusNotFound, store.ErrUnknownCluster.Error())
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Add(ctx, x, u.Name)
	s.noteSilence(r, "add-silence", saved, err)
	if !silenceError(w, err) {
		writeJSON(w, http.StatusCreated, saved)
	}
}

func (s *Server) removeSilence(w http.ResponseWriter, r *http.Request) {
	m := s.silences(w)
	if m == nil {
		return
	}
	u := userOf(r)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	gone, err := m.Remove(ctx, r.PathValue("id"), func(x settings.Silence) bool { return maySilence(u, x) })
	s.noteSilence(r, "remove-silence", gone, err)
	if !silenceError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "ended the silence of " + silenceScope(gone)})
	}
}

// silenceScope names what a silence covers, for the audit log.
func silenceScope(x settings.Silence) string {
	parts := []string{}
	for _, p := range []string{x.Cluster, x.Namespace, x.Kind, x.Object} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "all alerts"
	}
	return strings.Join(parts, "/")
}

// noteSilence adds a change to the silences to the audit log, unless it was
// refused before anything was tried.
func (s *Server) noteSilence(r *http.Request, action string, x settings.Silence, err error) {
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) || errors.Is(err, silence.ErrNotFound) || errors.Is(err, silence.ErrNotAllowed) {
		return
	}
	detail := x.Starts.Format(time.RFC3339) + " – " + x.Ends.Format(time.RFC3339)
	if x.Comment != "" {
		detail += ": " + x.Comment
	}
	s.note(r, action, "silence/"+silenceScope(x), detail, err)
}
