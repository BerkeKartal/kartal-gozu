package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/dashboard"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// routeDashboards adds the saved dashboards: everyone sees them, each panel
// showing what the person looking may see; operators make them, and those
// who made one, or admins, change it.
func (s *Server) routeDashboards(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/dashboards", s.require(auth.Viewer, s.dashboardList))
	mux.HandleFunc("GET /api/v1/dashboards/{id}", s.require(auth.Viewer, s.dashboardGet))
	mux.HandleFunc("POST /api/v1/dashboards", s.require(auth.Operator, s.dashboardAdd))
	mux.HandleFunc("PUT /api/v1/dashboards/{id}", s.require(auth.Operator, s.dashboardSave))
	mux.HandleFunc("DELETE /api/v1/dashboards/{id}", s.require(auth.Operator, s.dashboardRemove))
}

func (s *Server) dashboards(w http.ResponseWriter) *dashboard.Manager {
	if s.cfg.Dashboards == nil {
		writeError(w, http.StatusNotFound, "dashboards are not available on this server")
	}
	return s.cfg.Dashboards
}

// mayChange tells whether a user may change a dashboard.
func mayChange(u auth.User) func(settings.Dashboard) bool {
	return func(d settings.Dashboard) bool {
		return u.Role >= auth.Operator && (d.Owner == u.Name || u.Everywhere() >= auth.Admin)
	}
}

// dashboardView is a dashboard with whether the user may change it.
type dashboardView struct {
	settings.Dashboard
	CanEdit bool   `json:"canEdit"`
	Where   string `json:"where"`
}

func (s *Server) dashboardList(w http.ResponseWriter, _ *http.Request) {
	if m := s.dashboards(w); m != nil {
		writeJSON(w, http.StatusOK, map[string]any{"dashboards": m.List(), "where": m.Where()})
	}
}

func (s *Server) dashboardGet(w http.ResponseWriter, r *http.Request) {
	m := s.dashboards(w)
	if m == nil {
		return
	}
	d, ok := m.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, dashboard.ErrNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, dashboardView{Dashboard: d, CanEdit: mayChange(userOf(r))(d), Where: m.Where()})
}

// readDashboard reads a dashboard from the body: it may be larger than the
// other bodies are.
func readDashboard(w http.ResponseWriter, r *http.Request) (settings.Dashboard, bool) {
	var d settings.Dashboard
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&d); err != nil {
		writeError(w, http.StatusBadRequest, "the body must be a dashboard of up to 1 MiB: "+err.Error())
		return d, false
	}
	return d, true
}

// dashboardError answers for a change that failed; it reports whether one
// did.
func dashboardError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	var conflict *dashboard.ConflictError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.As(err, &conflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, dashboard.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, dashboard.ErrNotYours):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the dashboards could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) noteDashboard(r *http.Request, action string, d settings.Dashboard, err error) {
	var invalid *settings.InvalidError
	var conflict *dashboard.ConflictError
	if errors.As(err, &invalid) || errors.As(err, &conflict) || errors.Is(err, dashboard.ErrNotFound) || errors.Is(err, dashboard.ErrNotYours) {
		return
	}
	s.note(r, action, "dashboard/"+d.Title, "", err)
}

func (s *Server) dashboardAdd(w http.ResponseWriter, r *http.Request) {
	m := s.dashboards(w)
	if m == nil {
		return
	}
	d, ok := readDashboard(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Add(ctx, d, userOf(r).Name)
	s.noteDashboard(r, "add-dashboard", saved, err)
	if !dashboardError(w, err) {
		writeJSON(w, http.StatusCreated, dashboardView{Dashboard: saved, CanEdit: true, Where: m.Where()})
	}
}

func (s *Server) dashboardSave(w http.ResponseWriter, r *http.Request) {
	m := s.dashboards(w)
	if m == nil {
		return
	}
	d, ok := readDashboard(w, r)
	if !ok {
		return
	}
	u := userOf(r)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Save(ctx, r.PathValue("id"), d, u.Name, mayChange(u))
	s.noteDashboard(r, "save-dashboard", saved, err)
	if !dashboardError(w, err) {
		writeJSON(w, http.StatusOK, dashboardView{Dashboard: saved, CanEdit: true, Where: m.Where()})
	}
}

func (s *Server) dashboardRemove(w http.ResponseWriter, r *http.Request) {
	m := s.dashboards(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	gone, err := m.Remove(ctx, r.PathValue("id"), mayChange(userOf(r)))
	s.noteDashboard(r, "remove-dashboard", gone, err)
	if !dashboardError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + gone.Title})
	}
}
