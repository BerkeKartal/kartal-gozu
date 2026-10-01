package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/uptime"
)

// routeChecks adds the server's own URL checks: everyone sees them, admins
// change them.
func (s *Server) routeChecks(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/checks", s.require(auth.Viewer, s.checkList))
	mux.HandleFunc("POST /api/v1/checks", s.requireEverywhere(auth.Admin, s.addCheck))
	mux.HandleFunc("PUT /api/v1/checks/{id}", s.requireEverywhere(auth.Admin, s.changeCheck))
	mux.HandleFunc("DELETE /api/v1/checks/{id}", s.requireEverywhere(auth.Admin, s.removeCheck))
	mux.HandleFunc("POST /api/v1/checks/try", s.requireEverywhere(auth.Admin, s.tryCheck))
}

const checkFields = `{"name", "url", "interval", "timeout", "status", "contains", "insecure"}`

func (s *Server) checks(w http.ResponseWriter) *uptime.Monitor {
	if s.cfg.Checks == nil {
		writeError(w, http.StatusNotFound, "URL checks are not available on this server")
	}
	return s.cfg.Checks
}

func (s *Server) checkList(w http.ResponseWriter, _ *http.Request) {
	if m := s.checks(w); m != nil {
		writeJSON(w, http.StatusOK, map[string]any{"checks": m.List(), "where": m.Where(), "loadError": m.LoadError()})
	}
}

// checkError answers for a change that failed; it reports whether one did.
func checkError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, uptime.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the checks could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) addCheck(w http.ResponseWriter, r *http.Request) {
	m := s.checks(w)
	var c settings.Check
	if m == nil || !readJSON(w, r, &c, checkFields) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Add(ctx, c)
	s.noteCheck(r, "add-check", c, err)
	if !checkError(w, err) {
		writeJSON(w, http.StatusCreated, saved)
	}
}

func (s *Server) changeCheck(w http.ResponseWriter, r *http.Request) {
	m := s.checks(w)
	var c settings.Check
	if m == nil || !readJSON(w, r, &c, checkFields) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Change(ctx, r.PathValue("id"), c)
	s.noteCheck(r, "change-check", c, err)
	if !checkError(w, err) {
		writeJSON(w, http.StatusOK, saved)
	}
}

func (s *Server) removeCheck(w http.ResponseWriter, r *http.Request) {
	m := s.checks(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	c, err := m.Remove(ctx, r.PathValue("id"))
	if c.Name == "" {
		c.Name = r.PathValue("id")
	}
	s.noteCheck(r, "remove-check", c, err)
	if !checkError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + c.Name})
	}
}

// tryCheck requests the address of the check in the body once, so admins
// see what a check would say before they save it.
func (s *Server) tryCheck(w http.ResponseWriter, r *http.Request) {
	m := s.checks(w)
	var c settings.Check
	if m == nil || !readJSON(w, r, &c, checkFields) {
		return
	}
	res, err := m.Try(r.Context(), c)
	if !checkError(w, err) {
		writeJSON(w, http.StatusOK, res)
	}
}

// noteCheck adds a change to the checks to the audit log, unless it was
// refused before anything was tried, as a bad or unknown check is.
func (s *Server) noteCheck(r *http.Request, action string, c settings.Check, err error) {
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) || errors.Is(err, uptime.ErrNotFound) {
		return
	}
	s.note(r, action, "check/"+c.Name, c.URL, err)
}
