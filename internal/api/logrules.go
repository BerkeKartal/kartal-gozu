package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/logwatch"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// routeLogRules adds the log rules: everyone sees them, as their alerts
// are seen; admins change them, as they count in every namespace's lines.
func (s *Server) routeLogRules(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/logrules", s.require(auth.Viewer, s.logRuleList))
	mux.HandleFunc("POST /api/v1/logrules", s.requireEverywhere(auth.Admin, s.addLogRule))
	mux.HandleFunc("PUT /api/v1/logrules/{id}", s.requireEverywhere(auth.Admin, s.changeLogRule))
	mux.HandleFunc("DELETE /api/v1/logrules/{id}", s.requireEverywhere(auth.Admin, s.removeLogRule))
	mux.HandleFunc("POST /api/v1/logrules/try", s.requireEverywhere(auth.Admin, s.tryLogRule))
}

const logRuleFields = `{"name", "source", "index", "query", "window", "above", "severity"}`

func (s *Server) logRules(w http.ResponseWriter) *logwatch.Monitor {
	if s.cfg.LogRules == nil {
		writeError(w, http.StatusNotFound, "log rules are not available on this server")
	}
	return s.cfg.LogRules
}

func (s *Server) logRuleList(w http.ResponseWriter, _ *http.Request) {
	if m := s.logRules(w); m != nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": m.List(), "where": m.Where(), "loadError": m.LoadError()})
	}
}

// logRuleError answers for a change that failed; it reports whether one
// did.
func logRuleError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, logwatch.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the log rules could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) addLogRule(w http.ResponseWriter, r *http.Request) {
	m := s.logRules(w)
	var x settings.LogRule
	if m == nil || !readJSON(w, r, &x, logRuleFields) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Add(ctx, x)
	s.noteLogRule(r, "add-log-rule", x, err)
	if !logRuleError(w, err) {
		writeJSON(w, http.StatusCreated, saved)
	}
}

func (s *Server) changeLogRule(w http.ResponseWriter, r *http.Request) {
	m := s.logRules(w)
	var x settings.LogRule
	if m == nil || !readJSON(w, r, &x, logRuleFields) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Change(ctx, r.PathValue("id"), x)
	s.noteLogRule(r, "change-log-rule", x, err)
	if !logRuleError(w, err) {
		writeJSON(w, http.StatusOK, saved)
	}
}

func (s *Server) removeLogRule(w http.ResponseWriter, r *http.Request) {
	m := s.logRules(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	x, err := m.Remove(ctx, r.PathValue("id"))
	if x.Name == "" {
		x.Name = r.PathValue("id")
	}
	s.noteLogRule(r, "remove-log-rule", x, err)
	if !logRuleError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + x.Name})
	}
}

// tryLogRule counts the lines of the rule in the body once, so admins see
// what a rule would find before they save it.
func (s *Server) tryLogRule(w http.ResponseWriter, r *http.Request) {
	m := s.logRules(w)
	var x settings.LogRule
	if m == nil || !readJSON(w, r, &x, logRuleFields) {
		return
	}
	res, err := m.Try(r.Context(), x)
	if !logRuleError(w, err) {
		writeJSON(w, http.StatusOK, res)
	}
}

// noteLogRule adds a change to the rules to the audit log, unless it was
// refused before anything was tried, as a bad or unknown rule is.
func (s *Server) noteLogRule(r *http.Request, action string, x settings.LogRule, err error) {
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) || errors.Is(err, logwatch.ErrNotFound) {
		return
	}
	s.note(r, action, "log-rule/"+x.Name, x.Query, err)
}
