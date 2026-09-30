package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// routeSettings adds what admins change in the UI: the e-mail channel.
func (s *Server) routeSettings(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/settings/email", s.require(auth.Admin, s.emailSettings))
	mux.HandleFunc("PUT /api/v1/settings/email", s.require(auth.Admin, s.saveEmailSettings))
	mux.HandleFunc("POST /api/v1/settings/email/test", s.require(auth.Admin, s.testEmailSettings))
}

// note adds a change that is not a cluster command to the audit log.
func (s *Server) note(r *http.Request, action, object, detail string, err error) {
	u := userOf(r)
	e := AuditEntry{Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: action, Object: object, Detail: detail, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	s.audit.add(e)
	s.log.Info("audit", "user", e.User, "action", e.Action, "object", e.Object, "detail", e.Detail, "ok", e.OK, "error", e.Error)
}

func (s *Server) mail(w http.ResponseWriter) *settings.Mail {
	if s.cfg.Mail == nil {
		writeError(w, http.StatusNotFound, "e-mail settings are not available on this server")
	}
	return s.cfg.Mail
}

func (s *Server) emailSettings(w http.ResponseWriter, _ *http.Request) {
	if m := s.mail(w); m != nil {
		writeJSON(w, http.StatusOK, m.View())
	}
}

func (s *Server) saveEmailSettings(w http.ResponseWriter, r *http.Request) {
	m := s.mail(w)
	if m == nil {
		return
	}
	var c settings.Change
	if !readJSON(w, r, &c, `{"enabled", "addr", "from", "to", "username", "password"}`) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	v, err := m.Update(ctx, c)
	var invalid *settings.InvalidError
	switch {
	case errors.Is(err, settings.ErrFixed):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := v.Summary()
	if err != nil {
		detail = ""
	}
	s.note(r, "email-settings", "settings/email", detail, err)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the settings could not be saved: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// testEmailSettings sends a sample notification with the settings in the
// body (or the saved ones), before anyone relies on them.
func (s *Server) testEmailSettings(w http.ResponseWriter, r *http.Request) {
	m := s.mail(w)
	if m == nil {
		return
	}
	var c settings.Change
	if !readJSON(w, r, &c, `{"enabled", "addr", "from", "to", "username", "password"}`) {
		return
	}
	publicURL := ""
	if s.cfg.Alerts != nil {
		publicURL = s.cfg.Alerts.PublicURL
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := m.Test(ctx, c, publicURL)
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	to := strings.Join(c.To, ", ")
	if m.View().Fixed {
		to = strings.Join(m.View().To, ", ")
	}
	s.note(r, "test-email", "settings/email", to, err)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the test e-mail was not sent: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "sent to " + to})
}
