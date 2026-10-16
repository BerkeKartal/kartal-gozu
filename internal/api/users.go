package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// routeUsers adds the users admins manage in the UI, and changing one's own
// password.
func (s *Server) routeUsers(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users", s.requireEverywhere(auth.Admin, s.usersList))
	mux.HandleFunc("POST /api/v1/users", s.requireEverywhere(auth.Admin, s.userAdd))
	mux.HandleFunc("PUT /api/v1/users/{name}", s.requireEverywhere(auth.Admin, s.userUpdate))
	mux.HandleFunc("DELETE /api/v1/users/{name}", s.requireEverywhere(auth.Admin, s.userRemove))
	mux.HandleFunc("POST /api/v1/me/password", s.require(auth.Viewer, s.ownPassword))
}

func (s *Server) accounts(w http.ResponseWriter) *accounts.Manager {
	if s.cfg.Accounts == nil {
		writeError(w, http.StatusNotFound, "managing users in the UI is not available on this server")
	}
	return s.cfg.Accounts
}

// accountError writes the answer to a failed change; it reports whether
// there was one.
func accountError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, accounts.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, accounts.ErrWrongPassword):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the settings could not be saved: "+err.Error())
	}
	return true
}

// signOut ends a user's sessions once their account changed, so that
// what they may do changes at once too.
func (s *Server) signOut(name string) {
	if s.sessions != nil {
		s.sessions.EndUser(name)
	}
}

type userBody struct {
	Name     string `json:"name"`
	Grant    string `json:"grant"`
	Password string `json:"password"`
}

const userHint = `{"name": "ali", "grant": "operator@production/payments", "password": "..."}`

func (s *Server) usersList(w http.ResponseWriter, _ *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": m.List(), "fixed": m.Fixed(), "directory": s.cfg.Directory, "where": m.Where()})
}

func (s *Server) userAdd(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	var b userBody
	if !readJSON(w, r, &b, userHint) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	e, err := m.Add(ctx, b.Name, b.Grant, b.Password, userOf(r).Name)
	s.note(r, "add-user", "user/"+b.Name, b.Grant, err)
	if accountError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	var b userBody
	if !readJSON(w, r, &b, `{"grant": "viewer", "password": "..."} (either may be left out)`) {
		return
	}
	name := r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	e, err := m.Update(ctx, name, b.Grant, b.Password, userOf(r).Name)
	detail := b.Grant
	if b.Password != "" {
		detail += " (new password)"
	}
	s.note(r, "change-user", "user/"+name, detail, err)
	if accountError(w, err) {
		return
	}
	s.signOut(e.Name)
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) userRemove(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	name := r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	e, err := m.Remove(ctx, name)
	s.note(r, "remove-user", "user/"+name, "", err)
	if accountError(w, err) {
		return
	}
	s.signOut(e.Name)
	writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + e.Name})
}

// ownPassword changes the signed-in user's own password, for the users of
// the UI; the current password is asked for again.
func (s *Server) ownPassword(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	var b struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &b, `{"current": "...", "password": "..."}`) {
		return
	}
	u := userOf(r)
	if !m.Has(u.Name) {
		writeError(w, http.StatusBadRequest, "your password is not kept here; change it where it is (KARTAL_USERS or the directory)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	err := m.ChangeOwn(ctx, u.Name, b.Current, b.Password)
	s.note(r, "change-own-password", "user/"+u.Name, "", err)
	if accountError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
