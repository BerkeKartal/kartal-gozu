package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// routeUsers adds the admin panel's users, groups and sessions, and
// changing one's own password.
func (s *Server) routeUsers(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users", s.requireEverywhere(auth.Admin, s.usersList))
	mux.HandleFunc("POST /api/v1/users", s.requireEverywhere(auth.Admin, s.userAdd))
	mux.HandleFunc("PUT /api/v1/users/{name}", s.requireEverywhere(auth.Admin, s.userUpdate))
	mux.HandleFunc("DELETE /api/v1/users/{name}", s.requireEverywhere(auth.Admin, s.userRemove))
	mux.HandleFunc("POST /api/v1/groups", s.requireEverywhere(auth.Admin, s.groupAdd))
	mux.HandleFunc("PUT /api/v1/groups/{name}", s.requireEverywhere(auth.Admin, s.groupUpdate))
	mux.HandleFunc("DELETE /api/v1/groups/{name}", s.requireEverywhere(auth.Admin, s.groupRemove))
	mux.HandleFunc("GET /api/v1/sessions", s.requireEverywhere(auth.Admin, s.sessionsList))
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.requireEverywhere(auth.Admin, s.sessionEnd))
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
	case errors.Is(err, accounts.ErrNotFound), errors.Is(err, accounts.ErrGroupNotFound):
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

// signOutGroups ends the sessions of everyone the groups reach.
func (s *Server) signOutGroups(groups ...accounts.GroupEntry) {
	if s.sessions != nil {
		s.sessions.EndWhere(accounts.Reaches(groups...))
	}
}

// userBody is a user to add or a change to one. Fields left out stay as
// they are; grant is the single grant of before there could be several.
type userBody struct {
	Name     string   `json:"name"`
	FullName *string  `json:"fullName"`
	Email    *string  `json:"email"`
	Grant    string   `json:"grant"`
	Grants   []string `json:"grants"`
	Password string   `json:"password"`
	Disabled *bool    `json:"disabled"`
	Groups   []string `json:"groups"`
}

func (b userBody) input() accounts.UserInput {
	grants := b.Grants
	if grants == nil && strings.TrimSpace(b.Grant) != "" {
		grants = []string{b.Grant}
	}
	return accounts.UserInput{Name: b.Name, FullName: b.FullName, Email: b.Email, Grants: grants,
		Password: b.Password, Disabled: b.Disabled, Groups: b.Groups}
}

// detail describes a change for the audit log, never with a password.
func (b userBody) detail() string {
	var parts []string
	if b.Grants != nil {
		parts = append(parts, "grants: "+listed(b.Grants, ", "))
	} else if b.Grant != "" {
		parts = append(parts, "grant: "+b.Grant)
	}
	if b.Groups != nil {
		parts = append(parts, "groups: "+listed(b.Groups, ", "))
	}
	if b.Disabled != nil {
		if *b.Disabled {
			parts = append(parts, "disabled")
		} else {
			parts = append(parts, "enabled")
		}
	}
	if b.Password != "" {
		parts = append(parts, "new password")
	}
	return strings.Join(parts, "; ")
}

const userHint = `{"name": "ali", "grants": ["operator@production/payments", "viewer@staging"], "password": "..."}`

// directoryRule is a rule of KARTAL_LDAP_GROUPS, shown as it is set.
type directoryRule struct {
	Group string `json:"group"`
	Grant string `json:"grant"`
}

func (s *Server) usersList(w http.ResponseWriter, _ *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	rules := []directoryRule{}
	for _, r := range s.cfg.DirectoryRules {
		group, grant, _ := strings.Cut(r, "=>")
		rules = append(rules, directoryRule{Group: strings.TrimSpace(group), Grant: strings.TrimSpace(grant)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": m.List(), "groups": m.Groups(), "fixed": m.Fixed(),
		"directory": s.cfg.Directory, "directoryRules": rules, "where": m.Where()})
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
	e, err := m.Add(ctx, b.input(), userOf(r).Name)
	s.note(r, "add-user", "user/"+b.Name, b.detail(), err)
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
	if !readJSON(w, r, &b, `{"grants": ["viewer"], "disabled": false, "password": "..."} (any may be left out)`) {
		return
	}
	name := r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	e, err := m.Update(ctx, name, b.input(), userOf(r).Name)
	s.note(r, "change-user", "user/"+name, b.detail(), err)
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
	e, err := m.Remove(ctx, name, userOf(r).Name)
	s.note(r, "remove-user", "user/"+name, "", err)
	if accountError(w, err) {
		return
	}
	s.signOut(e.Name)
	writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + e.Name})
}

// groupBody is a group to add or a change to one; fields left out stay.
type groupBody struct {
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	Grants      []string `json:"grants"`
	Members     []string `json:"members"`
	Directory   []string `json:"directory"`
}

func (b groupBody) input() accounts.GroupInput {
	return accounts.GroupInput{Name: b.Name, Description: b.Description, Grants: b.Grants, Members: b.Members, Directory: b.Directory}
}

func (b groupBody) detail() string {
	var parts []string
	if b.Grants != nil {
		parts = append(parts, "grants: "+listed(b.Grants, ", "))
	}
	if b.Members != nil {
		parts = append(parts, "members: "+listed(b.Members, ", "))
	}
	if b.Directory != nil {
		parts = append(parts, "directory: "+listed(b.Directory, " | "))
	}
	return strings.Join(parts, "; ")
}

const groupHint = `{"name": "payments", "grants": ["operator@production/payments"], "members": ["ali"], "directory": ["CN=Payments,OU=Groups,DC=example,DC=org"]}`

func (s *Server) groupAdd(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	var b groupBody
	if !readJSON(w, r, &b, groupHint) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	g, err := m.AddGroup(ctx, b.input(), userOf(r).Name)
	s.note(r, "add-group", "group/"+b.Name, b.detail(), err)
	if accountError(w, err) {
		return
	}
	// Its members get what it gives at their next sign-in, which is now.
	s.signOutGroups(g)
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) groupUpdate(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	var b groupBody
	if !readJSON(w, r, &b, groupHint+" (any may be left out)") {
		return
	}
	name := r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	before, after, err := m.UpdateGroup(ctx, name, b.input(), userOf(r).Name)
	s.note(r, "change-group", "group/"+name, b.detail(), err)
	if accountError(w, err) {
		return
	}
	s.signOutGroups(before, after)
	writeJSON(w, http.StatusOK, after)
}

func (s *Server) groupRemove(w http.ResponseWriter, r *http.Request) {
	m := s.accounts(w)
	if m == nil {
		return
	}
	name := r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	g, err := m.RemoveGroup(ctx, name)
	s.note(r, "remove-group", "group/"+name, "", err)
	if accountError(w, err) {
		return
	}
	s.signOutGroups(g)
	writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + g.Name})
}

// sessionsList shows the live sessions; "you" is the one asking, so that
// an admin does not end it by mistake.
func (s *Server) sessionsList(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []auth.SessionInfo{}, "you": ""})
		return
	}
	you := ""
	if tok := bearerToken(r); strings.HasPrefix(tok, "kgs_") {
		you = auth.SessionID(tok)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": s.sessions.List(), "you": you})
}

func (s *Server) sessionEnd(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "there is no such session")
		return
	}
	id := r.PathValue("id")
	name, ok := s.sessions.EndID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "there is no such session; it may have ended already")
		return
	}
	s.note(r, "end-session", "user/"+name, "session "+id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"message": "ended a session of " + name})
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
	// Whoever else holds a session of theirs is out; this one stays.
	if s.sessions != nil {
		s.sessions.EndOthers(u.Name, bearerToken(r))
	}
	w.WriteHeader(http.StatusNoContent)
}

// listed joins a list for the audit log, saying so when it is empty.
func listed(xs []string, sep string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, sep)
}
