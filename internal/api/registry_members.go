package api

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
)

// A registry project's members, as Harbor shows them: everyone and
// everything with a role in it, and why. Its admins, and the admins of
// everything, give the UI's users and groups roles in it here; such a
// role is a grant of the project alone (role@registry:project), so no one
// here gives a role anywhere else. What reaches the project otherwise (a
// grant everywhere, a pattern such as registry:*, KARTAL_USERS, the
// directory's rules, robot accounts) is shown and changed where it is set.

func (s *Server) routeRegistryMembers(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/registry/projects/{name}/members", s.signedIn(s.registryMembers))
	mux.HandleFunc("PUT /api/v1/registry/projects/{name}/members", s.signedIn(s.registrySetMember))
	mux.HandleFunc("DELETE /api/v1/registry/projects/{name}/members/{kind}/{member}", s.signedIn(s.registryRemoveMember))
}

// memberSource is one grant that gives a member a role in the project:
// their own, a group's, KARTAL_USERS', a robot's or a directory rule's.
// Scope is what of it reaches the project (registry:team-a, registry:*),
// or empty for a grant everywhere; a grant's clusters are not shown.
type memberSource struct {
	Kind  string `json:"kind"`
	Name  string `json:"name,omitempty"`
	Role  string `json:"role"`
	Scope string `json:"scope"`
}

// projectMember is someone or something with a role in a project. Own is
// the role a grant of the project's own gives them, which this page
// changes; Editable says it may be changed here (the UI's users and
// groups).
type projectMember struct {
	Kind     string         `json:"kind"`
	Name     string         `json:"name"`
	FullName string         `json:"fullName,omitempty"`
	Role     string         `json:"role"`
	Own      string         `json:"own,omitempty"`
	Editable bool           `json:"editable"`
	Disabled bool           `json:"disabled,omitempty"`
	From     []memberSource `json:"from"`
}

// reaching are the grants that give a role in the project, as sources.
func reaching(grants []string, project, kind, name string) []memberSource {
	var out []memberSource
	for _, text := range grants {
		g, err := auth.ParseGrant(text)
		if err != nil {
			continue
		}
		role := auth.NewUser("", []auth.Grant{g}).RoleInProject(project)
		if role == 0 {
			continue
		}
		scope := ""
		for _, sc := range g.Scopes {
			one := auth.Grant{Role: g.Role, Scopes: []auth.Scope{sc}}
			if sc.Registry() && auth.NewUser("", []auth.Grant{one}).RoleInProject(project) > 0 {
				// The project's own scope says most.
				if scope == "" || sc.Project == project {
					scope = "registry:" + sc.Project
				}
			}
		}
		out = append(out, memberSource{Kind: kind, Name: name, Role: role.String(), Scope: scope})
	}
	return out
}

func bestRole(sources []memberSource) auth.Role {
	var best auth.Role
	for _, src := range sources {
		if r, err := auth.ParseRole(src.Role); err == nil {
			best = max(best, r)
		}
	}
	return best
}

// projectMembers are the project's members, the highest roles first.
func (s *Server) projectMembers(project string) []projectMember {
	out := []projectMember{}
	add := func(m projectMember, sources []memberSource) {
		if role := bestRole(sources); role > 0 {
			m.Role, m.From = role.String(), sources
			out = append(out, m)
		}
	}
	if m := s.cfg.Accounts; m != nil {
		groups := map[string][]string{}
		for _, g := range m.Groups() {
			groups[strings.ToLower(g.Name)] = g.Grants
			own := accounts.ProjectRoleOf(g.Grants, project)
			add(projectMember{Kind: "group", Name: g.Name, Own: roleText(own), Editable: true}, reaching(g.Grants, project, "own", ""))
		}
		viaGroups := func(names []string) []memberSource {
			var out []memberSource
			for _, n := range names {
				out = append(out, reaching(groups[strings.ToLower(n)], project, "group", n)...)
			}
			return out
		}
		for _, u := range m.List() {
			own := accounts.ProjectRoleOf(u.Grants, project)
			add(projectMember{Kind: "user", Name: u.Name, FullName: u.FullName, Own: roleText(own), Editable: true, Disabled: u.Disabled},
				append(reaching(u.Grants, project, "own", ""), viaGroups(u.Groups)...))
		}
		for _, u := range m.Fixed() {
			add(projectMember{Kind: "fixed", Name: u.Name}, append(reaching(u.Grants, project, "start", ""), viaGroups(u.Groups)...))
		}
		for _, r := range m.Robots() {
			add(projectMember{Kind: "robot", Name: r.Login, Disabled: r.Disabled || r.Expired}, reaching(r.Grants, project, "robot", ""))
		}
	}
	for _, rule := range s.cfg.DirectoryRules {
		group, grant, _ := strings.Cut(rule, "=>")
		group = strings.TrimSpace(group)
		add(projectMember{Kind: "rule", Name: group}, reaching([]string{strings.TrimSpace(grant)}, project, "directory", group))
	}
	rank := func(m projectMember) auth.Role { r, _ := auth.ParseRole(m.Role); return r }
	order := map[string]int{"user": 0, "group": 1, "fixed": 2, "robot": 3, "rule": 4}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i]), rank(out[j]); ri != rj {
			return ri > rj
		}
		if order[out[i].Kind] != order[out[j].Kind] {
			return order[out[i].Kind] < order[out[j].Kind]
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func roleText(r auth.Role) string {
	if r == 0 {
		return ""
	}
	return r.String()
}

// mayManageMembers: the admins of everything, and the project's admins.
func mayManageMembers(u auth.User, project string) bool {
	return u.Everywhere() >= auth.Admin || u.RoleInProject(project) >= auth.Admin
}

// memberProject checks the project's name and that it is there, answering
// the request when not.
func (s *Server) memberProject(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if !registry.ValidProject(name) {
		writeError(w, http.StatusBadRequest, "not a project's name")
		return "", false
	}
	status, _, err := s.registryCall(r, http.MethodGet, "/admin/v1/projects/"+url.PathEscape(name), nil, nil)
	switch {
	case err != nil:
		writeError(w, http.StatusBadGateway, "the image registry could not be reached")
		return "", false
	case status == http.StatusNotFound:
		writeError(w, http.StatusNotFound, "no such project")
		return "", false
	case status != http.StatusOK:
		writeError(w, http.StatusBadGateway, "the image registry could not say whether the project is there")
		return "", false
	}
	return name, true
}

type memberCandidate struct {
	Name     string `json:"name"`
	FullName string `json:"fullName,omitempty"`
}

func (s *Server) registryMembers(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	project := r.PathValue("name")
	if u.RoleInProject(project) < auth.Viewer && u.Everywhere() < auth.Admin {
		writeError(w, http.StatusForbidden, "this needs a role in the registry project "+project)
		return
	}
	if _, ok := s.memberProject(w, r); !ok {
		return
	}
	may := mayManageMembers(u, project) && s.cfg.Accounts != nil
	out := map[string]any{"members": s.projectMembers(project), "mayEdit": may}
	// Who may be added: the names of the UI's users and groups, no more.
	if may {
		users, groups := []memberCandidate{}, []memberCandidate{}
		for _, e := range s.cfg.Accounts.List() {
			users = append(users, memberCandidate{Name: e.Name, FullName: e.FullName})
		}
		for _, g := range s.cfg.Accounts.Groups() {
			groups = append(groups, memberCandidate{Name: g.Name})
		}
		out["candidates"] = map[string]any{"users": users, "groups": groups}
	}
	writeJSON(w, http.StatusOK, out)
}

// setMember gives a user or a group of the UI a role in the project, or
// takes it away with none, then ends the sessions it changes and notes it.
func (s *Server) setMember(w http.ResponseWriter, r *http.Request, kind, name string, role auth.Role) {
	u := userOf(r)
	project, ok := s.memberProject(w, r)
	if !ok {
		return
	}
	if !mayManageMembers(u, project) {
		writeError(w, http.StatusForbidden, "only the project's admins, and the admins of everything, change its members")
		return
	}
	m := s.accounts(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var err error
	var object string
	switch kind {
	case "user":
		var e accounts.Entry
		e, err = m.SetUserProjectRole(ctx, name, project, role, u.Name)
		object = "user/" + name
		if err == nil {
			s.signOut(e.Name)
		}
	case "group":
		var before, after accounts.GroupEntry
		before, after, err = m.SetGroupProjectRole(ctx, name, project, role, u.Name)
		object = "group/" + name
		if err == nil {
			s.signOutGroups(before, after)
		}
	default:
		writeError(w, http.StatusBadRequest, "a member here is a user or a group of the UI")
		return
	}
	detail := project + ": " + role.String()
	if role == 0 {
		detail = project + ": none"
	}
	e := AuditEntry{Time: s.now().UTC(), User: u.Name, Role: u.Role.String(), Action: "registry-member", Object: object, Detail: detail, OK: err == nil, Project: project}
	if err != nil {
		e.Error = err.Error()
	}
	s.audit.add(e)
	s.log.Info("audit", "user", e.User, "action", e.Action, "object", e.Object, "detail", e.Detail, "ok", e.OK, "error", e.Error)
	if accountError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": s.projectMembers(project)})
}

func (s *Server) registrySetMember(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if !readJSON(w, r, &b, `{"kind": "user", "name": "ayse", "role": "operator"}`) {
		return
	}
	role, err := auth.ParseRole(b.Role)
	if err != nil || role == 0 {
		writeError(w, http.StatusBadRequest, "the role is viewer, operator or admin")
		return
	}
	if strings.TrimSpace(b.Name) == "" {
		writeError(w, http.StatusBadRequest, "name the user or the group")
		return
	}
	s.setMember(w, r, b.Kind, strings.TrimSpace(b.Name), role)
}

func (s *Server) registryRemoveMember(w http.ResponseWriter, r *http.Request) {
	s.setMember(w, r, r.PathValue("kind"), r.PathValue("member"), 0)
}
