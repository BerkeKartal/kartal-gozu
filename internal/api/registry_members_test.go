package api

import (
	"encoding/json"
	"strings"
	"testing"
)

type membersAnswer struct {
	Members    []projectMember `json:"members"`
	MayEdit    bool            `json:"mayEdit"`
	Candidates *struct {
		Users  []memberCandidate `json:"users"`
		Groups []memberCandidate `json:"groups"`
	} `json:"candidates"`
}

func (e *regEnv) members(project, token string) (int, membersAnswer) {
	e.t.Helper()
	code, b := e.call("GET", "/api/v1/registry/projects/"+project+"/members", token, "")
	var a membersAnswer
	json.Unmarshal(b, &a)
	return code, a
}

func memberOf(a membersAnswer, kind, name string) (projectMember, bool) {
	for _, m := range a.Members {
		if m.Kind == kind && m.Name == name {
			return m, true
		}
	}
	return projectMember{}, false
}

// signIn signs in with a password, as the UI does, for a session token.
func (e *regEnv) signIn(user, password string) string {
	e.t.Helper()
	code, b := e.call("POST", "/api/v1/login", "", `{"username":"`+user+`","password":"`+password+`"}`)
	var a struct {
		Token string `json:"token"`
	}
	json.Unmarshal(b, &a)
	if code != 200 || a.Token == "" {
		e.t.Fatalf("sign in as %s: %d %s", user, code, b)
	}
	return a.Token
}

func TestRegistryMembers(t *testing.T) {
	e := newRegEnv(t)
	for _, p := range []string{"team-a", "team-b"} {
		if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"`+p+`"}`); code != 201 {
			t.Fatalf("project %s: %d %s", p, code, b)
		}
	}
	for _, body := range []string{
		`{"name":"ayse","fullName":"Ayşe Y","grants":["viewer@production/payments"],"password":"dogru-parola-1"}`,
		`{"name":"veli","grants":["admin@registry:*"],"password":"dogru-parola-2"}`,
	} {
		if code, b := e.call("POST", "/api/v1/users", bossTok, body); code != 201 {
			t.Fatalf("user: %d %s", code, b)
		}
	}
	if code, b := e.call("POST", "/api/v1/groups", bossTok, `{"name":"devops","grants":["viewer@staging"],"members":["ayse"]}`); code != 201 {
		t.Fatalf("group: %d %s", code, b)
	}
	if code, b := e.call("POST", "/api/v1/registry/robots", bossTok, `{"name":"ci","grants":["operator@registry:team-a"]}`); code != 201 {
		t.Fatalf("robot: %d %s", code, b)
	}

	// Who sees the members, and who may change them.
	for _, c := range []struct {
		tok        string
		code       int
		edit, cand bool
	}{
		{regLeadTok, 200, true, true},   // the project's admin
		{clusterTok, 200, true, true},   // an admin of every cluster and namespace
		{bossTok, 200, true, true},      // an admin of everything
		{regTeamTok, 200, false, false}, // an operator sees, and changes nothing
		{regViewTok, 200, false, false},
	} {
		code, a := e.members("team-a", c.tok)
		if code != c.code || a.MayEdit != c.edit || (a.Candidates != nil) != c.cand {
			t.Errorf("%s: %d %+v", c.tok, code, a)
		}
	}
	if code, _ := e.members("team-b", regLeadTok); code != 403 {
		t.Errorf("another project's members: %d", code)
	}
	if code, _ := e.members("nowhere", bossTok); code != 404 {
		t.Errorf("no such project: %d", code)
	}
	_, a := e.members("team-a", regLeadTok)
	if m, ok := memberOf(a, "robot", "robot$ci"); !ok || m.Role != "operator" || m.Editable {
		t.Errorf("the robot: %+v", a.Members)
	}
	if m, ok := memberOf(a, "user", "veli"); !ok || m.Role != "admin" || m.Own != "" || len(m.From) != 1 || m.From[0].Scope != "registry:*" {
		t.Errorf("a registry admin, by a pattern: %+v", m)
	}
	if _, ok := memberOf(a, "user", "ayse"); ok {
		t.Error("ayse has no role in team-a yet")
	}
	// Names only: no grants of the candidates.
	if raw, _ := json.Marshal(a.Candidates); !strings.Contains(string(raw), `"Ayşe Y"`) || strings.Contains(string(raw), "production") {
		t.Errorf("candidates: %s", raw)
	}

	// ayse signs in; her role in team-a then ends that session.
	sess := e.signIn("ayse", "dogru-parola-1")
	if code, _ := e.call("GET", "/api/v1/me", sess, ""); code != 200 {
		t.Fatalf("the session: %d", code)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a/members", regLeadTok, `{"kind":"user","name":"ayse","role":"operator"}`); code != 200 {
		t.Fatalf("set: %d %s", code, b)
	}
	if code, _ := e.call("GET", "/api/v1/me", sess, ""); code != 401 {
		t.Errorf("her session outlived the change: %d", code)
	}
	// Her clusters' grant is as it was.
	_, b := e.call("GET", "/api/v1/users", bossTok, "")
	if !strings.Contains(string(b), `"grants":["viewer@production/payments","operator@registry:team-a"]`) {
		t.Errorf("her grants: %s", b)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a/members", regLeadTok, `{"kind":"group","name":"devops","role":"viewer"}`); code != 200 {
		t.Fatalf("a group: %d %s", code, b)
	}
	_, a = e.members("team-a", regViewTok)
	m, ok := memberOf(a, "user", "ayse")
	if !ok || m.Role != "operator" || m.Own != "operator" || !m.Editable || len(m.From) != 2 {
		t.Errorf("ayse, her own and her group's: %+v", m)
	}
	if g, ok := memberOf(a, "group", "devops"); !ok || g.Own != "viewer" {
		t.Errorf("the group: %+v", g)
	}
	// Taken away: what her group gives stays.
	if code, b := e.call("DELETE", "/api/v1/registry/projects/team-a/members/user/ayse", regLeadTok, ""); code != 200 {
		t.Fatalf("remove: %d %s", code, b)
	}
	_, a = e.members("team-a", regViewTok)
	if m, ok := memberOf(a, "user", "ayse"); !ok || m.Role != "viewer" || m.Own != "" {
		t.Errorf("after: %+v", m)
	}

	// What may not be done.
	for _, c := range []struct {
		method, path, tok, body string
		code                    int
	}{
		{"PUT", "/api/v1/registry/projects/team-a/members", regTeamTok, `{"kind":"user","name":"ayse","role":"admin"}`, 403},
		{"PUT", "/api/v1/registry/projects/team-b/members", regLeadTok, `{"kind":"user","name":"ayse","role":"admin"}`, 403},
		{"DELETE", "/api/v1/registry/projects/team-b/members/group/devops", regLeadTok, "", 403},
		{"PUT", "/api/v1/registry/projects/team-a/members", regLeadTok, `{"kind":"robot","name":"ci","role":"admin"}`, 400},
		{"PUT", "/api/v1/registry/projects/team-a/members", regLeadTok, `{"kind":"user","name":"ayse","role":"none"}`, 400},
		{"PUT", "/api/v1/registry/projects/team-a/members", regLeadTok, `{"kind":"user","name":"ayse","role":"owner"}`, 400},
		{"PUT", "/api/v1/registry/projects/team-a/members", regLeadTok, `{"kind":"user","name":"nobody","role":"viewer"}`, 404},
		{"PUT", "/api/v1/registry/projects/nowhere/members", bossTok, `{"kind":"user","name":"ayse","role":"viewer"}`, 404},
		{"PUT", "/api/v1/registry/projects/Bad*/members", bossTok, `{"kind":"user","name":"ayse","role":"viewer"}`, 400},
	} {
		if code, b := e.call(c.method, c.path, c.tok, c.body); code != c.code {
			t.Errorf("%s %s %s: %d %s", c.method, c.path, c.body, code, b)
		}
	}

	// Each change is in the audit log, with its project.
	_, b = e.call("GET", "/api/v1/audit", bossTok, "")
	if n := strings.Count(string(b), `"action":"registry-member"`); n < 3 || !strings.Contains(string(b), `"project":"team-a"`) {
		t.Errorf("audit: %d entries: %s", n, b)
	}
}
