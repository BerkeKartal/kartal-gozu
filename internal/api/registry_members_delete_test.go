package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
)

// A deleted project's members lose their roles in it: a project made later
// by the name, by someone else maybe, gives them nothing.
func TestDeletedProjectsMembers(t *testing.T) {
	e := newRegEnv(t)
	for _, p := range []string{"old", "team-b"} {
		if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"`+p+`"}`); code != 201 {
			t.Fatalf("project %s: %d %s", p, code, b)
		}
	}
	if code, b := e.call("POST", "/api/v1/users", bossTok, `{"name":"ayse","grants":["viewer@production/payments+registry:old"],"password":"dogru-parola-1"}`); code != 201 {
		t.Fatalf("user: %d %s", code, b)
	}
	if code, b := e.call("POST", "/api/v1/groups", bossTok, `{"name":"qa","grants":["viewer@registry:old","viewer@registry:*"]}`); code != 201 {
		t.Fatalf("group: %d %s", code, b)
	}
	for _, body := range []string{`{"name":"only","grants":["operator@registry:old"]}`, `{"name":"both","grants":["operator@registry:old+registry:team-b"]}`} {
		if code, b := e.call("POST", "/api/v1/registry/robots", bossTok, body); code != 201 {
			t.Fatalf("robot: %d %s", code, b)
		}
	}
	sess := e.signIn("ayse", "dogru-parola-1")
	if code, b := e.call("DELETE", "/api/v1/registry/projects/old", bossTok, ""); code != 204 {
		t.Fatalf("delete: %d %s", code, b)
	}
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"old"}`); code != 201 {
		t.Fatalf("the name again: %d %s", code, b)
	}
	_, a := e.members("old", bossTok)
	for _, m := range a.Members {
		if m.Own != "" || (m.Kind == "user" && m.Name == "ayse") || (m.Kind == "robot" && m.Name != "robot$both" && !m.Disabled) {
			t.Errorf("a member of the old project in the new one: %+v", m)
		}
	}
	_, b := e.call("GET", "/api/v1/users", bossTok, "")
	if !strings.Contains(string(b), `"grants":["viewer@production/payments"]`) || !strings.Contains(string(b), `"grants":["viewer@registry:*"]`) {
		t.Errorf("what else they had is as it was: %s", b)
	}
	robots := map[string]accounts.RobotEntry{}
	_, b = e.call("GET", "/api/v1/registry/robots", bossTok, "")
	var list []accounts.RobotEntry
	json.Unmarshal(b, &list)
	for _, r := range list {
		robots[r.Name] = r
	}
	if r := robots["both"]; strings.Join(r.Grants, ",") != "operator@registry:team-b" || r.Disabled {
		t.Errorf("a robot of two projects: %+v", r)
	}
	if r := robots["only"]; len(r.Grants) != 0 || !r.Disabled {
		t.Errorf("a robot of the deleted project alone: %+v", r)
	}
	// Her session ended with her role.
	if code, _ := e.call("GET", "/api/v1/me", sess, ""); code != 401 {
		t.Errorf("her session: %d", code)
	}
	_, b = e.call("GET", "/api/v1/audit", bossTok, "")
	if !strings.Contains(string(b), `"action":"registry-member"`) || !strings.Contains(string(b), "deleted") {
		t.Errorf("audit: %s", b)
	}
}
