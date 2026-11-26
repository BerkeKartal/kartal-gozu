package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

func TestSources(t *testing.T) {
	e := newEnv(t)
	e.reg.cfg.SourcesKey = SourcesKey("a key of the registry's")
	ci := e.token("ci", "repository:shop/web:pull,push")
	e.pushImage("shop/web", "1.0", ci, "amd64")
	admin := func(method, path, body string) answer {
		return e.do(method, "/admin/v1/"+path, "admin-secret", []byte(body), UserHeader, "ayse")
	}
	// The registry itself is a source here.
	a := admin("POST", "sources", `{"name":"Self","kind":"registry","url":"`+e.srv.URL+`/","username":"ci","password":"pw"}`)
	var v SourceView
	if json.Unmarshal(a.body, &v); a.code != 201 || !v.HasSecret || v.URL != e.srv.URL || v.By != "ayse" {
		t.Fatalf("add: %d %s", a.code, a.body)
	}
	if strings.Contains(string(a.body), `"pw"`) || strings.Contains(string(a.body), "secret") {
		t.Errorf("the password came back: %s", a.body)
	}
	if src, _ := e.db.Source(v.ID); src.Secret == "" || strings.Contains(src.Secret, "pw") {
		t.Errorf("the password is kept as: %q", src.Secret)
	}
	// Tried with the password kept, and with a wrong one.
	var test SourceTest
	a = admin("POST", "sources/test", `{"id":"`+v.ID+`","name":"Self","kind":"registry","url":"`+e.srv.URL+`","username":"ci"}`)
	if json.Unmarshal(a.body, &test); a.code != 200 || !test.OK || len(test.Projects) != 1 || test.Projects[0].Name != "shop" {
		t.Errorf("a test: %d %s", a.code, a.body)
	}
	a = admin("POST", "sources/test", `{"name":"x","kind":"registry","url":"`+e.srv.URL+`","username":"ci","password":"wrong"}`)
	if json.Unmarshal(a.body, &test); a.code != 200 || test.OK || !strings.Contains(test.Error, "refused") {
		t.Errorf("a wrong password: %d %s", a.code, a.body)
	}
	// Changed without a password, it keeps its own; with an empty one it
	// has none.
	a = admin("PUT", "sources/"+v.ID, `{"name":"Self","kind":"registry","url":"`+e.srv.URL+`","username":"ci"}`)
	if json.Unmarshal(a.body, &v); a.code != 200 || !v.HasSecret {
		t.Errorf("a change: %d %s", a.code, a.body)
	}
	if a := admin("GET", "sources/"+v.ID+"/projects", ""); a.code != 200 || !strings.Contains(string(a.body), `"name":"shop"`) {
		t.Errorf("its projects: %d %s", a.code, a.body)
	}
	for _, bad := range []string{
		`{"name":"Self","kind":"registry","url":"` + e.srv.URL + `"}`,
		`{"name":"","kind":"registry","url":"https://example.org"}`,
		`{"name":"n","kind":"quay","url":"https://example.org"}`,
		`{"name":"n","kind":"nexus","url":"https://example.org"}`,
		`{"name":"n","kind":"registry","url":"example.org"}`,
		`{"name":"n","kind":"registry","url":"https://example.org","ca":"not one"}`,
	} {
		if a := admin("POST", "sources", bad); a.code != 400 && a.code != 409 {
			t.Errorf("%s: %d %s", bad, a.code, a.body)
		}
	}
	if a := admin("GET", "sources", ""); a.code != 200 || strings.Count(string(a.body), `"id"`) != 1 {
		t.Errorf("the sources: %d %s", a.code, a.body)
	}
	// With another key the password cannot be read, and the registry says
	// so.
	other := New(Config{Store: e.reg.cfg.Store, DB: e.db, SourcesKey: SourcesKey("another")})
	src, _ := e.db.Source(v.ID)
	if res := other.TestSource(context.Background(), src); res.OK || !strings.Contains(res.Error, "key changed") {
		t.Errorf("another key: %+v", res)
	}
	clear := admin("PUT", "sources/"+v.ID, `{"name":"Self","kind":"registry","url":"`+e.srv.URL+`","username":"ci","password":""}`)
	if json.Unmarshal(clear.body, &v); clear.code != 200 || v.HasSecret {
		t.Errorf("cleared: %d %s", clear.code, clear.body)
	}
	if a := admin("DELETE", "sources/"+v.ID, ""); a.code != 204 {
		t.Errorf("delete: %d", a.code)
	}
	if a := admin("DELETE", "sources/"+v.ID, ""); a.code != 404 {
		t.Errorf("delete again: %d", a.code)
	}
	if ev := e.db.Events(nil, 0); !hasAction(ev, "source-add") || !hasAction(ev, "source-change") || !hasAction(ev, "source-delete") {
		t.Errorf("the log: %+v", ev)
	}
	// Without a key there are no sources to add.
	e.reg.cfg.SourcesKey = nil
	if a := admin("POST", "sources", `{"name":"n","kind":"registry","url":"https://example.org","password":"p"}`); a.code != 400 || !strings.Contains(string(a.body), "no key") {
		t.Errorf("without a key: %d %s", a.code, a.body)
	}
}

func hasAction(events []meta.Event, action string) bool {
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}
