package api

import (
	"context"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
)

func TestRegistryStores(t *testing.T) {
	e := newRegEnv(t)
	dir := t.TempDir()
	store := `{"name":"archive","kind":"file","path":"` + dir + `","quota":1}`
	for _, tok := range []string{regLeadTok, clusterTok} {
		if code, _ := e.call("POST", "/api/v1/registry/stores", tok, store); code != 403 {
			t.Errorf("%s added a store: %d", tok, code)
		}
	}
	if code, b := e.call("POST", "/api/v1/registry/stores", bossTok, store); code != 201 {
		t.Fatalf("add a store: %d %s", code, b)
	}
	if code, b := e.call("POST", "/api/v1/registry/stores/test", bossTok, `{"name":"scratch","kind":"file","path":"`+dir+`"}`); code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Errorf("test: %d %s", code, b)
	}
	if code, b := e.call("GET", "/api/v1/registry/stores", bossTok, ""); code != 200 || !strings.Contains(string(b), `"name":"archive"`) || !strings.Contains(string(b), `"default":true`) {
		t.Errorf("list: %d %s", code, b)
	}
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"team-a","store":"archive"}`); code != 201 || !strings.Contains(string(b), `"store":"archive"`) {
		t.Fatalf("a project on the store: %d %s", code, b)
	}
	// Where a project is kept is the registry's admins' to say.
	if code, _ := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, `{"store":"default"}`); code != 403 {
		t.Errorf("a project's admin moved it: %d", code)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", bossTok, `{"store":"default"}`); code != 200 {
		t.Errorf("the registry's admin moves an empty project: %d %s", code, b)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", bossTok, `{"store":"archive"}`); code != 200 {
		t.Fatalf("and back: %d %s", code, b)
	}
	// Past its soft quota, an alert; nothing is refused.
	tok, _ := e.token("dev", regTeamTok, "repository:team-a/web:pull,push")
	e.pushTiny("team-a/web", "1.0", tok)
	var full alert.Alert
	for _, a := range e.srv.registryAlerts(context.Background()) {
		if a.Kind == alert.RegistryStoreFull {
			full = a
		}
	}
	if full.Object != "archive" || full.Severity != "critical" {
		t.Errorf("the store's alert: %+v", full)
	}
	if code, _ := e.call("DELETE", "/api/v1/registry/stores/archive", bossTok, ""); code != 409 {
		t.Errorf("deleting a store in use: %d", code)
	}
}
