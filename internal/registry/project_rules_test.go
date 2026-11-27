package registry

import (
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// A project a replication rule copies into is not deleted: the rule would
// fail every time it ran.
func TestAProjectARuleCopiesInto(t *testing.T) {
	up := newUpstream(t)
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	if err := e.db.CreateProject(meta.Project{Name: "mirror"}, "root"); err != nil {
		t.Fatal(err)
	}
	r := e.rule(t, src, meta.ReplicationRule{Name: "proxy", Repositories: "infra/proxy", Project: "mirror"})
	a := e.do("DELETE", "/admin/v1/projects/mirror", "admin-secret", nil)
	if a.code != 409 || !strings.Contains(string(a.body), "proxy") {
		t.Fatalf("deleting a project a rule copies into: %d %s", a.code, a.body)
	}
	if err := e.db.DeleteRule(r.ID, "root"); err != nil {
		t.Fatal(err)
	}
	if a := e.do("DELETE", "/admin/v1/projects/mirror", "admin-secret", nil); a.code != 204 {
		t.Fatalf("once the rule is gone: %d %s", a.code, a.body)
	}
}
