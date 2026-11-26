package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// Migrating again runs the same rule again: also when another source has a
// rule by the name, when a name is so long it is cut, and when the list
// names a project twice.
func TestMigrateAgain(t *testing.T) {
	up := newUpstream(t)
	long := strings.Repeat("a", 55)
	for _, p := range []string{long + "-one", long + "-two"} {
		if err := up.env.db.CreateProject(meta.Project{Name: p, Public: true}, "root"); err != nil {
			t.Fatal(err)
		}
		up.pushImage(p+"/app", "1", up.token("root", "repository:"+p+"/app:pull,push"), "amd64")
	}
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	pw := "pw"
	other, err := e.reg.source(SourceInput{Name: "elsewhere", Kind: "registry", URL: up.srv.URL, Username: "ci", Password: &pw}, meta.Source{ID: "else"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.PutSource(other, "root"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.PutRule(meta.ReplicationRule{ID: "r-else", Name: "Migration of infra", Source: other.ID, Repositories: "infra/**", Tags: "**", Project: "infra"}, "root"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	names := []string{"infra", long + "-one", long + "-two", "infra"}
	first, err := e.reg.Migrate(ctx, src, names, false, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range first {
		if m.Job != "" {
			e.wait(m.Job)
		}
	}
	if len(first) != 3 {
		t.Fatalf("a project named twice is moved once: %+v", first)
	}
	for _, m := range first {
		r, ok := e.db.Rule(m.Rule)
		if m.Error != "" || !ok || r.Source != src || r.Project != m.Project || r.Repositories != m.Project+"/**" {
			t.Errorf("%s: %+v, its rule %+v", m.Project, m, r)
		}
	}
	rules := len(e.db.Rules())
	again, err := e.reg.Migrate(ctx, src, names, false, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range again {
		if m.Job != "" {
			e.wait(m.Job)
		}
		if i < len(first) && (m.Error != "" || m.Rule != first[i].Rule) {
			t.Errorf("again %s: %+v, first %+v", m.Project, m, first[i])
		}
	}
	if len(e.db.Rules()) != rules {
		t.Errorf("again made rules: %d, were %d", len(e.db.Rules()), rules)
	}
}
