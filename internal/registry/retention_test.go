package registry

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

func TestImageRef(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	for _, c := range []struct{ ref, local, digest string }{
		{"registry.example.org/team-a/web:1.0", "team-a/web:1.0", ""},
		{"registry.example.org/team-a/web", "team-a/web:latest", ""},
		{"registry.example.org:443/team-a/web:1.0", "team-a/web:1.0", ""},
		{"registry.example.org/team-a/web@" + d, "team-a/web@" + d, d},
		{"registry.example.org/team-a/web:1.0@" + d, "team-a/web@" + d, d},
		{"docker-pullable://registry.example.org/team-a/web@" + d, "team-a/web@" + d, d},
		{"docker.io/library/nginx@" + d, "", d},
		{"nginx:1.27", "", ""},
		{"sha256:" + strings.Repeat("a", 64), "", d},
		{"other.example.org/team-a/web:1.0", "", ""},
		{"registry.example.org/web:1.0", "", ""}, // no project
	} {
		local, digest := ImageRef(c.ref, "https://Registry.example.org")
		if local != c.local || digest != c.digest {
			t.Errorf("%s: %q %q, want %q %q", c.ref, local, digest, c.local, c.digest)
		}
	}
}

func TestValidRetention(t *testing.T) {
	good := []meta.RetentionRule{{Tags: "**", Untagged: true, Keep: KeepLatestPushed, Count: 5}, {Repositories: "charts/*", Tags: "v*", Keep: KeepPushedWithin, Days: 180}}
	if err := ValidRetention(good); err != nil {
		t.Errorf("good rules: %v", err)
	}
	for _, bad := range []meta.RetentionRule{
		{Tags: "**", Keep: "newest", Count: 1},
		{Tags: "**", Keep: KeepLatestPushed},
		{Tags: "**", Keep: KeepPulledWithin, Days: 0},
		{Keep: KeepAlways},
		{Tags: "v[1", Keep: KeepAlways},
		{Repositories: "[", Tags: "**", Keep: KeepAlways},
	} {
		if err := ValidRetention([]meta.RetentionRule{bad}); err == nil {
			t.Errorf("taken: %+v", bad)
		}
	}
}

func info(digest string, pushed time.Time, tags ...string) meta.ArtifactInfo {
	return meta.ArtifactInfo{Artifact: meta.Artifact{Digest: digest, Pushed: pushed}, Tags: append([]string{}, tags...)}
}

func TestRetain(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	day := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	arts := []meta.ArtifactInfo{
		info("d1", day(1), "1.4"), info("d2", day(10), "1.3"), info("d3", day(100), "1.2"), info("d4", day(200), "1.1"),
		info("d5", day(300), "1.0"), info("u1", day(5)), info("u2", day(400)),
	}
	// A signature of d5, and an image an index lists, follow theirs.
	sig := info("s5", day(300))
	sig.Subject = "d5"
	arts = append(arts, sig)
	idx := info("ix", day(50), "multi")
	idx.Manifests = []manifest.Descriptor{{Digest: "c1"}}
	arts = append(arts, idx, info("c1", day(50)))
	// The template: the 5 latest, and what is newer than 180 days.
	rules := []meta.RetentionRule{{Tags: "**", Untagged: true, Keep: KeepLatestPushed, Count: 5},
		{Tags: "**", Untagged: true, Keep: KeepPushedWithin, Days: 180}}
	picked, kept := retain(rules, "web", arts, now)
	var gone []string
	for d := range picked {
		if !kept[d] {
			gone = append(gone, d)
		}
	}
	sort.Strings(gone)
	if strings.Join(gone, ",") != "d4,d5,u2" || picked["s5"] || picked["c1"] || !picked["ix"] {
		t.Errorf("the template: gone %v, picked %v", gone, picked)
	}
	// A rule of other repositories decides nothing here.
	if picked, _ := retain([]meta.RetentionRule{{Repositories: "charts/*", Tags: "**", Keep: KeepAlways}}, "web", arts, now); len(picked) != 0 {
		t.Errorf("another repository's rule: %v", picked)
	}
	// Tags of a pattern only, untagged left alone; pulls decide.
	pulled := now.AddDate(0, 0, -2)
	arts[3].LastPull = &pulled
	picked, kept = retain([]meta.RetentionRule{{Tags: "1.*", Keep: KeepPulledWithin, Days: 7}}, "web", arts, now)
	if picked["u1"] || !picked["d1"] || !kept["d4"] || kept["d1"] {
		t.Errorf("by pulls: picked %v kept %v", picked, kept)
	}
	picked, kept = retain([]meta.RetentionRule{{Tags: "1.*", Keep: KeepLatestPulled, Count: 1}}, "web", arts, now)
	if len(kept) != 1 || !kept["d4"] || len(picked) != 5 {
		t.Errorf("the latest pulled: picked %v kept %v", picked, kept)
	}
}

// images is a made-up kartal-server.
type images struct {
	clusters []ClusterImages
	err      error
}

func (i *images) Running(context.Context) ([]ClusterImages, error) { return i.clusters, i.err }

func TestRetention(t *testing.T) {
	e := newEnv(t)
	src := &images{}
	e.reg.cfg.Running = src
	ci := e.token("ci", "repository:shop/web:pull,push,delete")
	// Five builds, oldest first, a day apart; then a signature of the
	// oldest.
	now := time.Now()
	var digests []string
	for i, tag := range []string{"1.0", "1.1", "1.2", "1.3", "1.4"} {
		at := now.Add(time.Duration(i-5) * 24 * time.Hour)
		e.db.SetClock(func() time.Time { return at })
		d, _ := e.pushImage("shop/web", tag, ci, []string{"amd64", "arm64", "s390x", "ppc64le", "riscv64"}[i])
		digests = append(digests, d)
	}
	e.db.SetClock(time.Now)
	keep2 := []meta.RetentionRule{{Tags: "**", Untagged: true, Keep: KeepLatestPushed, Count: 2}}
	if _, err := e.db.UpdateProject("shop", meta.ProjectChange{Retention: &keep2, Immutable: &[]string{"1.0"}}, "root"); err != nil {
		t.Fatal(err)
	}
	// Without kartal-server's word nothing goes.
	src.err = errors.New("down")
	if _, err := e.reg.Retention(context.Background(), "", false, "root"); err == nil || !strings.Contains(err.Error(), "could not be known") {
		t.Errorf("without the clusters' word: %v", err)
	}
	// 1.1 runs in production; staging runs 1.2 by its tag; lab never said.
	src.err = nil
	src.clusters = []ClusterImages{
		{Name: "production", Known: true, Digests: []string{digests[1]}},
		{Name: "staging", Known: true, Refs: []string{"shop/web:1.2"}},
		{Name: "lab"},
	}
	rep, err := e.reg.Retention(context.Background(), "", true, "root")
	if err != nil || rep.Picked != 5 || rep.Kept != 2 || rep.Protected != 3 || rep.Deleted != 0 || len(rep.Unknown) != 1 {
		t.Errorf("a dry run: %+v %v", rep, err)
	}
	// Staging stops saying anything: it counts as it said last. Production
	// no longer runs 1.1.
	src.clusters = []ClusterImages{{Name: "production", Known: true}, {Name: "staging"}, {Name: "lab"}}
	rep, err = e.reg.Retention(context.Background(), "shop", false, "root")
	if err != nil || rep.Deleted != 1 || rep.Removed[0].Digest != digests[1] || rep.Protected != 2 {
		t.Errorf("retention: %+v %v", rep, err)
	}
	if _, ok := e.db.Artifact("shop/web", digests[1]); ok {
		t.Error("1.1 is still there")
	}
	for _, i := range []int{0, 2, 3, 4} {
		if _, ok := e.db.Artifact("shop/web", digests[i]); !ok {
			t.Errorf("build %d went", i)
		}
	}
	// A cluster gone from kartal-server protects nothing any more.
	src.clusters = []ClusterImages{{Name: "production", Known: true}}
	if rep, _ := e.reg.Retention(context.Background(), "", false, "root"); rep.Deleted != 1 || rep.Removed[0].Digest != digests[2] {
		t.Errorf("after staging went: %+v", rep)
	}
}

func TestRetentionJob(t *testing.T) {
	e := newEnv(t)
	e.reg.cfg.Running = &images{}
	if _, err := e.reg.StartJob(JobRetention, true, "shop", "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a project without rules: %v", err)
	}
	if _, err := e.reg.StartJob(JobGC, false, "shop", "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a collection of a project: %v", err)
	}
	always := []meta.RetentionRule{{Tags: "**", Keep: KeepAlways}}
	e.db.UpdateProject("shop", meta.ProjectChange{Retention: &always}, "root")
	j, err := e.reg.StartJob(JobRetention, true, "shop", "root")
	if err != nil {
		t.Fatal(err)
	}
	if done := e.wait(j.ID); done.Status != meta.JobDone || done.Project != "shop" || !strings.Contains(done.Summary, "would delete 0") {
		t.Errorf("the job: %+v", done)
	}
}
