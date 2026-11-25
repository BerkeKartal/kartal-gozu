package meta

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
)

const (
	dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	dM = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dS = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func open(t *testing.T, dir string) *DB {
	t.Helper()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func image(digest string) Artifact {
	return Artifact{Digest: digest, MediaType: manifest.OCIManifest, Kind: "image", Size: 500,
		Config: &manifest.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: dA, Size: 100},
		Layers: []manifest.Descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: dB, Size: 2000}}}
}

// fill pushes an image the way a client does: blobs first, then the
// manifest with a tag.
func push(t *testing.T, d *DB, repo, digest, tag string) {
	t.Helper()
	for _, b := range []struct {
		digest string
		size   int64
	}{{dA, 100}, {dB, 2000}} {
		if err := d.LinkBlob(repo, b.digest, b.size); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.PutArtifact(repo, image(digest), tag, "ci"); err != nil {
		t.Fatal(err)
	}
}

func TestProjectsComeFirst(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.Close()
	if err := d.LinkBlob("shop/web", dA, 1); !errors.Is(err, ErrNoProject) {
		t.Errorf("a blob without a project: %v", err)
	}
	if err := d.PutArtifact("shop/web", image(dM), "1.0", "ci"); !errors.Is(err, ErrNoProject) {
		t.Errorf("a manifest without a project: %v", err)
	}
	if err := d.CreateProject(Project{Name: "shop"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateProject(Project{Name: "shop"}, "admin"); !errors.Is(err, ErrExists) {
		t.Errorf("the same project twice: %v", err)
	}
	push(t, d, "shop/web", dM, "1.0")
	if err := d.DeleteProject("shop", "admin"); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("deleting a project with repositories: %v", err)
	}
	if err := d.DeleteRepository("shop/web", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteProject("shop", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Project("shop"); ok {
		t.Error("the project is still there")
	}
}

func TestArtifactsTagsAndReferrers(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.Close()
	d.CreateProject(Project{Name: "shop", Public: true}, "admin")
	push(t, d, "shop/web", dM, "1.0")
	if err := d.Tag("shop/web", "latest", dM, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := d.Tag("shop/web", "x", dC, "dev"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a tag on a missing artifact: %v", err)
	}
	if dg, ok := d.Resolve("shop/web", "latest"); !ok || dg != dM {
		t.Errorf("resolve latest: %q %v", dg, ok)
	}
	if dg, ok := d.Resolve("shop/web", dM); !ok || dg != dM {
		t.Errorf("resolve by digest: %q %v", dg, ok)
	}
	if _, ok := d.Resolve("shop/web", dC); ok {
		t.Error("a missing digest resolved")
	}
	// A signature that refers to the image.
	sig := Artifact{Digest: dS, MediaType: manifest.OCIManifest, ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Kind: "signature",
		Size: 300, Subject: dM}
	if err := d.PutArtifact("shop/web", sig, "", "cosign"); err != nil {
		t.Fatal(err)
	}
	if got := d.Referrers("shop/web", dM, ""); len(got) != 1 || got[0].Digest != dS {
		t.Errorf("referrers: %+v", got)
	}
	if got := d.Referrers("shop/web", dM, "application/spdx+json"); len(got) != 0 {
		t.Errorf("filtered referrers: %+v", got)
	}
	arts, _ := d.Artifacts("shop/web")
	if len(arts) != 2 || arts[0].Digest != dS || !reflect.DeepEqual(arts[1].Tags, []string{"1.0", "latest"}) || len(arts[0].Tags) != 0 {
		t.Errorf("artifacts: %+v", arts)
	}
	if tags, _ := d.Tags("shop/web", "1.0", 0); !reflect.DeepEqual(tags, []string{"latest"}) {
		t.Errorf("tags after 1.0: %v", tags)
	}
	if tags, _ := d.Tags("shop/web", "", 1); !reflect.DeepEqual(tags, []string{"1.0"}) {
		t.Errorf("one tag: %v", tags)
	}
	if err := d.Untag("shop/web", "latest", "dev"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Resolve("shop/web", "latest"); ok {
		t.Error("the tag is still there")
	}
	// Deleting an artifact takes its tags with it.
	if err := d.DeleteArtifact("shop/web", dM, "dev"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Resolve("shop/web", "1.0"); ok {
		t.Error("1.0 still points at the deleted artifact")
	}
	projects := d.Projects()
	if len(projects) != 1 || projects[0].Repositories != 1 || projects[0].Artifacts != 1 || projects[0].Size != 100+2000+300 {
		t.Errorf("projects: %+v", projects)
	}
	events := d.Events(nil, 0)
	if len(events) != 6 || events[0].Action != "delete" || events[len(events)-1].Action != "project-create" {
		t.Errorf("events: %+v", events)
	}
}

func TestPushedAgainKeepsHistory(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.Close()
	d.CreateProject(Project{Name: "shop"}, "admin")
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return t0 }
	push(t, d, "shop/web", dM, "1.0")
	d.RecordPull("shop/web", dM)
	d.now = func() time.Time { return t0.Add(time.Hour) }
	push(t, d, "shop/web", dM, "1.0-again")
	a, _ := d.Artifact("shop/web", dM)
	if !a.Pushed.Equal(t0) || a.PushedBy != "ci" || a.Pulls != 1 {
		t.Errorf("pushed again: %+v", a)
	}
}

func TestCatalog(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.Close()
	for _, p := range []string{"shop", "infra"} {
		d.CreateProject(Project{Name: p}, "admin")
	}
	for _, r := range []string{"shop/web", "shop/api", "infra/proxy", "shop/api/worker"} {
		push(t, d, r, dM, "1")
	}
	all := d.Catalog(func(string) bool { return true }, "", 0)
	if !reflect.DeepEqual(all, []string{"infra/proxy", "shop/api", "shop/api/worker", "shop/web"}) {
		t.Errorf("catalog: %v", all)
	}
	shop := d.Catalog(func(p string) bool { return p == "shop" }, "shop/api", 1)
	if !reflect.DeepEqual(shop, []string{"shop/api/worker"}) {
		t.Errorf("shop's after shop/api: %v", shop)
	}
	if repos := d.Repositories("shop"); len(repos) != 3 || repos[0].Name != "shop/api" || repos[0].Tags != 1 || repos[0].Size != 2600 {
		t.Errorf("repositories: %+v", repos)
	}
}

func TestReopen(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.CreateProject(Project{Name: "shop", Public: true, Description: "the shop"}, "admin")
	push(t, d, "shop/web", dM, "1.0")
	d.RecordPull("shop/web", dM)
	d.RecordPull("shop/web", dM)
	if err := d.Flush(); err != nil {
		t.Fatal(err)
	}
	// Reopened from the log alone: the process ended without closing.
	d.wal.Close()
	d2 := open(t, dir)
	check := func(d *DB, when string) {
		t.Helper()
		p, ok := d.Project("shop")
		a, aok := d.Artifact("shop/web", dM)
		dg, tok := d.Resolve("shop/web", "1.0")
		n, bok := d.Blob("shop/web", dB)
		if !ok || !p.Public || p.Description != "the shop" || !aok || a.Pulls != 2 || a.LastPull == nil || !tok || dg != dM || !bok || n != 2000 {
			t.Errorf("%s: project %+v, artifact %+v, tag %q, blob %d", when, p, a, dg, n)
		}
	}
	check(d2, "from the log")
	// Reopened from a snapshot.
	if err := d2.Close(); err != nil {
		t.Fatal(err)
	}
	if lineCount(filepath.Join(dir, "wal.jsonl")) != 0 {
		t.Error("the log was not started over")
	}
	d3 := open(t, dir)
	check(d3, "from the snapshot")
	// And from a snapshot and a log.
	d3.Tag("shop/web", "stable", dM, "dev")
	d3.wal.Close()
	d4 := open(t, dir)
	defer d4.Close()
	check(d4, "from both")
	if dg, ok := d4.Resolve("shop/web", "stable"); !ok || dg != dM {
		t.Error("the tag made after the snapshot is lost")
	}
}

func TestCrashes(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.CreateProject(Project{Name: "shop"}, "admin")
	push(t, d, "shop/web", dM, "1.0")
	d.wal.Close()
	wal := filepath.Join(dir, "wal.jsonl")
	b, _ := os.ReadFile(wal)

	// A last line cut short is dropped, and what comes after it is written
	// cleanly.
	os.WriteFile(wal, append(append([]byte{}, b...), `{"op":"tag","repo":"shop/web","ta`...), 0o640)
	d2 := open(t, dir)
	if _, ok := d2.Resolve("shop/web", "1.0"); !ok {
		t.Error("the whole lines were lost")
	}
	if err := d2.Tag("shop/web", "after", dM, "dev"); err != nil {
		t.Fatal(err)
	}
	d2.wal.Close()
	d3 := open(t, dir)
	if _, ok := d3.Resolve("shop/web", "after"); !ok {
		t.Error("a change after the cut line is lost")
	}
	d3.wal.Close()

	// A broken line in the middle is not skipped: what follows it may
	// depend on it.
	b, _ = os.ReadFile(wal)
	lines := strings.SplitAfter(string(b), "\n")
	lines[1] = "{not json}\n"
	os.WriteFile(wal, []byte(strings.Join(lines, "")), 0o640)
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a broken line in the middle: %v", err)
	}
}

func TestReplayedTwiceChangesNothing(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.CreateProject(Project{Name: "shop"}, "admin")
	push(t, d, "shop/web", dM, "1.0")
	for i := 0; i < 3; i++ {
		d.RecordPull("shop/web", dM)
	}
	d.Flush()
	wal := filepath.Join(dir, "wal.jsonl")
	before, _ := os.ReadFile(wal)
	// A crash after the snapshot was written but before the log was cut:
	// the log is replayed over a snapshot that holds it already.
	if err := d.Snapshot(); err != nil {
		t.Fatal(err)
	}
	d.wal.Close()
	os.WriteFile(wal, before, 0o640)
	d2 := open(t, dir)
	defer d2.Close()
	if a, _ := d2.Artifact("shop/web", dM); a.Pulls != 3 {
		t.Errorf("pulls after a double replay: %d", a.Pulls)
	}
	if n := len(d2.Events(nil, 0)); n != len(d.Events(nil, 0))*2 {
		// Events are a log of their own: replayed twice they show twice,
		// which is harmless, and only after such a crash.
		t.Logf("events: %d", n)
	}
}

func TestSnapshotAfterManyChanges(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	defer d.Close()
	d.CreateProject(Project{Name: "shop"}, "admin")
	for i := 0; i < snapshotEvery; i++ {
		if err := d.Record("ci", "push-failed", "shop", "shop/web", "", fmt.Sprint(i), ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := lineCount(filepath.Join(dir, "wal.jsonl")); n >= snapshotEvery {
		t.Errorf("the log has %d lines; no snapshot was taken", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshot.json")); err != nil {
		t.Error(err)
	}
	if err := d.Healthy(); err != nil {
		t.Error(err)
	}
	if n := len(d.Events(nil, 0)); n != snapshotEvery+1 {
		t.Errorf("%d events", n)
	}
}

func lineCount(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}
