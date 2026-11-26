package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

func TestRepoMatchAndTarget(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"**", "a/b/c", true}, {"team-a/**", "team-a/web", true}, {"team-a/**", "team-a/apps/web", true},
		{"team-a/**", "team-a", false}, {"team-a/**", "team-b/web", false}, {"team-*/**", "team-b/x", true},
		{"team-a/*", "team-a/web", true}, {"team-a/*", "team-a/apps/web", false}, {"library/nginx", "library/nginx", true},
	} {
		if got := repoMatch(c.pattern, c.name); got != c.want {
			t.Errorf("%s ~ %s: %v", c.pattern, c.name, got)
		}
	}
	r := meta.ReplicationRule{Project: "mirror"}
	if targetRepo(r, "library/nginx") != "mirror/nginx" || targetRepo(r, "team-a/apps/web") != "mirror/apps/web" || targetRepo(r, "nginx") != "mirror/nginx" {
		t.Error("the names here")
	}
	r.KeepPath = true
	if targetRepo(r, "library/nginx") != "mirror/library/nginx" {
		t.Error("the names here, with the path kept")
	}
}

// upstream is a registry to copy from, with images in its project infra.
type upstream struct {
	*env
	amd, arm, index string
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{env: newEnv(t)}
	ci := u.token("ci", "repository:infra/proxy:pull,push", "repository:infra/tools/kit:pull,push")
	u.amd, _ = u.pushImage("infra/proxy", "1.0", ci, "amd64")
	u.arm, _ = u.pushImage("infra/proxy", "1.1", ci, "arm64")
	u.pushImage("infra/tools/kit", "2.0", ci, "riscv64")
	index := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIIndex + `","manifests":[
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + u.amd + `","size":1,"platform":{"architecture":"amd64","os":"linux"}},
		{"mediaType":"` + manifest.OCIManifest + `","digest":"` + u.arm + `","size":1,"platform":{"architecture":"arm64","os":"linux","variant":"v8"}}]}`)
	if a := u.do("PUT", "/v2/infra/proxy/manifests/multi", ci, index, "Content-Type", manifest.OCIIndex); a.code != 201 {
		t.Fatalf("index: %d %s", a.code, a.body)
	}
	u.index = blobstore.Digest(index)
	return u
}

// replicate adds a source and a rule to e, and runs it.
func (e *env) rule(t *testing.T, src string, r meta.ReplicationRule) meta.ReplicationRule {
	t.Helper()
	r.ID, r.Source, r.Since = "r-"+r.Name, src, time.Now()
	if r.Name == "" {
		r.Name = "rule"
	}
	if err := e.reg.checkRule(r); err != nil {
		t.Fatal(err)
	}
	if err := e.db.PutRule(r, "root"); err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) source(t *testing.T, url string) string {
	t.Helper()
	e.reg.cfg.SourcesKey = SourcesKey("k")
	pw := "pw"
	src, err := e.reg.source(SourceInput{Name: "upstream", Kind: "registry", URL: url, Username: "ci", Password: &pw}, meta.Source{ID: "up"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.PutSource(src, "root"); err != nil {
		t.Fatal(err)
	}
	return src.ID
}

func TestReplicate(t *testing.T) {
	up := newUpstream(t)
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	r := e.rule(t, src, meta.ReplicationRule{Name: "infra", Repositories: "infra/**", Project: "shop"})
	ctx := context.Background()
	dry, err := e.reg.Replicate(ctx, r.ID, true, "root", nil)
	if err != nil || dry.Picked != 4 || dry.Copied != 4 || len(dry.Items) != 4 || dry.Items[0].Result != itemWould {
		t.Fatalf("a dry run: %+v %v", dry, err)
	}
	if _, ok := e.db.Artifacts("shop/proxy"); ok {
		t.Error("the dry run copied")
	}
	var progress []meta.JobProgress
	rep, err := e.reg.Replicate(ctx, r.ID, false, "root", func(p meta.JobProgress) { progress = append(progress, p) })
	last := progress[len(progress)-1]
	if err != nil || rep.Copied != 4 || rep.Failed != 0 || rep.Bytes == 0 || progress[0].Done != 0 || progress[0].Total != 4 || last.Done != 4 || last.Bytes != rep.Bytes {
		t.Fatalf("a run: %+v %v %+v", rep, err, progress)
	}
	// What it copied pulls, by the same digests.
	pull := e.token("ci", "repository:shop/proxy:pull", "repository:shop/tools/kit:pull")
	if a := e.do("GET", "/v2/shop/proxy/manifests/multi", pull, nil); a.code != 200 || a.h.Get("Docker-Content-Digest") != up.index {
		t.Errorf("the index: %d %s", a.code, a.h.Get("Docker-Content-Digest"))
	}
	if a := e.do("GET", "/v2/shop/tools/kit/manifests/2.0", pull, nil); a.code != 200 {
		t.Errorf("a deeper repository: %d", a.code)
	}
	var m manifest.Manifest
	json.Unmarshal(e.do("GET", "/v2/shop/proxy/manifests/1.0", pull, nil).body, &m)
	if a := e.do("GET", "/v2/shop/proxy/blobs/"+m.Layers[0].Digest, pull, nil); a.code != 200 || !strings.HasPrefix(string(a.body), "layer of infra/proxy") {
		t.Errorf("a layer: %d %q", a.code, a.body)
	}
	// Again: everything is here.
	again, err := e.reg.Replicate(ctx, r.ID, false, "root", nil)
	if err != nil || again.Present != 4 || again.Copied != 0 || again.Bytes != 0 || len(again.Items) != 0 {
		t.Errorf("again: %+v %v", again, err)
	}
	// The source's 1.0 becomes another image: kept here, unless the rule
	// overwrites, and an immutable tag stays even so.
	ci := up.token("ci", "repository:infra/proxy:pull,push")
	moved, _ := up.pushImage("infra/proxy", "1.0", ci, "s390x")
	kept, _ := e.reg.Replicate(ctx, r.ID, false, "root", nil)
	if kept.Kept != 1 || kept.Items[0].From != "infra/proxy:1.0" {
		t.Errorf("a tag that moved there: %+v", kept)
	}
	v := []string{"1.0"}
	e.db.UpdateProject("shop", meta.ProjectChange{Immutable: &v}, "root")
	r.Overwrite = true
	e.db.PutRule(r, "root")
	if rep, _ := e.reg.Replicate(ctx, r.ID, false, "root", nil); rep.Kept != 1 || !strings.Contains(rep.Items[0].Error, "immutable") {
		t.Errorf("an immutable tag: %+v", rep)
	}
	none := []string{}
	e.db.UpdateProject("shop", meta.ProjectChange{Immutable: &none}, "root")
	if rep, _ := e.reg.Replicate(ctx, r.ID, false, "root", nil); rep.Copied != 1 {
		t.Errorf("overwritten: %+v", rep)
	}
	if d, _ := e.db.Resolve("shop/proxy", "1.0"); d != moved {
		t.Errorf("1.0 here is %s, not %s", d, moved)
	}
}

func TestReplicatePlatformsAndReferrers(t *testing.T) {
	up := newUpstream(t)
	// An SBOM about the arm64 image.
	ci := up.token("ci", "repository:infra/proxy:pull,push")
	empty := up.pushBlob("infra/proxy", ci, []byte("{}"))
	doc := up.pushBlob("infra/proxy", ci, []byte(`{"spdxVersion":"SPDX-2.3"}`))
	sbom := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","artifactType":"application/spdx+json",
		"config":{"mediaType":"` + manifest.OCIEmpty + `","digest":"` + empty + `","size":2},
		"layers":[{"mediaType":"application/spdx+json","digest":"` + doc + `","size":26}],
		"subject":{"mediaType":"` + manifest.OCIManifest + `","digest":"` + up.arm + `","size":1}}`)
	if a := up.do("PUT", "/v2/infra/proxy/manifests/"+blobstore.Digest(sbom), ci, sbom, "Content-Type", manifest.OCIManifest); a.code != 201 {
		t.Fatalf("sbom: %d %s", a.code, a.body)
	}
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	ctx := context.Background()
	// Of the multi-arch image, amd64 alone: a new index, of one image.
	amd := e.rule(t, src, meta.ReplicationRule{Name: "amd", Repositories: "infra/proxy", Tags: "multi", Project: "pub", Platforms: []string{"linux/amd64"}})
	if rep, err := e.reg.Replicate(ctx, amd.ID, false, "root", nil); err != nil || rep.Copied != 1 {
		t.Fatalf("amd64 only: %+v %v", rep, err)
	}
	d, _ := e.db.Resolve("pub/proxy", "multi")
	a, _ := e.db.Artifact("pub/proxy", d)
	if d == up.index || len(a.Manifests) != 1 || a.Manifests[0].Digest != up.amd {
		t.Errorf("the index here: %s %+v", d, a.Manifests)
	}
	if _, ok := e.db.Artifact("pub/proxy", up.arm); ok {
		t.Error("the arm64 image came too")
	}
	// Run again, the narrowed index is here already: not another image,
	// and nothing is written again, even with overwrite.
	events := len(e.db.Events(nil, 0))
	amd.Overwrite = true
	e.db.PutRule(amd, "root")
	events++
	if rep, err := e.reg.Replicate(ctx, amd.ID, false, "root", nil); err != nil || rep.Present != 1 || rep.Copied != 0 || rep.Kept != 0 {
		t.Errorf("amd64 only, again: %+v %v", rep, err)
	}
	// A run that changed nothing writes nothing to the log either.
	if n := len(e.db.Events(nil, 0)); n != events {
		t.Errorf("%d events written by a run that changed nothing", n-events)
	}
	// With the referrers, the SBOM comes along with arm64's 1.1.
	refs := e.rule(t, src, meta.ReplicationRule{Name: "refs", Repositories: "infra/proxy", Tags: "1.1", Project: "shop", Referrers: true,
		Platforms: []string{"linux/arm64/v8"}})
	if rep, err := e.reg.Replicate(ctx, refs.ID, false, "root", nil); err != nil || rep.Copied != 1 || rep.Items[0].Error != "" {
		t.Fatalf("with referrers: %+v %v", rep, err)
	}
	if got := e.db.Referrers("shop/proxy", up.arm, ""); len(got) != 1 || got[0].Kind != "sbom" {
		t.Errorf("the SBOM here: %+v", got)
	}
}

func TestReplicateQuotaAndSourceTrouble(t *testing.T) {
	up := newUpstream(t)
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	tiny := int64(10)
	e.db.UpdateProject("shop", meta.ProjectChange{Quota: &tiny}, "root")
	r := e.rule(t, src, meta.ReplicationRule{Name: "infra", Repositories: "infra/proxy", Tags: "1.0", Project: "shop"})
	rep, err := e.reg.Replicate(context.Background(), r.ID, false, "root", nil)
	if err != nil || rep.Failed != 1 || !strings.Contains(rep.Items[0].Error, "quota") {
		t.Errorf("over the quota: %+v %v", rep, err)
	}
	// The source goes away: the run fails, saying so.
	up.srv.Close()
	if _, err := e.reg.Replicate(context.Background(), r.ID, false, "root", nil); err == nil || !strings.Contains(err.Error(), "listing upstream") {
		t.Errorf("without the source: %v", err)
	}
	// A source a rule copies from stays.
	if err := e.db.DeleteSource(src, "root"); !errors.Is(err, meta.ErrInUse) {
		t.Errorf("deleting a source in use: %v", err)
	}
}

func TestReplicationJobs(t *testing.T) {
	up := newUpstream(t)
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	r := e.rule(t, src, meta.ReplicationRule{Name: "infra", Repositories: "infra/**", Project: "shop", Cron: "0 * * * *", Enabled: true})
	j, err := e.reg.StartReplication(r.ID, false, "root")
	if err != nil {
		t.Fatal(err)
	}
	if done := e.wait(j.ID); done.Status != meta.JobDone || done.RuleName != "infra" || done.Project != "shop" || !strings.Contains(done.Summary, "copied 4") {
		t.Errorf("the job: %+v", done)
	}
	if _, err := e.reg.StartJob(JobReplication, false, "", "root"); !errors.Is(err, ErrJob) {
		t.Errorf("a replication without its rule: %v", err)
	}
	// Its schedule runs it once an hour.
	later := time.Now().Add(61 * time.Minute)
	e.reg.now = func() time.Time { return later }
	before := len(e.db.Jobs(0))
	e.reg.RunDue()
	jobs := e.db.Jobs(0)
	if len(jobs) <= before || jobs[0].Kind != JobReplication || jobs[0].By != ScheduledBy {
		t.Errorf("on its schedule: %+v", jobs)
	}
	e.wait(jobs[0].ID)
	e.reg.now = time.Now
	// A slow run is stopped.
	ci := up.token("ci", "repository:infra/big:pull,push")
	big := make([]byte, 256<<10)
	for i := range big {
		big[i] = byte(i * 7)
	}
	layer := up.pushBlob("infra/big", ci, big)
	cfg := up.pushBlob("infra/big", ci, []byte(`{"architecture":"amd64","os":"linux"}`))
	m := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		cfg + `","size":37},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + layer + `","size":262144}]}`)
	if a := up.do("PUT", "/v2/infra/big/manifests/1", ci, m, "Content-Type", manifest.OCIManifest); a.code != 201 {
		t.Fatalf("big: %d %s", a.code, a.body)
	}
	slow := e.rule(t, src, meta.ReplicationRule{Name: "slow", Repositories: "infra/big", Project: "pub", BandwidthKiB: 1})
	j, err = e.reg.StartReplication(slow.ID, false, "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.StartReplication(slow.ID, false, "root"); !errors.Is(err, ErrRunning) {
		t.Errorf("the same rule twice: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	if got := e.reg.withProgress(func() meta.Job { j, _ := e.db.Job(j.ID); return j }()); got.Progress == nil || got.Progress.Total != 1 || got.Progress.Bytes == 0 {
		t.Errorf("progress: %+v", got.Progress)
	}
	if err := e.reg.CancelJob(j.ID, "ayse"); err != nil {
		t.Fatal(err)
	}
	if done := e.wait(j.ID); done.Status != meta.JobFailed || done.Error != "stopped by ayse" {
		t.Errorf("a stopped job: %+v", done)
	}
	if err := e.reg.CancelJob(j.ID, "ayse"); !errors.Is(err, ErrJob) {
		t.Errorf("stopping a job that ended: %v", err)
	}
}

func TestRulesThroughTheAdminAPI(t *testing.T) {
	up := newUpstream(t)
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	admin := func(method, path, body string) answer {
		return e.do(method, "/admin/v1/"+path, "admin-secret", []byte(body), UserHeader, "ayse")
	}
	a := admin("POST", "rules", `{"name":"Infra","source":"`+src+`","repositories":"infra/**","project":"shop","cron":"30 * * * *","enabled":true}`)
	var v RuleView
	if json.Unmarshal(a.body, &v); a.code != 201 || v.SourceName != "upstream" || v.Next == nil || v.By != "ayse" {
		t.Fatalf("add: %d %s", a.code, a.body)
	}
	for _, bad := range []string{
		`{"name":"x","source":"nope","repositories":"**","project":"shop"}`,
		`{"name":"x","source":"` + src + `","repositories":"","project":"shop"}`,
		`{"name":"x","source":"` + src + `","repositories":"[","project":"shop"}`,
		`{"name":"x","source":"` + src + `","repositories":"**","project":"nowhere"}`,
		`{"name":"x","source":"` + src + `","repositories":"**","project":"shop","platforms":["amd64"]}`,
		`{"name":"x","source":"` + src + `","repositories":"**","project":"shop","cron":"soon"}`,
		`{"name":"x","source":"` + src + `","repositories":"**","project":"shop","concurrency":20}`,
		`{"name":"Infra","source":"` + src + `","repositories":"**","project":"shop"}`,
	} {
		if a := admin("POST", "rules", bad); a.code != 400 && a.code != 409 {
			t.Errorf("%s: %d %s", bad, a.code, a.body)
		}
	}
	a = admin("POST", "jobs", `{"kind":"replication","rule":"`+v.ID+`","dryRun":true}`)
	var j meta.Job
	if json.Unmarshal(a.body, &j); a.code != 202 || j.RuleName != "Infra" {
		t.Fatalf("a dry run: %d %s", a.code, a.body)
	}
	e.wait(j.ID)
	if a := admin("DELETE", "sources/"+src, ""); a.code != 409 {
		t.Errorf("deleting a source in use: %d %s", a.code, a.body)
	}
	if a := admin("PUT", "rules/"+v.ID, `{"name":"Infra","source":"`+src+`","repositories":"infra/proxy","project":"pub"}`); a.code != 200 {
		t.Errorf("a change: %d %s", a.code, a.body)
	}
	if a := admin("DELETE", "rules/"+v.ID, ""); a.code != 204 {
		t.Errorf("delete: %d", a.code)
	}
	if a := admin("DELETE", "sources/"+src, ""); a.code != 204 {
		t.Errorf("deleting the source then: %d %s", a.code, a.body)
	}
}

func TestMigrate(t *testing.T) {
	up := newUpstream(t)
	root := up.token("root", "repository:pub/tools:pull,push")
	up.pushImage("pub/tools", "1", root, "amd64")
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	// Here neither infra nor pub is yet.
	for _, p := range []string{"infra", "pub"} {
		if err := e.db.DeleteProject(p, "root"); err != nil {
			t.Fatal(err)
		}
	}
	out, err := e.reg.Migrate(context.Background(), src, []string{"infra", "pub", "nope"}, true, "ayse")
	if err != nil || len(out) != 3 {
		t.Fatalf("migrate: %+v %v", out, err)
	}
	// A registry of the Distribution API does not tell which projects are
	// public, as Harbor does: they are made private.
	if !out[0].Created || out[0].Public || out[0].Job == "" || !out[1].Created || out[1].Public || out[2].Error == "" {
		t.Errorf("what it did: %+v", out)
	}
	r, _ := e.db.Rule(out[0].Rule)
	if r.Repositories != "infra/**" || r.Project != "infra" || r.Cron != "0 * * * *" || !r.Enabled || !r.Referrers {
		t.Errorf("the rule: %+v", r)
	}
	if done := e.wait(out[0].Job); done.Status != meta.JobDone || !strings.Contains(done.Summary, "copied 4") {
		t.Errorf("the first run: %+v", done)
	}
	if d, ok := e.db.Resolve("infra/proxy", "multi"); !ok || d != up.index {
		t.Errorf("infra/proxy:multi here: %s %v", d, ok)
	}
	e.wait(out[1].Job)
	// Again: the same rule runs again, and nothing more is made.
	rules := len(e.db.Rules())
	again, err := e.reg.Migrate(context.Background(), src, []string{"infra"}, false, "ayse")
	if err != nil || again[0].Created || again[0].Rule != out[0].Rule || len(e.db.Rules()) != rules {
		t.Errorf("again: %+v %v", again, err)
	}
	if done := e.wait(again[0].Job); !strings.Contains(done.Summary, "4 here already") {
		t.Errorf("the second run: %+v", done)
	}
	if _, err := e.reg.Migrate(context.Background(), "nope", []string{"infra"}, false, "ayse"); !errors.Is(err, ErrSource) {
		t.Errorf("an unknown source: %v", err)
	}
}

// A blob the store has and no repository does is garbage a collection may
// be deleting: replication pulls it again rather than link it.
func TestReplicatePullsGarbageAgain(t *testing.T) {
	up := newUpstream(t)
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	ci := up.token("ci", "repository:infra/proxy:pull")
	var m manifest.Manifest
	json.Unmarshal(up.do("GET", "/v2/infra/proxy/manifests/1.0", ci, nil).body, &m)
	layer := up.do("GET", "/v2/infra/proxy/blobs/"+m.Layers[0].Digest, ci, nil).body
	if err := e.reg.cfg.Store.Put(m.Layers[0].Digest, layer); err != nil {
		t.Fatal(err)
	}
	e.age(m.Layers[0].Digest, 3*time.Hour)
	r := e.rule(t, src, meta.ReplicationRule{Name: "one", Repositories: "infra/proxy", Tags: "1.0", Project: "shop"})
	rep, err := e.reg.Replicate(context.Background(), r.ID, false, "root", nil)
	if err != nil || rep.Copied != 1 || rep.Bytes < int64(len(layer)) {
		t.Errorf("a run: %+v %v", rep, err)
	}
	// Pulled again, it is new: a collection now spares it.
	if gc, _ := e.reg.GC(context.Background(), DefaultGrace, false, "root"); gc.Blobs != 0 {
		t.Errorf("collected: %+v", gc)
	}
}

// So many replications run at once; the rest wait their turn.
func TestReplicationsWaitTheirTurn(t *testing.T) {
	up := newUpstream(t)
	ci := up.token("ci", "repository:infra/big:pull,push")
	big := make([]byte, 128<<10)
	for i := range big {
		big[i] = byte(i * 13)
	}
	layer := up.pushBlob("infra/big", ci, big)
	cfg := up.pushBlob("infra/big", ci, []byte(`{"architecture":"amd64","os":"linux"}`))
	m := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.OCIManifest + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		cfg + `","size":37},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + layer + `","size":131072}]}`)
	if a := up.do("PUT", "/v2/infra/big/manifests/1", ci, m, "Content-Type", manifest.OCIManifest); a.code != 201 {
		t.Fatalf("big: %d %s", a.code, a.body)
	}
	e := newEnv(t)
	src := e.source(t, up.srv.URL)
	var ids []string
	for i := 0; i < maxReplications+1; i++ {
		r := e.rule(t, src, meta.ReplicationRule{Name: fmt.Sprintf("slow-%d", i), Repositories: "infra/big", Project: "pub", KeepPath: i > 0, BandwidthKiB: 1})
		j, err := e.reg.StartReplication(r.ID, false, "root")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
	}
	time.Sleep(500 * time.Millisecond)
	waiting := 0
	for _, id := range ids {
		j, _ := e.db.Job(id)
		if p := e.reg.withProgress(j).Progress; p != nil && p.Waiting {
			waiting++
		}
	}
	if waiting != 1 {
		t.Errorf("%d replications wait", waiting)
	}
	for _, id := range ids {
		e.reg.CancelJob(id, "root")
	}
	for _, id := range ids {
		if j := e.wait(id); j.Status != meta.JobFailed {
			t.Errorf("a stopped job: %+v", j)
		}
	}
}
