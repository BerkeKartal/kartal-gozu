package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

const (
	regSecret    = "registry-secret-0123456789"
	bossTok      = "boss-token-0123456789"
	clusterTok   = "cluster-admin-token-0123456789"
	regTeamTok   = "team-a-token-0123456789"
	regViewTok   = "team-a-viewer-token-0123456789"
	regLeadTok   = "team-a-lead-token-0123456789"
	registryUser = "operator@registry:team-a"
)

type regEnv struct {
	t      *testing.T
	srv    *Server
	st     *store.Store
	api    *httptest.Server
	public *httptest.Server
	// reg is the registry the server manages.
	reg *registry.Server
}

// newRegEnv starts a server with a registry; opts change the registry's
// Config.
func newRegEnv(t *testing.T, opts ...func(*registry.Config)) *regEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	blobs, _ := blobstore.NewFile(t.TempDir())
	db, err := meta.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keeper := settings.NewKeeper(ctx, settings.Memory{}, log)
	team, _ := auth.ParseGrant(registryUser)
	viewer, _ := auth.ParseGrant("viewer@registry:team-a")
	lead, _ := auth.ParseGrant("admin@registry:team-a")
	cluster, _ := auth.ParseGrant("admin@*/*")
	users := map[string]auth.User{
		bossTok:    {Name: "boss", Role: auth.Admin},
		clusterTok: auth.NewUser("ops", []auth.Grant{cluster}),
		regTeamTok: auth.NewUser("dev", []auth.Grant{team}),
		regViewTok: auth.NewUser("reader", []auth.Grant{viewer}),
		regLeadTok: auth.NewUser("lead", []auth.Grant{lead}),
	}
	accts := accounts.New(keeper, nil)
	e := &regEnv{t: t, st: store.New("demo", "lab")}
	rcfg := registry.Config{Store: blobs, DB: db, Log: log, SourcesKey: registry.SourcesKey(regSecret)}
	for _, o := range opts {
		o(&rcfg)
	}
	reg := registry.New(rcfg)
	e.reg = reg
	adm := httptest.NewServer(reg.Admin(regSecret))
	t.Cleanup(adm.Close)
	srv := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"}, Users: users, StaleAfter: time.Minute, CommandTimeout: time.Second,
		Accounts: accts, RegistryURL: adm.URL, RegistrySecret: regSecret, RegistryPublic: "registry.example.org",
	}, e.st, log)
	e.srv = srv
	e.api = httptest.NewServer(srv)
	t.Cleanup(e.api.Close)
	// The registry asks the server, which is up by now.
	reg2 := registry.New(registry.Config{Store: blobs, DB: db, Log: log, Auth: &registry.ServerAuth{URL: e.api.URL, Secret: regSecret}})
	events := registry.NewForwarder(e.api.URL, regSecret, log)
	db.SetOnEvent(events.Hand)
	go events.Run(ctx)
	e.public = httptest.NewServer(reg2.Public())
	t.Cleanup(e.public.Close)
	return e
}

func (e *regEnv) call(method, path, token, body string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.api.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// token signs in to the registry as docker does.
func (e *regEnv) token(user, password string, scopes ...string) (string, int) {
	q := url.Values{"service": {"kartal-registry"}, "scope": scopes}
	req, _ := http.NewRequest("GET", e.public.URL+"/token?"+q.Encode(), nil)
	req.SetBasicAuth(user, password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	return body.Token, resp.StatusCode
}

func (e *regEnv) v2(method, path, token string, body []byte, contentType string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.public.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestRegistryThroughTheServer(t *testing.T) {
	e := newRegEnv(t)

	// Only the registry's admins make projects.
	if code, _ := e.call("POST", "/api/v1/registry/projects", clusterTok, `{"name":"team-a"}`); code != 403 {
		t.Errorf("a cluster admin made a project: %d", code)
	}
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"team-a"}`); code != 201 {
		t.Fatalf("make a project: %d %s", code, b)
	}
	// A robot account, which only the registry's admins make.
	if code, _ := e.call("POST", "/api/v1/registry/robots", regTeamTok, `{"name":"ci","grants":["operator@registry:team-a"]}`); code != 403 {
		t.Errorf("a project operator made a robot: %d", code)
	}
	code, b := e.call("POST", "/api/v1/registry/robots", bossTok, `{"name":"ci","grants":["operator@registry:team-a"]}`)
	var made struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(b, &made); code != 201 || made.Secret == "" {
		t.Fatalf("make a robot: %d %s", code, b)
	}

	// The robot pushes.
	if _, code := e.token("robot$ci", "kgr_wrong", "repository:team-a/web:push"); code != 401 {
		t.Errorf("a wrong robot secret: %d", code)
	}
	tok, code := e.token("robot$ci", made.Secret, "repository:team-a/web:pull,push")
	if code != 200 {
		t.Fatalf("the robot's token: %d", code)
	}
	cfg := []byte(`{"architecture":"amd64","os":"linux"}`)
	cd := blobstore.Digest(cfg)
	if resp := e.v2("POST", "/v2/team-a/web/blobs/uploads/?digest="+url.QueryEscape(cd), tok, cfg, ""); resp.StatusCode != 201 {
		t.Fatalf("push the config: %d", resp.StatusCode)
	}
	m := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` +
		cd + `","size":` + strconv.Itoa(len(cfg)) + `},"layers":[]}`)
	if resp := e.v2("PUT", "/v2/team-a/web/manifests/1.0", tok, m, "application/vnd.oci.image.manifest.v1+json"); resp.StatusCode != 201 {
		t.Fatalf("push the manifest: %d", resp.StatusCode)
	}
	// A token is good for its owner's name only.
	if _, code := e.token("dev", regTeamTok, "repository:team-a/web:pull"); code != 200 {
		t.Errorf("a token with its owner's name: %d", code)
	}
	if _, code := e.token("boss", regTeamTok, "repository:team-a/web:pull"); code != 401 {
		t.Errorf("a token with someone else's name: %d", code)
	}

	// What people see in the UI.
	if code, b := e.call("GET", "/api/v1/registry/projects", clusterTok, ""); code != 200 || string(bytes.TrimSpace(b)) != "[]" {
		t.Errorf("a cluster admin's projects: %d %s", code, b)
	}
	code, b = e.call("GET", "/api/v1/registry/projects", regTeamTok, "")
	if code != 200 || !strings.Contains(string(b), `"name":"team-a"`) || !strings.Contains(string(b), `"role":"operator"`) {
		t.Errorf("the team's projects: %d %s", code, b)
	}
	if code, b := e.call("GET", "/api/v1/registry/repository?name=team-a/web", regViewTok, ""); code != 200 || !strings.Contains(string(b), `"1.0"`) {
		t.Errorf("a viewer reads the repository: %d %s", code, b)
	}
	digest := blobstore.Digest(m)
	if code, _ := e.call("DELETE", "/api/v1/registry/artifact?repo=team-a/web&digest="+digest, regViewTok, ""); code != 403 {
		t.Errorf("a viewer deleted: %d", code)
	}
	if code, _ := e.call("PUT", "/api/v1/registry/tag?repo=team-a/web&tag=stable", regTeamTok, `{"digest":"`+digest+`"}`); code != 204 {
		t.Errorf("an operator tags: %d", code)
	}
	if code, _ := e.call("PUT", "/api/v1/registry/projects/team-a", regTeamTok, `{"public":true}`); code != 403 {
		t.Errorf("an operator changed the project: %d", code)
	}

	// A role in the registry alone reaches no cluster.
	if code, _ := e.call("GET", "/api/v1/clusters", regTeamTok, ""); code != 403 {
		t.Errorf("a registry operator lists clusters: %d", code)
	}
	code, b = e.call("GET", "/api/v1/me", regTeamTok, "")
	var me struct {
		Role, RegistryRole string
		Registry           bool
	}
	if json.Unmarshal(b, &me); code != 200 || me.Role != "none" || me.RegistryRole != "operator" || !me.Registry {
		t.Errorf("me: %d %s", code, b)
	}

	// The robot's push and the tag are in the audit log, as made in the
	// project.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, b := e.call("GET", "/api/v1/audit", bossTok, "")
		var entries []AuditEntry
		json.Unmarshal(b, &entries)
		var push, tag bool
		for _, en := range entries {
			push = push || (en.Action == "registry-push" && en.User == "robot$ci" && en.Project == "team-a")
			tag = tag || (en.Action == "registry-tag" && en.User == "dev")
		}
		if push && tag {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit: %s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The cluster admin of every cluster does not see the project's log.
	_, b = e.call("GET", "/api/v1/audit", clusterTok, "")
	if strings.Contains(string(b), "registry-push") {
		t.Error("a cluster admin sees the registry's log")
	}
	// The registry asks with the shared secret only.
	if code, _ := e.call("POST", "/api/v1/registry/authorize", "wrong", `{}`); code != 401 {
		t.Errorf("authorize without the secret: %d", code)
	}
}

// A project's admins set its immutable tags; its quota is the registry's
// admins' to give.
func TestRegistryProjectRules(t *testing.T) {
	e := newRegEnv(t)
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"team-a"}`); code != 201 {
		t.Fatalf("make a project: %d %s", code, b)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, `{"immutable":["v*"]}`); code != 200 {
		t.Errorf("the project's admin sets its immutable tags: %d %s", code, b)
	}
	if code, _ := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, `{"quota":1073741824}`); code != 403 {
		t.Errorf("the project's admin set its quota: %d", code)
	}
	if code, _ := e.call("PUT", "/api/v1/registry/projects/team-a", regTeamTok, `{"immutable":[]}`); code != 403 {
		t.Errorf("an operator changed the rules: %d", code)
	}
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", bossTok, `{"quota":1073741824}`); code != 200 {
		t.Errorf("the registry's admin sets the quota: %d %s", code, b)
	}
	code, b := e.call("GET", "/api/v1/registry/projects/team-a", regTeamTok, "")
	var p struct {
		Immutable []string
		Quota     int64
		Public    bool
	}
	if json.Unmarshal(b, &p); code != 200 || len(p.Immutable) != 1 || p.Immutable[0] != "v*" || p.Quota != 1<<30 || p.Public {
		t.Errorf("the project: %d %s", code, b)
	}
}

// The registry's jobs are its admins'.
func TestRegistryJobs(t *testing.T) {
	e := newRegEnv(t)
	if code, _ := e.call("GET", "/api/v1/registry/jobs", regLeadTok, ""); code != 403 {
		t.Errorf("a project's admin lists the jobs: %d", code)
	}
	if code, _ := e.call("POST", "/api/v1/registry/jobs", regLeadTok, `{"kind":"gc"}`); code != 403 {
		t.Errorf("a project's admin starts a job: %d", code)
	}
	code, b := e.call("POST", "/api/v1/registry/jobs", bossTok, `{"kind":"gc","dryRun":true}`)
	var j struct {
		ID, By string
	}
	if json.Unmarshal(b, &j); code != 202 || j.By != "boss" {
		t.Fatalf("start a dry run: %d %s", code, b)
	}
	if code, b := e.call("GET", "/api/v1/registry/jobs/"+j.ID, bossTok, ""); code != 200 || !strings.Contains(string(b), `"kind":"gc"`) {
		t.Errorf("the job: %d %s", code, b)
	}
	if code, b := e.call("PUT", "/api/v1/registry/schedules/verify", bossTok, `{"cron":"0 5 * * 6","enabled":true}`); code != 200 ||
		!strings.Contains(string(b), `"next"`) {
		t.Errorf("a schedule: %d %s", code, b)
	}
	if code, _ := e.call("PUT", "/api/v1/registry/schedules/verify", bossTok, `{"cron":"soon","enabled":true}`); code != 400 {
		t.Errorf("a schedule that cannot be read: %d", code)
	}
	if code, b := e.call("GET", "/api/v1/registry/jobs", bossTok, ""); code != 200 || !strings.Contains(string(b), `"zone":"Europe/Istanbul"`) {
		t.Errorf("the jobs: %d %s", code, b)
	}
}

// The registry hears what runs in the clusters, which retention keeps.
func TestRegistryRunning(t *testing.T) {
	e := newRegEnv(t)
	d := "sha256:" + strings.Repeat("c", 64)
	snap := &protocol.Snapshot{
		Pods: []protocol.Pod{{Name: "web-1", Images: []string{"registry.example.org/team-a/web:1.4", "nginx:1.27"},
			ImageIDs: []string{"docker-pullable://registry.example.org/team-a/web@" + d}}},
		Workloads: []protocol.Workload{{Name: "api", Images: []string{"registry.example.org/team-a/api:2.0"}}},
		CronJobs:  []protocol.CronJob{{Name: "report", Images: []string{"registry.example.org/team-a/report@" + d}}},
	}
	if err := e.st.PutSnapshot("demo", snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.call("GET", "/api/v1/registry/running", bossTok, ""); code != 401 {
		t.Errorf("without the shared secret: %d", code)
	}
	code, b := e.call("GET", "/api/v1/registry/running", regSecret, "")
	var out struct {
		Clusters []registry.ClusterImages
	}
	if json.Unmarshal(b, &out); code != 200 || len(out.Clusters) != 2 {
		t.Fatalf("running: %d %s", code, b)
	}
	demo, lab := out.Clusters[0], out.Clusters[1]
	if !demo.Known || strings.Join(demo.Digests, ",") != d ||
		strings.Join(demo.Refs, ",") != "team-a/api:2.0,team-a/report@"+d+",team-a/web:1.4,team-a/web@"+d {
		t.Errorf("demo: %+v", demo)
	}
	if lab.Known || len(lab.Refs) != 0 {
		t.Errorf("a cluster that said nothing: %+v", lab)
	}
}

// A project's admins set its retention rules and apply them, but only
// theirs.
func TestRegistryProjectRetention(t *testing.T) {
	e := newRegEnv(t)
	for _, p := range []string{"team-a", "team-b"} {
		if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"`+p+`"}`); code != 201 {
			t.Fatalf("make %s: %d %s", p, code, b)
		}
	}
	rules := `{"retention":[{"tags":"**","untagged":true,"keep":"latestPushed","count":5}]}`
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, rules); code != 200 {
		t.Fatalf("the project's admin sets rules: %d %s", code, b)
	}
	if code, _ := e.call("PUT", "/api/v1/registry/projects/team-a", regLeadTok, `{"retention":[{"keep":"always"}]}`); code != 400 {
		t.Errorf("a rule that picks nothing: %d", code)
	}
	code, b := e.call("POST", "/api/v1/registry/jobs", regLeadTok, `{"kind":"retention","project":"team-a","dryRun":true}`)
	var j struct{ ID string }
	if json.Unmarshal(b, &j); code != 202 {
		t.Fatalf("a dry run of the project's rules: %d %s", code, b)
	}
	if code, _ := e.call("GET", "/api/v1/registry/jobs/"+j.ID, regLeadTok, ""); code != 200 {
		t.Errorf("the project's admin reads its job: %d", code)
	}
	if code, _ := e.call("GET", "/api/v1/registry/jobs/"+j.ID, regTeamTok, ""); code != 403 {
		t.Errorf("an operator reads the job: %d", code)
	}
	if code, _ := e.call("POST", "/api/v1/registry/jobs", regLeadTok, `{"kind":"retention","project":"team-b"}`); code != 403 {
		t.Errorf("another project's retention: %d", code)
	}
	if code, _ := e.call("POST", "/api/v1/registry/jobs", regLeadTok, `{"kind":"retention"}`); code != 403 {
		t.Errorf("every project's retention: %d", code)
	}
}

// The registry's problems become alerts, for its admins and, of a
// project, its people.
func TestRegistryAlerts(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	if got := e.srv.registryAlerts(ctx); len(got) != 0 {
		t.Errorf("a sound registry: %+v", got)
	}
	if code, b := e.call("POST", "/api/v1/registry/projects", bossTok, `{"name":"team-a"}`); code != 201 {
		t.Fatalf("make a project: %d %s", code, b)
	}
	tok, _ := e.token("dev", regTeamTok, "repository:team-a/web:pull,push")
	blob := []byte("a layer of team-a")
	if resp := e.v2("POST", "/v2/team-a/web/blobs/uploads/?digest="+url.QueryEscape(blobstore.Digest(blob)), tok, blob, ""); resp.StatusCode != 201 {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	// Full, and with rules that cannot run: the registry is not told what
	// runs in the clusters here.
	body := `{"quota":` + strconv.Itoa(len(blob)) + `,"retention":[{"tags":"**","keep":"latestPushed","count":1}]}`
	if code, b := e.call("PUT", "/api/v1/registry/projects/team-a", bossTok, body); code != 200 {
		t.Fatalf("rules: %d %s", code, b)
	}
	code, b := e.call("POST", "/api/v1/registry/jobs", bossTok, `{"kind":"retention","project":"team-a"}`)
	var j struct{ ID string }
	if json.Unmarshal(b, &j); code != 202 {
		t.Fatalf("retention: %d %s", code, b)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, b := e.call("GET", "/api/v1/registry/jobs/"+j.ID, bossTok, ""); !strings.Contains(string(b), `"status":"running"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the job did not end")
		}
	}
	got := e.srv.registryAlerts(ctx)
	kinds := map[string]alert.Alert{}
	for _, a := range got {
		kinds[a.Kind] = a
	}
	if q := kinds[alert.RegistryQuota]; q.Object != "team-a" || q.Severity != "critical" || !strings.Contains(q.Detail, "(100%)") {
		t.Errorf("the quota: %+v", got)
	}
	if f := kinds[alert.RegistryJobFailed]; f.Object != "retention of team-a" || !strings.Contains(f.Detail, "what runs") {
		t.Errorf("the failed job: %+v", got)
	}
	lead, _ := auth.ParseGrant("admin@registry:team-a")
	ops, _ := auth.ParseGrant("admin@*/*")
	if !alertVisible(auth.NewUser("lead", []auth.Grant{lead}), kinds[alert.RegistryQuota]) ||
		alertVisible(auth.NewUser("lead", []auth.Grant{lead}), kinds[alert.RegistryJobFailed]) ||
		alertVisible(auth.NewUser("ops", []auth.Grant{ops}), kinds[alert.RegistryQuota]) ||
		!alertVisible(auth.User{Name: "boss", Role: auth.Admin}, kinds[alert.RegistryJobFailed]) {
		t.Error("who sees the registry's alerts")
	}
	// Unreachable, it says so, and its other alerts stay as they were.
	m := alert.NewManager(time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.ObserveRegistry(got, time.Now())
	away := New(Config{RegistryURL: "http://127.0.0.1:1", RegistrySecret: regSecret}, store.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	down := away.registryAlerts(ctx)
	if len(down) != 1 || down[0].Kind != alert.RegistryUnreachable {
		t.Fatalf("unreachable: %+v", down)
	}
	m.ObserveRegistry(down, time.Now())
	if n := m.ActiveCount("", func(a alert.Alert) bool { return alert.IsRegistry(a.Kind) }); n != 3 {
		t.Errorf("while unreachable: %d alerts", n)
	}
	m.ObserveRegistry(nil, time.Now())
	if n := m.ActiveCount("", nil); n != 0 {
		t.Errorf("all well again: %d alerts", n)
	}
}

// The sources replication copies from are the registry's admins'; their
// passwords pass through to the registry, never back.
func TestRegistrySources(t *testing.T) {
	e := newRegEnv(t)
	if code, _ := e.call("GET", "/api/v1/registry/sources", regLeadTok, ""); code != 403 {
		t.Errorf("a project's admin lists the sources: %d", code)
	}
	body := `{"name":"Itself","kind":"registry","url":"` + e.public.URL + `","username":"boss","password":"` + bossTok + `"}`
	code, b := e.call("POST", "/api/v1/registry/sources", bossTok, body)
	var src struct {
		ID        string
		HasSecret bool
	}
	if json.Unmarshal(b, &src); code != 201 || !src.HasSecret || strings.Contains(string(b), bossTok) {
		t.Fatalf("add: %d %s", code, b)
	}
	code, b = e.call("POST", "/api/v1/registry/sources/test", bossTok, `{"id":"`+src.ID+`","name":"Itself","kind":"registry","url":"`+e.public.URL+`","username":"boss"}`)
	if code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Errorf("a test: %d %s", code, b)
	}
	if code, b := e.call("GET", "/api/v1/registry/sources/"+src.ID+"/projects", bossTok, ""); code != 200 {
		t.Errorf("its projects: %d %s", code, b)
	}
	if code, _ := e.call("POST", "/api/v1/registry/sources", bossTok, `not json`); code != 400 {
		t.Errorf("a body that is not JSON: %d", code)
	}
	// Moving projects here is the registry's admins'.
	if code, _ := e.call("POST", "/api/v1/registry/sources/"+src.ID+"/migrate", regLeadTok, `{"projects":["team-a"]}`); code != 403 {
		t.Errorf("a project's admin moves projects: %d", code)
	}
	if code, b := e.call("POST", "/api/v1/registry/sources/"+src.ID+"/migrate", bossTok, `{"projects":[]}`); code != 400 {
		t.Errorf("moving nothing: %d %s", code, b)
	}
	if code, _ := e.call("DELETE", "/api/v1/registry/sources/"+src.ID, bossTok, ""); code != 204 {
		t.Errorf("delete: %d", code)
	}
}
