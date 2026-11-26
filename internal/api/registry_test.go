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
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
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
	api    *httptest.Server
	public *httptest.Server
}

func newRegEnv(t *testing.T) *regEnv {
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
	e := &regEnv{t: t}
	reg := registry.New(registry.Config{Store: blobs, DB: db, Log: log})
	adm := httptest.NewServer(reg.Admin(regSecret))
	t.Cleanup(adm.Close)
	srv := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"}, Users: users, StaleAfter: time.Minute, CommandTimeout: time.Second,
		Accounts: accts, RegistryURL: adm.URL, RegistrySecret: regSecret, RegistryPublic: "registry.example.org",
	}, store.New("demo"), log)
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
