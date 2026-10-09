package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestDataSources(t *testing.T) {
	var queries, auths []string
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		auths = append(auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/query_range":
			queries = append(queries, r.Form.Get("query"))
			io.WriteString(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"team-a"},"values":[[60,"2"]]}]}}`)
		case "/api/v1/status/buildinfo":
			if r.Header.Get("Authorization") != "Basic dTpzZWNyZXQ=" { // u:secret
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"status":"error","error":"unauthorized"}`)
				return
			}
			io.WriteString(w, `{"status":"success","data":{"version":"2.53.0"}}`)
		case "/api/v1/labels":
			queries = append(queries, r.Form.Get("match[]"))
			io.WriteString(w, `{"status":"success","data":["__name__","namespace"]}`)
		}
	}))
	defer prom.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keeper := settings.NewKeeper(context.Background(), settings.Memory{}, log)
	grant, _ := auth.ParseGrant("viewer@prod/team-a")
	st := store.New("prod")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users: map[string]auth.User{
			teamTok:   auth.NewUser("takim", []auth.Grant{grant}),
			viewerTok: {Name: "ekip", Role: auth.Viewer},
		},
		AdminToken: adminTok,
		StaleAfter: time.Minute, MaxPollWait: time.Second, CommandTimeout: 2 * time.Second,
		DataSources: datasource.NewManager(keeper),
	}, st, log)
	st.PutSnapshot("prod", &protocol.Snapshot{Namespaces: []protocol.Namespace{{Name: "team-a"}, {Name: "team-b"}}}, time.Now())

	for _, c := range []struct {
		tok, body string
		want      int
	}{
		{viewerTok, `{"name": "p", "type": "prometheus", "url": "` + prom.URL + `"}`, 403},
		{adminTok, `{"name": "p", "type": "prometheus", "url": "prom:9090"}`, 400},
		{adminTok, `{"name": "p", "type": "prometheus", "url": "` + prom.URL + `", "via": "nowhere"}`, 400},
		{adminTok, `{"name": "p", "type": "prometheus", "url": "` + prom.URL + `", "cluster": "prod", "auth": "basic", "username": "u", "password": "secret"}`, 201},
		{adminTok, `{"name": "all", "type": "prometheus", "url": "` + prom.URL + `"}`, 201},
	} {
		if rec := do(s, "POST", "/api/v1/settings/datasources", c.tok, c.body); rec.Code != c.want {
			t.Errorf("%s %s: %d %s", c.tok, c.body, rec.Code, rec.Body)
		}
	}
	rec := do(s, "GET", "/api/v1/settings/datasources", adminTok, "")
	if strings.Contains(rec.Body.String(), "secret") || !strings.Contains(rec.Body.String(), `"passwordSet":true`) {
		t.Fatalf("settings show %s", rec.Body)
	}
	var set struct{ Sources []datasource.View }
	json.Unmarshal(rec.Body.Bytes(), &set)
	id := set.Sources[0].ID
	// A change without the password keeps it: the test still signs in.
	change := `{"name": "Prometheus", "type": "prometheus", "url": "` + prom.URL + `", "cluster": "prod", "auth": "basic", "username": "u"}`
	if rec := do(s, "PUT", "/api/v1/settings/datasources/"+id, adminTok, change); rec.Code != 200 || strings.Contains(rec.Body.String(), "secret") {
		t.Errorf("change: %d %s", rec.Code, rec.Body)
	}
	rec = do(s, "POST", "/api/v1/settings/datasources/test", adminTok, `{"id": "`+id+`", `+change[1:])
	if !strings.Contains(rec.Body.String(), `"version":"Prometheus 2.53.0"`) {
		t.Errorf("test: %s", rec.Body)
	}
	rec = do(s, "POST", "/api/v1/settings/datasources/test", adminTok, change)
	if !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Errorf("a test without the password passed: %s", rec.Body)
	}
	// The saved password does not go to another address.
	moved := strings.Replace(change, prom.URL, "http://elsewhere.example:9090", 1)
	if rec := do(s, "PUT", "/api/v1/settings/datasources/"+id, adminTok, moved); rec.Code != 400 || !strings.Contains(rec.Body.String(), "address changed") {
		t.Errorf("a move keeping the password: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "POST", "/api/v1/settings/datasources/test", adminTok, `{"id": "`+id+`", `+moved[1:]); rec.Code != 400 {
		t.Errorf("a test elsewhere with the saved password: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "GET", "/api/v1/datasources/"+id+"/labels/..%2Fstatus/values", adminTok, ""); rec.Code != 400 {
		t.Errorf("a label name out of the path: %d", rec.Code)
	}

	// The team sees the source tied to its cluster, not the other one.
	var list []Public
	json.Unmarshal(do(s, "GET", "/api/v1/datasources", teamTok, "").Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != id || list[0].Interval != 30 {
		t.Fatalf("the team's sources: %+v", list)
	}
	other := set.Sources[1].ID
	if rec := do(s, "GET", "/api/v1/datasources/"+other+"/query_range?query=up", teamTok, ""); rec.Code != 403 {
		t.Errorf("the team queried a source for everyone: %d", rec.Code)
	}
	// Its queries are kept to its namespace; others' go as written.
	if rec := do(s, "GET", "/api/v1/datasources/"+id+"/query_range?query=sum(up)&start=60000&end=60000&step=1000", teamTok, ""); rec.Code != 200 {
		t.Fatalf("query: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "GET", "/api/v1/datasources/"+id+"/query_range?query=sum(up)&start=60000&end=60000&step=1000", viewerTok, ""); rec.Code != 200 {
		t.Fatalf("query: %d %s", rec.Code, rec.Body)
	}
	if len(queries) != 2 || queries[0] != `sum (up{namespace=~"team-a"})` || queries[1] != "sum(up)" {
		t.Errorf("Prometheus was asked %q", queries)
	}
	do(s, "GET", "/api/v1/datasources/"+id+"/labels", teamTok, "")
	if queries[len(queries)-1] != `{namespace=~"team-a"}` {
		t.Errorf("labels for the team matched %q", queries[len(queries)-1])
	}
	if rec := do(s, "GET", "/api/v1/datasources/"+id+"/query_range?query=rate(x[5m:1m])", teamTok, ""); rec.Code != 400 {
		t.Errorf("a query that cannot be kept to the namespace: %d", rec.Code)
	}
	if rec := do(s, "POST", "/api/v1/datasources/"+id+"/series", viewerTok, `{}`); rec.Code != 400 {
		t.Errorf("an Elasticsearch query to Prometheus: %d", rec.Code)
	}
	if !strings.Contains(strings.Join(auths, ","), "Basic dTpzZWNyZXQ=") {
		t.Errorf("the saved password was not used: %q", auths)
	}
	if rec := do(s, "DELETE", "/api/v1/settings/datasources/"+id, adminTok, ""); rec.Code != 200 {
		t.Errorf("remove: %d", rec.Code)
	}
	if rec := do(s, "GET", "/api/v1/datasources/"+id+"/query_range?query=up", viewerTok, ""); rec.Code != 404 {
		t.Errorf("a removed source answered: %d", rec.Code)
	}
}
