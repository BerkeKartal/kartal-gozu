package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

func TestVersionsPage(t *testing.T) {
	st := store.New("prod", "test")
	alerts := alert.NewManager(0, nil)
	s := New(Config{AgentTokens: map[string]string{agentTok: "prod"}, AdminToken: adminTok, StaleAfter: time.Minute,
		Version: "7804c92", UpdateRepo: "owner/kartal-gozu", VersionLookups: true, Alerts: alerts}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now()
	st.PutSnapshot("prod", &protocol.Snapshot{AgentVersion: "72a9486", KubeVersion: "v1.30.14+k3s1", Nodes: []protocol.Node{
		{Name: "n1", KubeletVersion: "v1.30.14+k3s1"}, {Name: "n2", KubeletVersion: "v1.30.13+k3s1"}, {Name: "n3", KubeletVersion: "v1.30.14+k3s1"}}}, now)
	st.PutSnapshot("test", &protocol.Snapshot{AgentVersion: "7804c92-dirty", KubeVersion: "v1.33.11"}, now)

	var page struct {
		Server struct {
			Version, Repo string
			Lookups       bool
		}
		Clusters []clusterVersions
	}
	rec := do(s, "GET", "/api/v1/versions", adminTok, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || page.Server.Version != "7804c92" || page.Server.Repo != "owner/kartal-gozu" || !page.Server.Lookups {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(page.Clusters) != 2 || page.Clusters[0].Name != "prod" || !page.Clusters[0].AgentDiffers || page.Clusters[1].AgentDiffers {
		t.Fatalf("clusters: %+v", page.Clusters)
	}
	k := page.Clusters[0].Kubernetes
	if len(k) != 2 || k[0].Upstream != "1.30.14" || !k[0].APIServer || strings.Join(k[0].Nodes, ",") != "n1,n3" ||
		k[1].Version != "v1.30.13+k3s1" || k[1].APIServer || strings.Join(k[1].Nodes, ",") != "n2" {
		t.Errorf("kubernetes: %+v", k)
	}
	var list []clusterSummary
	json.Unmarshal(do(s, "GET", "/api/v1/clusters", adminTok, "").Body.Bytes(), &list)
	if len(list) != 2 || !list[0].AgentDiffers || list[1].AgentDiffers {
		t.Errorf("summaries: %+v", list)
	}

	// The page may ask the two services, and only them.
	csp := do(s, "GET", "/", "", "").Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'self' https://api.github.com https://api.osv.dev;") {
		t.Errorf("policy: %s", csp)
	}
	quiet := New(Config{AgentTokens: map[string]string{agentTok: "prod"}, AdminToken: adminTok}, store.New("prod"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if csp := do(quiet, "GET", "/", "", "").Header().Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self';") {
		t.Errorf("policy without lookups: %s", csp)
	}

	// An agent of another version is an alert after a while.
	ci, _ := st.Cluster("prod")
	active := func() int {
		return alerts.ActiveCount("prod", func(a alert.Alert) bool { return a.Kind == alert.AgentVersion })
	}
	s.watchVersions(ci, now)
	if active() != 0 {
		t.Error("alert before the grace")
	}
	s.watchVersions(ci, now.Add(agentVersionGrace))
	if active() != 1 {
		t.Error("no alert after the grace")
	}
	// A restart forgets since when the versions differ. The alert kept from
	// before stays while the grace starts over: neither resolved nor raised.
	s.agentSince = map[string]time.Time{}
	s.watchVersions(ci, now.Add(agentVersionGrace+time.Second))
	if active() != 1 {
		t.Error("resolved while the grace started over")
	}
	st.PutSnapshot("prod", &protocol.Snapshot{AgentVersion: "7804c92"}, now)
	ci, _ = st.Cluster("prod")
	s.watchVersions(ci, now.Add(agentVersionGrace+time.Minute))
	if active() != 0 || len(s.agentSince) != 0 {
		t.Error("not resolved")
	}
}
