package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/uptime"
)

func TestChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts := alert.NewManager(0, nil)
	m := uptime.New(settings.NewKeeper(ctx, settings.Memory{}, nil), alerts, nil)
	m.Probe = func(_ context.Context, c settings.Check) uptime.Result {
		return uptime.Result{Time: time.Now().UTC(), OK: false, Error: "answered 502 Bad Gateway", Status: 502}
	}
	m.Jitter = func(time.Duration) time.Duration { return 0 }
	m.Start(ctx)
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "demo"},
		Users:       map[string]auth.User{viewerTok: {Name: "ekip", Role: auth.Viewer}},
		AdminToken:  adminTok,
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
		Alerts: alerts, Checks: m,
	}, store.New("demo"), slog.New(slog.NewTextHandler(io.Discard, nil)))

	body := `{"name":"Portal","url":"https://portal.example.org/health","interval":60}`
	if rec := do(s, "POST", "/api/v1/checks", viewerTok, body); rec.Code != 403 {
		t.Errorf("a viewer added a check: %d", rec.Code)
	}
	if rec := do(s, "POST", "/api/v1/checks", adminTok, `{"name":"x","url":"ftp://example.org"}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "not an http") {
		t.Errorf("a bad check: %d %s", rec.Code, rec.Body)
	}
	rec := do(s, "POST", "/api/v1/checks", adminTok, body)
	var c settings.Check
	if json.Unmarshal(rec.Body.Bytes(), &c); rec.Code != 201 || c.ID == "" || c.Timeout != 10 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "POST", "/api/v1/checks/try", adminTok, body); rec.Code != 200 || !strings.Contains(rec.Body.String(), "502 Bad Gateway") {
		t.Errorf("try: %d %s", rec.Code, rec.Body)
	}

	// Everyone sees the checks, and the alert of a failing one, which
	// belongs to no cluster.
	var list struct {
		Checks []uptime.Status `json:"checks"`
	}
	for i := 0; i < 200; i++ {
		json.Unmarshal(do(s, "GET", "/api/v1/checks", viewerTok, "").Body.Bytes(), &list)
		if len(list.Checks) == 1 && list.Checks[0].Last != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(list.Checks) != 1 || list.Checks[0].Last == nil || list.Checks[0].Last.OK {
		t.Fatalf("list: %+v", list)
	}
	var st alert.State
	json.Unmarshal(do(s, "GET", "/api/v1/alerts", viewerTok, "").Body.Bytes(), &st)
	if len(st.Active) != 1 || st.Active[0].Kind != "URLDown" || st.Active[0].Cluster != "" {
		t.Errorf("alerts: %+v", st.Active)
	}

	if rec := do(s, "PUT", "/api/v1/checks/"+c.ID, adminTok, `{"name":"Portal","url":"https://portal.example.org/","interval":120}`); rec.Code != 200 {
		t.Errorf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "PUT", "/api/v1/checks/nope", adminTok, body); rec.Code != 404 {
		t.Errorf("change a missing check: %d", rec.Code)
	}
	if rec := do(s, "DELETE", "/api/v1/checks/"+c.ID, adminTok, ""); rec.Code != 200 {
		t.Errorf("remove: %d %s", rec.Code, rec.Body)
	}
	var audit []AuditEntry
	json.Unmarshal(do(s, "GET", "/api/v1/audit", adminTok, "").Body.Bytes(), &audit)
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action+" "+e.Object)
	}
	if got := strings.Join(actions, ", "); got != "remove-check check/Portal, change-check check/Portal, add-check check/Portal" {
		t.Errorf("audit: %s", got)
	}
}

func TestCertificatesAndVolumes(t *testing.T) {
	viewer, _ := auth.ParseGrant("viewer@prod/team-a")
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		Users:       map[string]auth.User{teamTok: auth.NewUser("takim", []auth.Grant{viewer})},
		AdminToken:  adminTok,
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
	}, store.New("prod"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now()
	snap := protocol.Snapshot{
		Certificates: []protocol.Certificate{
			{Namespace: "team-a", Secret: "web-tls", NotAfter: now.Add(5 * 24 * time.Hour)},
			{Namespace: "team-a", Secret: "fine-tls", NotAfter: now.Add(50 * 24 * time.Hour)},
			{Namespace: "team-b", Secret: "api-tls", NotAfter: now.Add(50 * 24 * time.Hour)},
		},
		VolumeClaims: []protocol.VolumeClaim{
			{Namespace: "team-a", Name: "data", Phase: "Bound", UsedBytes: 90, CapacityBytes: 100},
			{Namespace: "team-a", Name: "logs", Phase: "Bound", UsedBytes: 10, CapacityBytes: 100},
		},
	}
	b, _ := json.Marshal(snap)
	if rec := do(s, "POST", "/agent/v1/report", agentTok, string(b)); rec.Code != 204 {
		t.Fatalf("report: %d", rec.Code)
	}
	names := func(path, token string) string {
		var items []map[string]any
		json.Unmarshal(do(s, "GET", path, token, "").Body.Bytes(), &items)
		var out []string
		for _, it := range items {
			name, _ := it["secret"].(string)
			if name == "" {
				name, _ = it["name"].(string)
			}
			out = append(out, name)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct{ path, token, want string }{
		{"/api/v1/clusters/prod/certificates", adminTok, "web-tls,fine-tls,api-tls"},
		{"/api/v1/clusters/prod/certificates", teamTok, "web-tls,fine-tls"},
		{"/api/v1/clusters/prod/certificates?problems=true", adminTok, "web-tls"},
		{"/api/v1/clusters/prod/volumeclaims?problems=true", adminTok, "data"},
	} {
		if got := names(c.path, c.token); got != c.want {
			t.Errorf("%s: %s, want %s", c.path, got, c.want)
		}
	}
	var sum struct {
		Counts map[string]int `json:"counts"`
	}
	json.Unmarshal(do(s, "GET", "/api/v1/clusters/prod", adminTok, "").Body.Bytes(), &sum)
	if sum.Counts["certificates"] != 3 || sum.Counts["certificatesExpiring"] != 1 || sum.Counts["volumeClaimsFilling"] != 1 {
		t.Errorf("counts: %v", sum.Counts)
	}
	var me map[string]any
	json.Unmarshal(do(s, "GET", "/api/v1/me", teamTok, "").Body.Bytes(), &me)
	if lv, _ := me["levels"].(map[string]any); lv["volumeWarning"] != 85.0 || lv["volumeCritical"] != 95.0 || lv["certificateWarningDays"] != 14.0 || lv["certificateCriticalDays"] != 3.0 ||
		lv["nodeDiskWarning"] != 80.0 || lv["nodeDiskCritical"] != 90.0 {
		t.Errorf("levels: %v", me["levels"])
	}
}

func TestNodeDiskProblems(t *testing.T) {
	s := New(Config{
		AgentTokens: map[string]string{agentTok: "prod"},
		AdminToken:  adminTok,
		StaleAfter:  time.Minute, MaxPollWait: time.Second, CommandTimeout: time.Second,
	}, store.New("prod"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	snap := protocol.Snapshot{Nodes: []protocol.Node{
		{Name: "fine", Ready: true, Disk: &protocol.Disk{UsedBytes: 50, CapacityBytes: 100}},
		{Name: "full", Ready: true, Disk: &protocol.Disk{UsedBytes: 81, CapacityBytes: 100}},
		{Name: "images", Ready: true, Disk: &protocol.Disk{UsedBytes: 10, CapacityBytes: 100}, ImageDisk: &protocol.Disk{UsedBytes: 85, CapacityBytes: 100}},
		{Name: "unknown", Ready: true},
	}}
	b, _ := json.Marshal(snap)
	if rec := do(s, "POST", "/agent/v1/report", agentTok, string(b)); rec.Code != 204 {
		t.Fatalf("report: %d", rec.Code)
	}
	var items []protocol.Node
	json.Unmarshal(do(s, "GET", "/api/v1/clusters/prod/nodes?problems=true", adminTok, "").Body.Bytes(), &items)
	var names []string
	for _, n := range items {
		names = append(names, n.Name)
	}
	if strings.Join(names, ",") != "full,images" {
		t.Errorf("nodes with problems: %v", names)
	}
}
