package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func int32p(v int32) *int32 { return &v }

func TestLogsCommand(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc}

	res := e.Run(context.Background(), protocol.Command{ID: "1", Type: protocol.CommandLogs, Namespace: "demo", Name: "api-7c9f-abcde", Container: "app", TailLines: 100})

	if !res.OK || res.Output != "line1\nline2\n" || res.CommandID != "1" {
		t.Fatalf("result = %+v", res)
	}
	if q := f.LogQuery(); q.Get("tailLines") != "100" || q.Get("container") != "app" || q.Get("timestamps") != "true" {
		t.Errorf("log query = %v", q)
	}
}

func TestWriteCommandsNeedOptIn(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc}

	res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandRestart, Namespace: "demo", Kind: "deployment", Name: "api"})

	if res.OK || !strings.Contains(res.Error, "disabled") {
		t.Fatalf("restart ran without KARTAL_ALLOW_WRITE: %+v", res)
	}
	if len(f.Patches()) != 0 {
		t.Error("a patch reached the API server")
	}
}

func TestRestartPatchesPodTemplate(t *testing.T) {
	f, kc := NewFakeKube(t)
	fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	e := &Executor{Kube: kc, AllowWrite: true, Now: func() time.Time { return fixed }}

	res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandRestart, Namespace: "demo", Kind: "Deployment", Name: "api"})

	if !res.OK {
		t.Fatalf("restart failed: %s", res.Error)
	}
	p := f.Patches()
	if len(p) != 1 {
		t.Fatalf("patches = %+v", p)
	}
	want := `{"spec":{"template":{"metadata":{"annotations":{"kartal-gozu.io/restartedAt":"2026-09-30T12:00:00Z"}}}}}`
	if p[0].Path != "/apis/apps/v1/namespaces/demo/deployments/api" || p[0].ContentType != "application/strategic-merge-patch+json" || p[0].Body != want {
		t.Errorf("patch = %+v", p[0])
	}
}

func TestScaleCommand(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowWrite: true}

	if res := e.Run(context.Background(), protocol.Command{Type: protocol.CommandScale, Namespace: "demo", Kind: "deployment", Name: "api", Replicas: int32p(3)}); !res.OK {
		t.Fatalf("scale failed: %s", res.Error)
	}
	if p := f.Patches(); len(p) != 1 || p[0].ContentType != "application/merge-patch+json" || p[0].Body != `{"spec":{"replicas":3}}` {
		t.Errorf("patch = %+v", p)
	}
}

func TestDiscoverResources(t *testing.T) {
	_, kc := NewFakeKube(t)
	res := (&Executor{Kube: kc}).Run(context.Background(), protocol.Command{Type: protocol.CommandResources})
	if !res.OK {
		t.Fatalf("discovery failed: %s", res.Error)
	}
	var out struct {
		Resources []protocol.APIResource `json:"resources"`
		Errors    []string               `json:"errors"`
	}
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatal(err)
	}
	found := map[string]protocol.APIResource{}
	for _, r := range out.Resources {
		found[r.Group+"/"+r.Resource] = r
	}
	if r, ok := found["traefik.io/ingressroutes"]; !ok || r.Version != "v1alpha1" || !r.Namespaced {
		t.Errorf("CRD missing from discovery: %+v", out.Resources)
	}
	if _, ok := found["apps/deployments"]; !ok {
		t.Error("apps/deployments missing")
	}
	if _, ok := found["/pods/log"]; ok {
		t.Error("subresources must be skipped")
	}
	if _, ok := found["/bindings"]; ok {
		t.Error("types that cannot be listed must be skipped")
	}
	if len(out.Errors) != 1 || !strings.Contains(out.Errors[0], "broken.example.org") {
		t.Errorf("a broken API group should be reported, not fatal: %v", out.Errors)
	}
}

func TestListAnyResource(t *testing.T) {
	_, kc := NewFakeKube(t)
	res := (&Executor{Kube: kc}).Run(context.Background(), protocol.Command{
		Type: protocol.CommandList, Group: "traefik.io", Version: "v1alpha1", Resource: "ingressroutes", Namespace: "demo",
	})
	if !res.OK {
		t.Fatalf("list failed: %s", res.Error)
	}
	var refs []protocol.ObjectRef
	json.Unmarshal([]byte(res.Output), &refs)
	if len(refs) != 2 || refs[0].Name != "admin" || refs[1].Name != "web" {
		t.Errorf("refs = %+v", refs)
	}
}

func TestGetRedactsSecrets(t *testing.T) {
	_, kc := NewFakeKube(t)
	res := (&Executor{Kube: kc}).Run(context.Background(), protocol.Command{
		Type: protocol.CommandGet, Version: "v1", Resource: "secrets", Namespace: "demo", Name: "db",
	})
	if !res.OK {
		t.Fatalf("get failed: %s", res.Error)
	}
	if strings.Contains(res.Output, "c3VwZXItc2VjcmV0") || strings.Contains(res.Output, "last-applied-configuration") {
		t.Fatalf("secret value leaked:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, `"password": "<redacted>"`) || !strings.Contains(res.Output, `"team": "payments"`) {
		t.Errorf("keys and harmless annotations should remain:\n%s", res.Output)
	}
	if strings.Contains(res.Output, "managedFields") {
		t.Error("managedFields should be dropped")
	}
}

func TestGetConfigMapKeepsData(t *testing.T) {
	_, kc := NewFakeKube(t)
	res := (&Executor{Kube: kc}).Run(context.Background(), protocol.Command{
		Type: protocol.CommandGet, Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "app-config",
	})
	if !res.OK || !strings.Contains(res.Output, `"LOG_LEVEL": "debug"`) || strings.Contains(res.Output, "managedFields") {
		t.Errorf("result = %+v", res)
	}
}

func TestCommandsAreValidated(t *testing.T) {
	_, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowWrite: true, Namespaces: []string{"demo"}}
	cases := map[string]protocol.Command{
		"outside scope":           {Type: protocol.CommandLogs, Namespace: "kube-system", Name: "x"},
		"too many":                {Type: protocol.CommandScale, Namespace: "demo", Kind: "deployment", Name: "api", Replicas: int32p(500)},
		"missing replicas":        {Type: protocol.CommandScale, Namespace: "demo", Kind: "deployment", Name: "api"},
		"unknown kind":            {Type: protocol.CommandRestart, Namespace: "demo", Kind: "cronjob", Name: "api"},
		"daemonset scale":         {Type: protocol.CommandScale, Namespace: "demo", Kind: "daemonset", Name: "api", Replicas: int32p(1)},
		"unknown type":            {Type: "delete", Namespace: "demo", Name: "api"},
		"missing name":            {Type: protocol.CommandLogs, Namespace: "demo"},
		"path in group":           {Type: protocol.CommandList, Group: "../../api", Version: "v1", Resource: "secrets", Namespace: "demo"},
		"path in resource":        {Type: protocol.CommandList, Version: "v1", Resource: "pods/log", Namespace: "demo"},
		"bad version":             {Type: protocol.CommandList, Version: "1", Resource: "pods", Namespace: "demo"},
		"cluster-wide restricted": {Type: protocol.CommandList, Version: "v1", Resource: "nodes"},
		"get without name":        {Type: protocol.CommandGet, Version: "v1", Resource: "configmaps", Namespace: "demo"},
	}
	for name, cmd := range cases {
		if res := e.Run(context.Background(), cmd); res.OK || res.Error == "" {
			t.Errorf("%s: expected an error, got %+v", name, res)
		}
	}
}
