package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/fakekube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func boolp(b bool) *bool { return &b }

func run(t *testing.T, e *Executor, cmd protocol.Command) protocol.Result {
	t.Helper()
	return e.Run(context.Background(), cmd)
}

func TestPreviousContainerLogs(t *testing.T) {
	f, kc := NewFakeKube(t)
	res := run(t, &Executor{Kube: kc}, protocol.Command{Type: protocol.CommandLogs, Namespace: "demo", Name: "api-7c9f-abcde", Previous: true})
	if !res.OK || !strings.Contains(res.Output, "connection refused") || f.LogQuery().Get("previous") != "true" {
		t.Errorf("previous logs: %+v query=%v", res, f.LogQuery())
	}
}

func TestObjectEvents(t *testing.T) {
	_, kc := NewFakeKube(t)
	res := run(t, &Executor{Kube: kc}, protocol.Command{Type: protocol.CommandEvents, Namespace: "demo", Kind: "Pod", Name: "api-7c9f-abcde"})
	var events []protocol.ObjectEvent
	if err := json.Unmarshal([]byte(res.Output), &events); err != nil || !res.OK {
		t.Fatalf("%+v (%v)", res, err)
	}
	if len(events) != 4 || events[0].Reason != "BackOff" || events[0].Type != "Warning" || events[0].Source != "kubelet (worker1)" {
		t.Errorf("events should be newest first, all types included: %+v", events)
	}
	if res := run(t, &Executor{Kube: kc}, protocol.Command{Type: protocol.CommandEvents, Namespace: "demo", Kind: "Pod,x", Name: "a"}); res.OK {
		t.Error("a kind that could change the field selector was accepted")
	}
}

func TestWriteActionsNeedOptIn(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc}
	for _, cmd := range []protocol.Command{
		{Type: protocol.CommandDelete, Namespace: "demo", Kind: "pod", Name: "api-7c9f-abcde"},
		{Type: protocol.CommandCordon, Name: "cp1", Flag: boolp(true)},
		{Type: protocol.CommandSuspend, Namespace: "demo", Name: "backup", Flag: boolp(true)},
		{Type: protocol.CommandTrigger, Namespace: "demo", Name: "backup"},
		{Type: protocol.CommandRollback, Namespace: "demo", Name: "api", Revision: 1},
	} {
		if res := run(t, e, cmd); res.OK || !strings.Contains(res.Error, "disabled") {
			t.Errorf("%s ran without KARTAL_ALLOW_WRITE: %+v", cmd.Type, res)
		}
	}
	if len(f.Patches()) != 0 {
		t.Errorf("changes reached the API server: %+v", f.Patches())
	}
}

func TestDeleteCordonSuspend(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowWrite: true}
	for _, cmd := range []protocol.Command{
		{Type: protocol.CommandDelete, Namespace: "demo", Kind: "pod", Name: "api-7c9f-abcde"},
		{Type: protocol.CommandCordon, Name: "cp1", Flag: boolp(true)},
		{Type: protocol.CommandSuspend, Namespace: "demo", Name: "backup", Flag: boolp(false)},
	} {
		if res := run(t, e, cmd); !res.OK {
			t.Fatalf("%s: %s", cmd.Type, res.Error)
		}
	}
	want := []fakekube.Patch{
		{Method: "DELETE", Path: "/api/v1/namespaces/demo/pods/api-7c9f-abcde"},
		{Method: "PATCH", Path: "/api/v1/nodes/cp1", ContentType: "application/merge-patch+json", Body: `{"spec":{"unschedulable":true}}`},
		{Method: "PATCH", Path: "/apis/batch/v1/namespaces/demo/cronjobs/backup", ContentType: "application/merge-patch+json", Body: `{"spec":{"suspend":false}}`},
	}
	if got := f.Patches(); !reflect.DeepEqual(got, want) {
		t.Errorf("requests:\n got %+v\nwant %+v", got, want)
	}
	if res := run(t, e, protocol.Command{Type: protocol.CommandDelete, Namespace: "demo", Kind: "deployment", Name: "api"}); res.OK {
		t.Error("only pods may be deleted")
	}
	if res := run(t, &Executor{Kube: kc, AllowWrite: true, Namespaces: []string{"demo"}}, protocol.Command{Type: protocol.CommandCordon, Name: "cp1", Flag: boolp(true)}); res.OK {
		t.Error("a namespace-limited agent cordoned a node")
	}
}

func TestTriggerCronJob(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowWrite: true, Now: func() time.Time { return time.Unix(1790000000, 0) }}
	res := run(t, e, protocol.Command{Type: protocol.CommandTrigger, Namespace: "demo", Name: "backup"})
	if !res.OK {
		t.Fatalf("trigger: %s", res.Error)
	}
	p := f.Patches()
	if len(p) != 1 || p[0].Method != "POST" || p[0].Path != "/apis/batch/v1/namespaces/demo/jobs" {
		t.Fatalf("requests: %+v", p)
	}
	var job struct {
		Metadata struct {
			Name            string            `json:"name"`
			Annotations     map[string]string `json:"annotations"`
			OwnerReferences []struct {
				Kind, Name string
			} `json:"ownerReferences"`
		} `json:"metadata"`
	}
	json.Unmarshal([]byte(p[0].Body), &job)
	if !strings.HasPrefix(job.Metadata.Name, "backup-manual-") || job.Metadata.Annotations["cronjob.kubernetes.io/instantiate"] != "manual" ||
		len(job.Metadata.OwnerReferences) != 1 || job.Metadata.OwnerReferences[0].Name != "backup" {
		t.Errorf("job: %s", p[0].Body)
	}
	if !strings.Contains(res.Output, job.Metadata.Name) {
		t.Errorf("message %q does not name the job", res.Output)
	}
}

func TestHistoryAndRollback(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowWrite: true}
	res := run(t, e, protocol.Command{Type: protocol.CommandHistory, Namespace: "demo", Name: "api"})
	var h protocol.History
	if err := json.Unmarshal([]byte(res.Output), &h); err != nil || !res.OK {
		t.Fatalf("%+v (%v)", res, err)
	}
	if h.Current != 2 || len(h.Revisions) != 2 || h.Revisions[0].Revision != 2 || h.Revisions[1].Images[0] != "registry.example.org/demo/api:0f00d1" {
		t.Errorf("history: %+v", h)
	}
	if res := run(t, e, protocol.Command{Type: protocol.CommandRollback, Namespace: "demo", Name: "api", Revision: 2}); res.OK {
		t.Error("rolled back to the current revision")
	}
	if res := run(t, e, protocol.Command{Type: protocol.CommandRollback, Namespace: "demo", Name: "api", Revision: 1}); !res.OK {
		t.Fatalf("rollback: %s", res.Error)
	}
	p := f.Patches()
	if len(p) != 1 || p[0].ContentType != "application/json-patch+json" || !strings.Contains(p[0].Body, "api:0f00d1") || strings.Contains(p[0].Body, "pod-template-hash") {
		t.Fatalf("rollback patch: %+v", p)
	}
	// Like kubectl: the revision's change cause comes back, and the
	// Deployment keeps its own revision bookkeeping.
	var ops []struct {
		Op, Path string
		Value    json.RawMessage
	}
	if err := json.Unmarshal([]byte(p[0].Body), &ops); err != nil || len(ops) != 2 || ops[1].Path != "/metadata/annotations" {
		t.Fatalf("patch operations: %s (%v)", p[0].Body, err)
	}
	var ann map[string]string
	json.Unmarshal(ops[1].Value, &ann)
	if ann["kubernetes.io/change-cause"] != "image 0f00d1" || ann["deployment.kubernetes.io/revision"] != "2" {
		t.Errorf("annotations after the rollback: %v", ann)
	}
}

func TestNamesCannotLeaveTheirPath(t *testing.T) {
	_, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowWrite: true, AllowEdit: true, AllowExec: true}
	for _, cmd := range []protocol.Command{
		{Type: protocol.CommandDelete, Kind: "pod", Namespace: "demo", Name: ".."},
		{Type: protocol.CommandLogs, Namespace: "..", Name: "api-7c9f-abcde"},
		{Type: protocol.CommandGet, Version: "v1", Resource: "pods", Namespace: "demo", Name: "."},
		{Type: protocol.CommandGet, Version: "v1", Resource: "pods", Namespace: "Demo", Name: "x"},
		{Type: protocol.CommandApply, Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "a%2Fb", Body: "x: y"},
		{Type: protocol.CommandEvents, Kind: "Pod", Namespace: "../x", Name: "a"},
	} {
		if res := run(t, e, cmd); res.OK || !strings.Contains(res.Error, "invalid") {
			t.Errorf("%s %q/%q was not refused: %+v", cmd.Type, cmd.Namespace, cmd.Name, res)
		}
	}
}

func TestFieldSelectorValues(t *testing.T) {
	if got := fieldValue(`a,b=c\d`); got != `a\,b\=c\\d` {
		t.Errorf("got %q", got)
	}
}

func TestExec(t *testing.T) {
	_, kc := NewFakeKube(t)
	cmd := protocol.Command{Type: protocol.CommandExec, Namespace: "demo", Name: "api-7c9f-abcde", Exec: []string{"hostname"}}
	if res := run(t, &Executor{Kube: kc, AllowWrite: true}, cmd); res.OK || !strings.Contains(res.Error, "KARTAL_ALLOW_EXEC") {
		t.Errorf("exec ran without KARTAL_ALLOW_EXEC: %+v", res)
	}
	e := &Executor{Kube: kc, AllowExec: true}
	var out protocol.ExecResult
	res := run(t, e, cmd)
	json.Unmarshal([]byte(res.Output), &out)
	if !res.OK || out.Stdout != "api-7c9f-abcde\n" || out.ExitCode != 0 {
		t.Errorf("hostname: %+v %+v", res, out)
	}
	cmd.Exec = []string{"no-such-tool"}
	res = run(t, e, cmd)
	json.Unmarshal([]byte(res.Output), &out)
	if !res.OK || out.ExitCode != 127 || !strings.Contains(out.Stderr, "not found") {
		t.Errorf("failing command: %+v %+v", res, out)
	}
}

func TestApply(t *testing.T) {
	f, kc := NewFakeKube(t)
	cmd := protocol.Command{Type: protocol.CommandApply, Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "app-config", Body: "kind: ConfigMap\n", DryRun: true}
	if res := run(t, &Executor{Kube: kc, AllowWrite: true}, cmd); res.OK || !strings.Contains(res.Error, "KARTAL_ALLOW_EDIT") {
		t.Errorf("edit ran without KARTAL_ALLOW_EDIT: %+v", res)
	}
	e := &Executor{Kube: kc, AllowEdit: true}
	if res := run(t, e, cmd); !res.OK || !strings.Contains(res.Output, "kartal-gozu.io/demo") {
		t.Fatalf("dry run: %+v", res)
	}
	if p := f.Patches(); len(p) != 1 || p[0].Method != "PUT" || p[0].Path != "/api/v1/namespaces/demo/configmaps/app-config?dryRun=All" || p[0].ContentType != "application/yaml" {
		t.Errorf("request: %+v", p)
	}
	cmd.Resource, cmd.Name = "secrets", "db"
	if res := run(t, e, cmd); res.OK || !strings.Contains(res.Error, "secrets cannot be edited") {
		t.Errorf("a Secret was edited: %+v", res)
	}
}

func TestHelmReleases(t *testing.T) {
	_, kc := NewFakeKube(t)
	res := run(t, &Executor{Kube: kc}, protocol.Command{Type: protocol.CommandHelm})
	if !res.OK {
		t.Fatalf("helm: %s", res.Error)
	}
	if strings.Contains(res.Output, fakekube.HelmValue) {
		t.Fatal("a Helm value left the agent")
	}
	var rels []protocol.HelmRelease
	json.Unmarshal([]byte(res.Output), &rels)
	if len(rels) != 2 {
		t.Fatalf("releases: %+v", rels)
	}
	api, traefik := rels[0], rels[1]
	if api.Name != "api" || api.Revision != 3 || api.Status != "failed" || api.Chart != "api" || !strings.Contains(api.Description, "timed out") {
		t.Errorf("api: %+v", api)
	}
	if traefik.Revision != 2 || traefik.Status != "deployed" || traefik.ChartVersion != "32.0.0" || traefik.AppVersion != "v3.3.2" {
		t.Errorf("traefik: %+v", traefik)
	}
}

func TestRequestsAndLimits(t *testing.T) {
	_, kc := NewFakeKube(t)
	snap := (&Collector{Kube: kc}).Collect(context.Background())
	api := snap.Pods[0]
	// The init container asks for more CPU than the app container, so it wins.
	if api.Requests == nil || api.Requests.CPUMilli != 200 || api.Requests.MemoryBytes != 128<<20 ||
		api.Limits == nil || api.Limits.CPUMilli != 500 {
		t.Errorf("pod requests=%+v limits=%+v", api.Requests, api.Limits)
	}
	if w := snap.Nodes[1]; w.Requests == nil || w.Requests.CPUMilli != 200 {
		t.Errorf("worker1 requests: %+v", w.Requests)
	}
	if d := snap.Workloads[0]; d.Usage == nil || d.Usage.CPUMilli != 120 {
		t.Errorf("deployment usage should add up its pods: %+v", d.Usage)
	}
	e := &Executor{AllowWrite: true, AllowEdit: true}
	if got := e.Capabilities(); !reflect.DeepEqual(got, []string{"write", "edit"}) {
		t.Errorf("capabilities: %v", got)
	}
}
