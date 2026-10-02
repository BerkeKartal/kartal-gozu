package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestCountsPerKindAndNamespace(t *testing.T) {
	st, h := newTestServer()
	st.PutSnapshot("demo", &protocol.Snapshot{
		Namespaces: []protocol.Namespace{{Name: "a", Status: "Active"}, {Name: "b", Status: "Active"}, {Name: "empty"}},
		Workloads: []protocol.Workload{
			{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 2, Ready: 1},
			{Kind: "Deployment", Namespace: "b", Name: "api", Desired: 1, Ready: 1},
			{Kind: "StatefulSet", Namespace: "b", Name: "db", Desired: 1, Ready: 0},
			{Kind: "DaemonSet", Namespace: "a", Name: "agent", Desired: 3, Ready: 3},
		},
		Pods: []protocol.Pod{
			{Namespace: "a", Name: "web-1", Phase: "Running", Ready: 1, Total: 1},
			{Namespace: "a", Name: "web-2", Phase: "Running", Total: 1, Reason: "CrashLoopBackOff"},
			{Namespace: "b", Name: "api-old", Phase: "Failed", Total: 1, Reason: "Evicted", Owner: "Deployment/api"},
		},
		Services:     []protocol.Service{{Namespace: "a", Name: "web"}, {Namespace: "b", Name: "api"}},
		Ingresses:    []protocol.Ingress{{Namespace: "a", Name: "web"}},
		ConfigMaps:   []protocol.ObjectRef{{Namespace: "a", Name: "c1"}, {Namespace: "a", Name: "c2"}},
		Secrets:      []protocol.ObjectRef{{Namespace: "b", Name: "s"}},
		VolumeClaims: []protocol.VolumeClaim{{Namespace: "b", Name: "data", Phase: "Pending"}},
		Jobs:         []protocol.Job{{Namespace: "b", Name: "backup", Completions: 1, Failed: 2, Condition: "Failed"}, {Namespace: "b", Name: "retrying", Completions: 1, Failed: 1, Active: 1}},
		CronJobs:     []protocol.CronJob{{Namespace: "b", Name: "backup"}},
		Events:       []protocol.Event{{Namespace: "a"}, {Namespace: "b"}, {Namespace: "b"}},
	}, time.Now())
	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}

	var sum clusterSummary
	get("/api/v1/clusters/demo", &sum)
	want := objectCounts{
		Workloads: 4, WorkloadsDegraded: 2, Deployments: 2, DeploymentsDegraded: 1, StatefulSets: 1, StatefulSetsDegraded: 1, DaemonSets: 1,
		Pods: 3, PodsUnhealthy: 1, PodsReplaced: 1, Services: 2, Ingresses: 1, ConfigMaps: 2, Secrets: 1, VolumeClaims: 1, VolumeClaimsUnbound: 1,
		Jobs: 2, JobsFailed: 1, CronJobs: 1, Warnings: 3,
	}
	if sum.Counts.objectCounts != want || sum.Counts.Namespaces != 3 {
		t.Errorf("cluster counts:\n got %+v\nwant %+v", sum.Counts, want)
	}

	var ns []namespaceSummary
	get("/api/v1/clusters/demo/namespaces", &ns)
	if len(ns) != 3 {
		t.Fatalf("namespaces: %+v", ns)
	}
	a, b, empty := ns[0], ns[1], ns[2]
	if a.Status != "Active" || a.Deployments != 1 || a.DeploymentsDegraded != 1 || a.DaemonSets != 1 || a.Pods != 2 || a.PodsUnhealthy != 1 ||
		a.ConfigMaps != 2 || a.Ingresses != 1 || a.Warnings != 1 {
		t.Errorf("namespace a: %+v", a)
	}
	if b.StatefulSetsDegraded != 1 || b.Pods != 1 || b.PodsUnhealthy != 0 || b.PodsReplaced != 1 || b.Secrets != 1 || b.VolumeClaimsUnbound != 1 || b.JobsFailed != 1 || b.CronJobs != 1 || b.Warnings != 2 {
		t.Errorf("namespace b: %+v", b)
	}
	if empty.objectCounts != (objectCounts{}) {
		t.Errorf("empty namespace: %+v", empty)
	}
}
