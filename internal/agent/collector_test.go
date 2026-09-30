package agent

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestCollectWholeCluster(t *testing.T) {
	_, kc := NewFakeKube(t)
	c := &Collector{Kube: kc, Version: "test", MaxEvents: 10, IncludeSecrets: true}

	snap := c.Collect(context.Background())

	if len(snap.Errors) != 0 {
		t.Fatalf("unexpected collection errors: %v", snap.Errors)
	}
	if snap.KubeVersion != "v1.30.14" || !snap.MetricsAvailable {
		t.Errorf("version=%q metrics=%v", snap.KubeVersion, snap.MetricsAvailable)
	}
	if len(snap.Namespaces) != 2 {
		t.Errorf("namespaces = %v", snap.Namespaces)
	}

	// Nodes: roles, readiness, pressure, taints, capacity, usage, pod count.
	if len(snap.Nodes) != 2 {
		t.Fatalf("nodes = %+v", snap.Nodes)
	}
	cp, worker := snap.Nodes[0], snap.Nodes[1]
	if !cp.Ready || !reflect.DeepEqual(cp.Roles, []string{"control-plane"}) || cp.InternalIP != "10.0.0.1" ||
		cp.Allocatable.CPUMilli != 3800 || cp.Allocatable.MemoryBytes != 7<<30 || cp.Capacity.Pods != 110 ||
		cp.Usage == nil || cp.Usage.CPUMilli != 250 || cp.PodCount != 1 ||
		!reflect.DeepEqual(cp.Taints, []string{"node-role.kubernetes.io/control-plane:NoSchedule"}) {
		t.Errorf("control-plane node: %+v", cp)
	}
	if worker.Ready || !reflect.DeepEqual(worker.Pressure, []string{"MemoryPressure"}) || worker.Usage != nil || worker.PodCount != 1 {
		t.Errorf("worker node: %+v", worker)
	}

	if len(snap.Pods) != 2 {
		t.Fatalf("expected both pagination pages, got %d pods", len(snap.Pods))
	}
	api := snap.Pods[0]
	if api.Name != "api-7c9f-abcde" || api.Owner != "Deployment/api" {
		t.Errorf("pod owner not resolved to deployment: %+v", api)
	}
	if api.Reason != "CrashLoopBackOff" || api.Restarts != 5 || api.Ready != 0 || api.Total != 1 || api.Healthy() {
		t.Errorf("pod status not summarised: %+v", api)
	}
	if api.Usage == nil || api.Usage.CPUMilli != 120 || api.Usage.MemoryBytes != 80<<20 {
		t.Errorf("pod usage should sum its containers: %+v", api.Usage)
	}
	if exporter := snap.Pods[1]; !exporter.Healthy() || exporter.Owner != "DaemonSet/node-exporter" {
		t.Errorf("exporter pod: %+v", exporter)
	}

	if len(snap.Workloads) != 2 || snap.Workloads[0].Kind != "Deployment" || !snap.Workloads[0].Degraded() {
		t.Errorf("workloads = %+v", snap.Workloads)
	}

	wantPorts := []protocol.ServicePort{
		{Name: "http", Port: 80, TargetPort: "http", Protocol: "TCP"},
		{Name: "https", Port: 443, TargetPort: "8443", Protocol: "TCP"},
	}
	if len(snap.Services) != 1 || !reflect.DeepEqual(snap.Services[0].Ports, wantPorts) {
		t.Errorf("services = %+v", snap.Services)
	}
	if len(snap.Ingresses) != 1 || !snap.Ingresses[0].TLS || snap.Ingresses[0].Class != "traefik" ||
		!reflect.DeepEqual(snap.Ingresses[0].Rules, []protocol.IngressRule{{Host: "demo.example.org", Path: "/", Backend: "api:80"}}) {
		t.Errorf("ingresses = %+v", snap.Ingresses)
	}
	if len(snap.ConfigMaps) != 1 || snap.ConfigMaps[0].Name != "app-config" {
		t.Errorf("configmaps = %+v", snap.ConfigMaps)
	}
	if len(snap.Secrets) != 1 || snap.Secrets[0].Name != "db" {
		t.Errorf("secrets = %+v", snap.Secrets)
	}
	if len(snap.VolumeClaims) != 1 || snap.VolumeClaims[0].Capacity != "10Gi" || snap.VolumeClaims[0].StorageClass != "local" {
		t.Errorf("volume claims = %+v", snap.VolumeClaims)
	}
	if len(snap.Jobs) != 1 || snap.Jobs[0].Owner != "CronJob/backup" || snap.Jobs[0].Succeeded != 1 {
		t.Errorf("jobs = %+v", snap.Jobs)
	}
	if len(snap.CronJobs) != 1 || snap.CronJobs[0].Schedule != "0 3 * * *" || snap.CronJobs[0].Suspended {
		t.Errorf("cronjobs = %+v", snap.CronJobs)
	}
	if len(snap.Events) != 1 || snap.Events[0].Count != 12 || !snap.Events[0].LastSeen.Equal(time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("events: %+v", snap.Events)
	}
}

func TestSecretsAreOptIn(t *testing.T) {
	_, kc := NewFakeKube(t)
	snap := (&Collector{Kube: kc}).Collect(context.Background())
	if len(snap.Secrets) != 0 {
		t.Errorf("secret names collected without opt-in: %+v", snap.Secrets)
	}
}

func TestCollectOnlyWatchedNamespaces(t *testing.T) {
	_, kc := NewFakeKube(t)
	c := &Collector{Kube: kc, Namespaces: []string{"demo"}}

	snap := c.Collect(context.Background())

	if len(snap.Errors) != 0 {
		t.Fatalf("unexpected collection errors: %v", snap.Errors)
	}
	if len(snap.Namespaces) != 1 || snap.Namespaces[0].Name != "demo" {
		t.Errorf("namespaces = %v", snap.Namespaces)
	}
	for _, p := range snap.Pods {
		if p.Namespace != "demo" {
			t.Errorf("pod from unwatched namespace: %+v", p)
		}
	}
	if len(snap.Pods) != 1 || len(snap.Workloads) != 1 {
		t.Errorf("pods=%d workloads=%d", len(snap.Pods), len(snap.Workloads))
	}
}

func TestCollectWithoutMetricsServer(t *testing.T) {
	f, kc := NewFakeKube(t)
	f.NoMetrics = true

	snap := (&Collector{Kube: kc}).Collect(context.Background())

	if len(snap.Errors) != 0 {
		t.Errorf("a missing metrics-server is normal, not an error: %v", snap.Errors)
	}
	if snap.MetricsAvailable || snap.Nodes[0].Usage != nil || snap.Pods[0].Usage != nil {
		t.Error("usage reported although no metrics exist")
	}
}

func TestCollectKeepsGoingWhenAPartIsForbidden(t *testing.T) {
	f, kc := NewFakeKube(t)
	f.Forbid = []string{"/daemonsets"}

	snap := (&Collector{Kube: kc}).Collect(context.Background())

	if len(snap.Errors) != 1 || !strings.HasPrefix(snap.Errors[0], "daemonsets:") || !strings.Contains(snap.Errors[0], "403") {
		t.Fatalf("errors = %v", snap.Errors)
	}
	if len(snap.Pods) != 2 || len(snap.Workloads) != 1 || len(snap.Nodes) != 2 {
		t.Errorf("the rest of the snapshot should survive: pods=%d workloads=%d nodes=%d", len(snap.Pods), len(snap.Workloads), len(snap.Nodes))
	}
}
