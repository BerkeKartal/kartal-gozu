package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
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

func TestUnreadableWatchedNamespaceStaysListed(t *testing.T) {
	_, kc := NewFakeKube(t)
	c := &Collector{Kube: kc, Namespaces: []string{"demo", "missing"}}

	snap := c.Collect(context.Background())

	if len(snap.Namespaces) != 2 || snap.Namespaces[0].Name != "demo" || snap.Namespaces[1].Name != "missing" {
		t.Errorf("namespaces = %+v", snap.Namespaces)
	}
	found := false
	for _, e := range snap.Errors {
		found = found || strings.HasPrefix(e, "namespaces: missing:")
	}
	if !found {
		t.Errorf("the unreadable namespace should be reported: %v", snap.Errors)
	}
	if len(snap.Pods) != 1 {
		t.Errorf("the readable namespace should still be collected: %d pods", len(snap.Pods))
	}
}

func TestPodResourcesCountSidecars(t *testing.T) {
	var p kube.Pod
	err := json.Unmarshal([]byte(`{"spec":{
		"initContainers":[
			{"name":"proxy","restartPolicy":"Always","resources":{"requests":{"cpu":"100m","memory":"64Mi"}}},
			{"name":"migrate","resources":{"requests":{"cpu":"500m","memory":"32Mi"}}}],
		"containers":[{"name":"app","resources":{"requests":{"cpu":"200m","memory":"128Mi"},"limits":{"cpu":"1"}}}]}}`), &p)
	if err != nil {
		t.Fatal(err)
	}
	req, lim := podResources(p)
	// The app and the sidecar need 300m and 192Mi; "migrate" runs next to
	// the sidecar started before it: 600m and 96Mi. The pod needs the most.
	if req == nil || req.CPUMilli != 600 || req.MemoryBytes != 192<<20 || lim == nil || lim.CPUMilli != 1000 || lim.MemoryBytes != 0 {
		t.Errorf("requests %+v, limits %+v", req, lim)
	}
}

func TestVolumeStatsAndCertificates(t *testing.T) {
	f, kc := NewFakeKube(t)
	now := time.Now()
	c := &Collector{Kube: kc, Version: "test", VolumeStats: true, TLSSecrets: true, Now: func() time.Time { return now }}
	snap := c.Collect(context.Background())
	if len(snap.Errors) != 0 {
		t.Fatalf("errors: %v", snap.Errors)
	}
	// Used is what is no longer available, reserved blocks included.
	if v := snap.VolumeClaims[0]; v.UsedBytes != 62<<30/10 || v.CapacityBytes != 10<<30 || v.InodesUsed != 41_000 || v.Inodes != 655_360 {
		t.Errorf("volume: %+v", v)
	}
	if len(snap.Certificates) != 2 {
		t.Fatalf("certificates: %+v", snap.Certificates)
	}
	api := snap.Certificates[0]
	left := api.NotAfter.Sub(now)
	if api.Secret != "api-tls" || api.Subject != "demo.example.org" || api.Issuer != "Kartal Demo CA" ||
		len(api.DNSNames) != 2 || left < 11*24*time.Hour || left > 12*24*time.Hour {
		t.Errorf("certificate: %+v", api)
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "private-key") || strings.Contains(string(b), "BEGIN") {
		t.Error("the snapshot carries key or certificate material")
	}

	// Within the minute, the kubelets are not asked again; when they cannot
	// be asked, the last figures stay and the error is shown.
	f.Forbid = []string{"/proxy/stats/summary", "/secrets"}
	if snap := c.Collect(context.Background()); len(snap.Errors) != 0 || snap.VolumeClaims[0].UsedBytes == 0 {
		t.Errorf("asked again too soon: %v", snap.Errors)
	}
	now = now.Add(6 * time.Minute)
	snap = c.Collect(context.Background())
	if len(snap.Errors) != 2 || !strings.HasPrefix(snap.Errors[0], "certificates: ") || !strings.HasPrefix(snap.Errors[1], "volume stats: cp1: ") ||
		snap.VolumeClaims[0].UsedBytes == 0 || len(snap.Certificates) != 2 {
		t.Errorf("after a failure: %v %+v", snap.Errors, snap.VolumeClaims[0])
	}
	// After an hour without an answer, the old figures are dropped.
	now = now.Add(2 * time.Hour)
	if snap := c.Collect(context.Background()); snap.VolumeClaims[0].UsedBytes != 0 || len(snap.Certificates) != 0 {
		t.Errorf("stale figures kept: %+v", snap.VolumeClaims[0])
	}
}

func TestNodeAndPodDisks(t *testing.T) {
	f, kc := NewFakeKube(t)
	f.Extra = 2
	snap := (&Collector{Kube: kc, Version: "test", VolumeStats: true}).Collect(context.Background())
	if len(snap.Errors) != 0 {
		t.Fatalf("errors: %v", snap.Errors)
	}
	nodes := map[string]protocol.Node{}
	for _, n := range snap.Nodes {
		nodes[n.Name] = n
	}
	// The images share the root file system, so they are not counted twice;
	// the node that does not answer has no figures.
	const capacity = 98 << 30
	if d := nodes["cp1"].Disk; d == nil || d.CapacityBytes != capacity || d.UsedBytes != capacity-capacity*18/100 ||
		d.Inodes != 6_400_000 || nodes["cp1"].ImageDisk != nil {
		t.Errorf("cp1: %+v, images %+v", d, nodes["cp1"].ImageDisk)
	}
	if n := nodes["worker1"]; n.Disk != nil || n.ImageDisk != nil {
		t.Errorf("worker1: %+v", n.Disk)
	}
	if a := nodes["cp1"].Allocatable; a.DiskBytes != 88<<30 {
		t.Errorf("allocatable ephemeral storage: %+v", a)
	}
	disks := map[string]int64{}
	for _, p := range snap.Pods {
		if p.DiskBytes != nil {
			disks[p.Namespace+"/"+p.Name] = *p.DiskBytes
		}
		if p.Name == "web-5d8c-012" && (p.Requests == nil || p.Requests.DiskBytes != 100<<20 || p.Limits == nil || p.Limits.DiskBytes != 1<<30) {
			t.Errorf("ephemeral storage: requests %+v, limits %+v", p.Requests, p.Limits)
		}
	}
	if want := map[string]int64{"team-01/web-5d8c-012": 9 << 20, "team-02/web-5d8c-022": 18 << 20}; !reflect.DeepEqual(disks, want) {
		t.Errorf("pod disks: %v", disks)
	}
}
