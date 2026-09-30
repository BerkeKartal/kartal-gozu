package agent

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Collector builds a Snapshot from the Kubernetes API.
type Collector struct {
	Kube *kube.Client
	// Namespaces limits collection; empty means the whole cluster.
	Namespaces []string
	// IncludeSecrets adds Secret names (never their values) to the snapshot.
	IncludeSecrets bool
	MaxEvents      int
	Version        string
	Now            func() time.Time
}

// collectConcurrency bounds parallel API calls; they share one HTTP/2
// connection, so this mostly limits load on the API server.
const collectConcurrency = 6

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// scopes returns the path fragments to query: one per watched namespace, or
// a single cluster-wide scope.
func (c *Collector) scopes() []string {
	if len(c.Namespaces) == 0 {
		return []string{""}
	}
	out := make([]string, len(c.Namespaces))
	for i, ns := range c.Namespaces {
		out[i] = "/namespaces/" + kube.Seg(ns)
	}
	return out
}

// each lists one resource in every scope and converts the items.
func each[K, P any](ctx context.Context, c *Collector, fail func(string, error), what, prefix, resource string, query url.Values, conv func(K) P) []P {
	var out []P
	for _, scope := range c.scopes() {
		items, err := kube.ListAll[K](ctx, c.Kube, prefix+scope+"/"+resource, query)
		if err != nil {
			fail(what, err)
			continue
		}
		for _, it := range items {
			out = append(out, conv(it))
		}
	}
	return out
}

func (c *Collector) Collect(ctx context.Context) *protocol.Snapshot {
	snap := &protocol.Snapshot{AgentVersion: c.Version, CollectedAt: c.now().UTC()}
	var (
		mu                                    sync.Mutex
		deployments, statefulsets, daemonsets []protocol.Workload
		nodeUsage, podUsage                   map[string]protocol.Resources
	)
	fail := func(what string, err error) {
		mu.Lock()
		defer mu.Unlock()
		snap.Errors = append(snap.Errors, what+": "+err.Error())
	}
	warnings := url.Values{"fieldSelector": {"type=Warning"}}

	// Every task writes only its own variables, so they can run in parallel.
	tasks := []func(){
		func() {
			if v, err := c.Kube.ServerVersion(ctx); err != nil {
				fail("version", err)
			} else {
				snap.KubeVersion = v
			}
		},
		func() {
			if ns, err := c.namespaces(ctx); err != nil {
				fail("namespaces", err)
			} else {
				snap.Namespaces = ns
			}
		},
		func() {
			if items, err := kube.ListAll[kube.Node](ctx, c.Kube, "/api/v1/nodes", nil); err != nil {
				fail("nodes", err)
			} else {
				for _, n := range items {
					snap.Nodes = append(snap.Nodes, toNode(n))
				}
			}
		},
		func() {
			deployments = each(ctx, c, fail, "deployments", "/apis/apps/v1", "deployments", nil,
				func(r kube.Replicated) protocol.Workload { return replicatedWorkload("Deployment", r) })
		},
		func() {
			statefulsets = each(ctx, c, fail, "statefulsets", "/apis/apps/v1", "statefulsets", nil,
				func(r kube.Replicated) protocol.Workload { return replicatedWorkload("StatefulSet", r) })
		},
		func() {
			daemonsets = each(ctx, c, fail, "daemonsets", "/apis/apps/v1", "daemonsets", nil, daemonSetWorkload)
		},
		func() { snap.Pods = each(ctx, c, fail, "pods", "/api/v1", "pods", nil, toPod) },
		func() { snap.Services = each(ctx, c, fail, "services", "/api/v1", "services", nil, toService) },
		func() {
			snap.Ingresses = each(ctx, c, fail, "ingresses", "/apis/networking.k8s.io/v1", "ingresses", nil, toIngress)
		},
		func() { snap.ConfigMaps = c.metaRefs(ctx, fail, "configmaps") },
		func() {
			if c.IncludeSecrets {
				snap.Secrets = c.metaRefs(ctx, fail, "secrets")
			}
		},
		func() {
			snap.VolumeClaims = each(ctx, c, fail, "persistentvolumeclaims", "/api/v1", "persistentvolumeclaims", nil, toVolumeClaim)
		},
		func() { snap.Jobs = each(ctx, c, fail, "jobs", "/apis/batch/v1", "jobs", nil, toJob) },
		func() { snap.CronJobs = each(ctx, c, fail, "cronjobs", "/apis/batch/v1", "cronjobs", nil, toCronJob) },
		func() { snap.Events = each(ctx, c, fail, "events", "/api/v1", "events", warnings, toEvent) },
		func() { nodeUsage = c.nodeMetrics(ctx, fail) },
		func() { podUsage = c.podMetrics(ctx, fail) },
	}

	sem := make(chan struct{}, collectConcurrency)
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(task func()) {
			defer wg.Done()
			defer func() { <-sem }()
			task()
		}(task)
	}
	wg.Wait()

	snap.Workloads = append(append(deployments, statefulsets...), daemonsets...)
	snap.MetricsAvailable = nodeUsage != nil || podUsage != nil
	podsPerNode := map[string]int{}
	for i := range snap.Pods {
		p := &snap.Pods[i]
		podsPerNode[p.Node]++
		if u, ok := podUsage[p.Namespace+"/"+p.Name]; ok {
			p.Usage = &u
		}
	}
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		n.PodCount = podsPerNode[n.Name]
		if u, ok := nodeUsage[n.Name]; ok {
			n.Usage = &u
		}
	}

	sort.Slice(snap.Nodes, func(i, j int) bool { return snap.Nodes[i].Name < snap.Nodes[j].Name })
	sortByNSName(snap.Workloads, func(x protocol.Workload) (string, string) { return x.Namespace, x.Kind + "/" + x.Name })
	sortByNSName(snap.Pods, func(x protocol.Pod) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.Services, func(x protocol.Service) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.Ingresses, func(x protocol.Ingress) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.ConfigMaps, func(x protocol.ObjectRef) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.Secrets, func(x protocol.ObjectRef) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.VolumeClaims, func(x protocol.VolumeClaim) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.Jobs, func(x protocol.Job) (string, string) { return x.Namespace, x.Name })
	sortByNSName(snap.CronJobs, func(x protocol.CronJob) (string, string) { return x.Namespace, x.Name })
	sort.Slice(snap.Events, func(i, j int) bool { return snap.Events[i].LastSeen.After(snap.Events[j].LastSeen) })
	if limit := c.MaxEvents; limit > 0 && len(snap.Events) > limit {
		snap.Events = snap.Events[:limit]
	}
	sort.Strings(snap.Errors)
	return snap
}

func sortByNSName[T any](s []T, key func(T) (string, string)) {
	sort.Slice(s, func(i, j int) bool {
		ai, an := key(s[i])
		bi, bn := key(s[j])
		if ai != bi {
			return ai < bi
		}
		return an < bn
	})
}

func (c *Collector) namespaces(ctx context.Context) ([]protocol.Namespace, error) {
	if len(c.Namespaces) == 0 {
		items, err := kube.ListAll[kube.Namespace](ctx, c.Kube, "/api/v1/namespaces", nil)
		if err != nil {
			return nil, err
		}
		out := make([]protocol.Namespace, 0, len(items))
		for _, it := range items {
			out = append(out, protocol.Namespace{Name: it.Metadata.Name, Status: it.Status.Phase})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	out := make([]protocol.Namespace, 0, len(c.Namespaces))
	for _, name := range c.Namespaces {
		var ns kube.Namespace
		if err := c.Kube.Get(ctx, "/api/v1/namespaces/"+kube.Seg(name), &ns); err != nil {
			return out, err
		}
		out = append(out, protocol.Namespace{Name: ns.Metadata.Name, Status: ns.Status.Phase})
	}
	return out, nil
}

// metaRefs lists names only: object contents are never transferred.
func (c *Collector) metaRefs(ctx context.Context, fail func(string, error), resource string) []protocol.ObjectRef {
	var out []protocol.ObjectRef
	for _, scope := range c.scopes() {
		items, err := kube.ListMeta(ctx, c.Kube, "/api/v1"+scope+"/"+resource, 0)
		if err != nil {
			fail(resource, err)
			continue
		}
		for _, m := range items {
			out = append(out, protocol.ObjectRef{Namespace: m.Namespace, Name: m.Name, CreatedAt: m.CreationTimestamp})
		}
	}
	return out
}

// nodeMetrics returns nil when metrics-server is not installed.
func (c *Collector) nodeMetrics(ctx context.Context, fail func(string, error)) map[string]protocol.Resources {
	items, err := kube.ListAll[kube.NodeMetrics](ctx, c.Kube, "/apis/metrics.k8s.io/v1beta1/nodes", nil)
	if err != nil {
		if !kube.IsNotFound(err) {
			fail("node metrics", err)
		}
		return nil
	}
	out := make(map[string]protocol.Resources, len(items))
	for _, it := range items {
		out[it.Metadata.Name] = protocol.Resources{CPUMilli: kube.MilliValue(it.Usage["cpu"]), MemoryBytes: kube.Value(it.Usage["memory"])}
	}
	return out
}

func (c *Collector) podMetrics(ctx context.Context, fail func(string, error)) map[string]protocol.Resources {
	var out map[string]protocol.Resources
	for _, scope := range c.scopes() {
		items, err := kube.ListAll[kube.PodMetrics](ctx, c.Kube, "/apis/metrics.k8s.io/v1beta1"+scope+"/pods", nil)
		if err != nil {
			if !kube.IsNotFound(err) {
				fail("pod metrics", err)
			}
			continue
		}
		if out == nil {
			out = map[string]protocol.Resources{}
		}
		for _, it := range items {
			var r protocol.Resources
			for _, ct := range it.Containers {
				r.CPUMilli += kube.MilliValue(ct.Usage["cpu"])
				r.MemoryBytes += kube.Value(ct.Usage["memory"])
			}
			out[it.Metadata.Namespace+"/"+it.Metadata.Name] = r
		}
	}
	return out
}

func images(t kube.PodTemplate) []string {
	out := make([]string, 0, len(t.Spec.Containers))
	for _, c := range t.Spec.Containers {
		out = append(out, c.Image)
	}
	return out
}

func replicatedWorkload(kind string, r kube.Replicated) protocol.Workload {
	desired := int32(1) // Kubernetes defaults an unset replicas field to 1
	if r.Spec.Replicas != nil {
		desired = *r.Spec.Replicas
	}
	return protocol.Workload{
		Kind:      kind,
		Namespace: r.Metadata.Namespace,
		Name:      r.Metadata.Name,
		Desired:   desired,
		Ready:     r.Status.ReadyReplicas,
		Updated:   r.Status.UpdatedReplicas,
		Images:    images(r.Spec.Template),
		CreatedAt: r.Metadata.CreationTimestamp,
	}
}

func daemonSetWorkload(d kube.DaemonSet) protocol.Workload {
	return protocol.Workload{
		Kind:      "DaemonSet",
		Namespace: d.Metadata.Namespace,
		Name:      d.Metadata.Name,
		Desired:   d.Status.DesiredNumberScheduled,
		Ready:     d.Status.NumberReady,
		Updated:   d.Status.UpdatedNumberScheduled,
		Images:    images(d.Spec.Template),
		CreatedAt: d.Metadata.CreationTimestamp,
	}
}

func resources(m map[string]string) protocol.Resources {
	return protocol.Resources{CPUMilli: kube.MilliValue(m["cpu"]), MemoryBytes: kube.Value(m["memory"]), Pods: kube.Value(m["pods"])}
}

func toNode(n kube.Node) protocol.Node {
	out := protocol.Node{
		Name:             n.Metadata.Name,
		Unschedulable:    n.Spec.Unschedulable,
		KubeletVersion:   n.Status.NodeInfo.KubeletVersion,
		OSImage:          n.Status.NodeInfo.OSImage,
		ContainerRuntime: n.Status.NodeInfo.ContainerRuntimeVersion,
		Capacity:         resources(n.Status.Capacity),
		Allocatable:      resources(n.Status.Allocatable),
		CreatedAt:        n.Metadata.CreationTimestamp,
	}
	for label := range n.Metadata.Labels {
		if role, ok := strings.CutPrefix(label, "node-role.kubernetes.io/"); ok && role != "" {
			out.Roles = append(out.Roles, role)
		}
	}
	sort.Strings(out.Roles)
	for _, a := range n.Status.Addresses {
		if a.Type == "InternalIP" {
			out.InternalIP = a.Address
			break
		}
	}
	for _, cond := range n.Status.Conditions {
		switch {
		case cond.Type == "Ready":
			out.Ready = cond.Status == "True"
		case cond.Status == "True":
			out.Pressure = append(out.Pressure, cond.Type)
		}
	}
	for _, t := range n.Spec.Taints {
		s := t.Key
		if t.Value != "" {
			s += "=" + t.Value
		}
		out.Taints = append(out.Taints, s+":"+t.Effect)
	}
	return out
}

func stateReason(s kube.ContainerState) string {
	if s.Waiting != nil {
		return s.Waiting.Reason
	}
	if s.Terminated != nil {
		return s.Terminated.Reason
	}
	return ""
}

func toPod(p kube.Pod) protocol.Pod {
	out := protocol.Pod{
		Namespace: p.Metadata.Namespace,
		Name:      p.Metadata.Name,
		Phase:     p.Status.Phase,
		Reason:    p.Status.Reason,
		Node:      p.Spec.NodeName,
		IP:        p.Status.PodIP,
		Total:     len(p.Spec.Containers),
		Owner:     ownerOf(p.Metadata),
	}
	if p.Status.StartTime != nil {
		out.StartedAt = *p.Status.StartTime
	}
	for _, c := range p.Spec.Containers {
		out.Containers = append(out.Containers, c.Name)
	}
	for _, cs := range p.Status.InitContainerStatuses {
		if r := stateReason(cs.State); r != "" && r != "Completed" && out.Reason == "" {
			out.Reason = "Init:" + r
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Ready {
			out.Ready++
		}
		out.Restarts += cs.RestartCount
		if r := stateReason(cs.State); r != "" && out.Reason == "" && p.Status.Phase != "Succeeded" {
			out.Reason = r
		}
	}
	return out
}

func toService(s kube.Service) protocol.Service {
	out := protocol.Service{
		Namespace: s.Metadata.Namespace,
		Name:      s.Metadata.Name,
		Type:      s.Spec.Type,
		ClusterIP: s.Spec.ClusterIP,
		Selector:  s.Spec.Selector,
		CreatedAt: s.Metadata.CreationTimestamp,
	}
	for _, p := range s.Spec.Ports {
		out.Ports = append(out.Ports, protocol.ServicePort{
			Name: p.Name, Port: p.Port, TargetPort: string(p.TargetPort), NodePort: p.NodePort, Protocol: p.Protocol,
		})
	}
	return out
}

func toIngress(in kube.Ingress) protocol.Ingress {
	out := protocol.Ingress{
		Namespace: in.Metadata.Namespace,
		Name:      in.Metadata.Name,
		TLS:       len(in.Spec.TLS) > 0,
		CreatedAt: in.Metadata.CreationTimestamp,
	}
	if in.Spec.IngressClassName != nil {
		out.Class = *in.Spec.IngressClassName
	}
	for _, r := range in.Spec.Rules {
		if r.HTTP == nil {
			out.Rules = append(out.Rules, protocol.IngressRule{Host: r.Host})
			continue
		}
		for _, p := range r.HTTP.Paths {
			backend := ""
			if svc := p.Backend.Service; svc != nil {
				port := svc.Port.Name
				if port == "" {
					port = strconv.Itoa(int(svc.Port.Number))
				}
				backend = svc.Name + ":" + port
			}
			out.Rules = append(out.Rules, protocol.IngressRule{Host: r.Host, Path: p.Path, Backend: backend})
		}
	}
	return out
}

func toVolumeClaim(p kube.PersistentVolumeClaim) protocol.VolumeClaim {
	out := protocol.VolumeClaim{
		Namespace:   p.Metadata.Namespace,
		Name:        p.Metadata.Name,
		Phase:       p.Status.Phase,
		Capacity:    p.Status.Capacity["storage"],
		VolumeName:  p.Spec.VolumeName,
		AccessModes: p.Spec.AccessModes,
		CreatedAt:   p.Metadata.CreationTimestamp,
	}
	if p.Spec.StorageClassName != nil {
		out.StorageClass = *p.Spec.StorageClassName
	}
	return out
}

func toJob(j kube.Job) protocol.Job {
	completions := int32(1)
	if j.Spec.Completions != nil {
		completions = *j.Spec.Completions
	}
	return protocol.Job{
		Namespace:   j.Metadata.Namespace,
		Name:        j.Metadata.Name,
		Owner:       ownerOf(j.Metadata),
		Completions: completions,
		Succeeded:   j.Status.Succeeded,
		Failed:      j.Status.Failed,
		Active:      j.Status.Active,
		StartedAt:   j.Status.StartTime,
		CompletedAt: j.Status.CompletionTime,
	}
}

func toCronJob(cj kube.CronJob) protocol.CronJob {
	return protocol.CronJob{
		Namespace:    cj.Metadata.Namespace,
		Name:         cj.Metadata.Name,
		Schedule:     cj.Spec.Schedule,
		Suspended:    cj.Spec.Suspend != nil && *cj.Spec.Suspend,
		Active:       len(cj.Status.Active),
		LastSchedule: cj.Status.LastScheduleTime,
		LastSuccess:  cj.Status.LastSuccessfulTime,
	}
}

// ownerOf names the controlling object; a ReplicaSet is reported as the
// Deployment that owns it, which is what people actually manage.
func ownerOf(m kube.Meta) string {
	for _, o := range m.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if h := m.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "Deployment/" + strings.TrimSuffix(o.Name, "-"+h)
			}
		}
		return o.Kind + "/" + o.Name
	}
	return ""
}

func latest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.After(out) {
			out = t
		}
	}
	return out
}

func toEvent(e kube.Event) protocol.Event {
	count := e.Count
	if count == 0 {
		count = 1
	}
	ns := e.InvolvedObject.Namespace
	if ns == "" {
		ns = e.Metadata.Namespace
	}
	return protocol.Event{
		Namespace: ns,
		Object:    e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name,
		Reason:    e.Reason,
		Message:   e.Message,
		Count:     count,
		LastSeen:  latest(e.LastTimestamp, e.EventTime, e.FirstTimestamp, e.Metadata.CreationTimestamp),
	}
}
