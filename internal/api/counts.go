package api

import "github.com/BerkeKartal/kartal-gozu/internal/protocol"

// objectCounts are the per-kind numbers the UI shows in its navigation, for
// the whole cluster and for each namespace. The "Degraded", "Unhealthy",
// "Failed" and "Unbound" numbers are the ones that need attention.
type objectCounts struct {
	Workloads            int `json:"workloads"`
	WorkloadsDegraded    int `json:"workloadsDegraded"`
	Deployments          int `json:"deployments"`
	DeploymentsDegraded  int `json:"deploymentsDegraded"`
	StatefulSets         int `json:"statefulSets"`
	StatefulSetsDegraded int `json:"statefulSetsDegraded"`
	DaemonSets           int `json:"daemonSets"`
	DaemonSetsDegraded   int `json:"daemonSetsDegraded"`
	Pods                 int `json:"pods"`
	PodsUnhealthy        int `json:"podsUnhealthy"`
	Services             int `json:"services"`
	Ingresses            int `json:"ingresses"`
	ConfigMaps           int `json:"configMaps"`
	Secrets              int `json:"secrets"`
	VolumeClaims         int `json:"volumeClaims"`
	VolumeClaimsUnbound  int `json:"volumeClaimsUnbound"`
	Jobs                 int `json:"jobs"`
	JobsFailed           int `json:"jobsFailed"`
	CronJobs             int `json:"cronJobs"`
	Warnings             int `json:"warnings"`
}

// tally counts a snapshot's objects for the whole cluster and for each
// namespace, in one pass.
func tally(snap *protocol.Snapshot) (objectCounts, map[string]*objectCounts) {
	var total objectCounts
	byNS := map[string]*objectCounts{}
	count := func(ns string, add func(*objectCounts)) {
		add(&total)
		c := byNS[ns]
		if c == nil {
			c = &objectCounts{}
			byNS[ns] = c
		}
		add(c)
	}
	for _, w := range snap.Workloads {
		degraded := w.Degraded()
		count(w.Namespace, func(c *objectCounts) {
			c.Workloads++
			var kind, kindDegraded *int
			switch w.Kind {
			case "Deployment":
				kind, kindDegraded = &c.Deployments, &c.DeploymentsDegraded
			case "StatefulSet":
				kind, kindDegraded = &c.StatefulSets, &c.StatefulSetsDegraded
			case "DaemonSet":
				kind, kindDegraded = &c.DaemonSets, &c.DaemonSetsDegraded
			}
			if kind != nil {
				*kind++
			}
			if degraded {
				c.WorkloadsDegraded++
				if kindDegraded != nil {
					*kindDegraded++
				}
			}
		})
	}
	for _, p := range snap.Pods {
		unhealthy := !p.Healthy()
		count(p.Namespace, func(c *objectCounts) {
			c.Pods++
			if unhealthy {
				c.PodsUnhealthy++
			}
		})
	}
	for _, s := range snap.Services {
		count(s.Namespace, func(c *objectCounts) { c.Services++ })
	}
	for _, i := range snap.Ingresses {
		count(i.Namespace, func(c *objectCounts) { c.Ingresses++ })
	}
	for _, m := range snap.ConfigMaps {
		count(m.Namespace, func(c *objectCounts) { c.ConfigMaps++ })
	}
	for _, s := range snap.Secrets {
		count(s.Namespace, func(c *objectCounts) { c.Secrets++ })
	}
	for _, v := range snap.VolumeClaims {
		unbound := v.Phase != "Bound"
		count(v.Namespace, func(c *objectCounts) {
			c.VolumeClaims++
			if unbound {
				c.VolumeClaimsUnbound++
			}
		})
	}
	for _, j := range snap.Jobs {
		failed := j.HasFailed()
		count(j.Namespace, func(c *objectCounts) {
			c.Jobs++
			if failed {
				c.JobsFailed++
			}
		})
	}
	for _, cj := range snap.CronJobs {
		count(cj.Namespace, func(c *objectCounts) { c.CronJobs++ })
	}
	for _, e := range snap.Events {
		count(e.Namespace, func(c *objectCounts) { c.Warnings++ })
	}
	return total, byNS
}
