package api

import (
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// objectCounts are the per-kind numbers the UI shows in its navigation, for
// the whole cluster and for each namespace. The "Degraded", "Unhealthy",
// "Failed", "Unbound", "Filling" and "Expiring" numbers are the ones that
// need attention.
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
	PodsReplaced         int `json:"podsReplaced"` // left behind, not unhealthy
	Services             int `json:"services"`
	Ingresses            int `json:"ingresses"`
	ConfigMaps           int `json:"configMaps"`
	Secrets              int `json:"secrets"`
	VolumeClaims         int `json:"volumeClaims"`
	VolumeClaimsUnbound  int `json:"volumeClaimsUnbound"`
	VolumeClaimsFilling  int `json:"volumeClaimsFilling"`
	Certificates         int `json:"certificates"`
	CertificatesExpiring int `json:"certificatesExpiring"`
	Jobs                 int `json:"jobs"`
	JobsFailed           int `json:"jobsFailed"`
	CronJobs             int `json:"cronJobs"`
	Warnings             int `json:"warnings"`
}

// tally counts a snapshot's objects for the whole cluster and for each
// namespace, in one pass.
func tally(snap *protocol.Snapshot, lv levels) (objectCounts, map[string]*objectCounts) {
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
		unhealthy, replaced := p.Troubled(), p.Replaced()
		count(p.Namespace, func(c *objectCounts) {
			c.Pods++
			if unhealthy {
				c.PodsUnhealthy++
			}
			if replaced {
				c.PodsReplaced++
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
		unbound, filling := v.Phase != "Bound", lv.filling(v)
		count(v.Namespace, func(c *objectCounts) {
			c.VolumeClaims++
			if unbound {
				c.VolumeClaimsUnbound++
			}
			if filling {
				c.VolumeClaimsFilling++
			}
		})
	}
	for _, crt := range snap.Certificates {
		expiring := lv.expiring(crt)
		count(crt.Namespace, func(c *objectCounts) {
			c.Certificates++
			if expiring {
				c.CertificatesExpiring++
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

// levels say when a volume or a certificate needs attention; they follow
// the alerts' warning levels.
type levels struct {
	volume      float64
	nodeDisk    float64
	certificate time.Duration
	now         time.Time
}

func (s *Server) levels() levels {
	volume, _ := s.cfg.Alerts.VolumeLevels()
	nodeDisk, _ := s.cfg.Alerts.NodeDiskLevels()
	certificate, _ := s.cfg.Alerts.CertificateLevels()
	return levels{volume: volume, nodeDisk: nodeDisk, certificate: certificate, now: s.now()}
}

func (lv levels) filling(v protocol.VolumeClaim) bool { return v.Fill() >= lv.volume }

// diskFilling tells whether a node's disk is past the warning level.
func (lv levels) diskFilling(n protocol.Node) bool {
	return n.Disk.Fill() >= lv.nodeDisk || n.ImageDisk.Fill() >= lv.nodeDisk
}

// expiring includes a certificate that cannot be read: nobody knows when
// it expires.
func (lv levels) expiring(c protocol.Certificate) bool {
	return c.Error != "" || c.NotAfter.Sub(lv.now) <= lv.certificate
}
