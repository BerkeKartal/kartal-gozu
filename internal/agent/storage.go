package agent

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	volumeEvery      = time.Minute
	certificateEvery = 5 * time.Minute
	// The kubelets are asked a few at a time, each for a short while, and
	// all of them within statsBudget, so a slow node cannot stall reports.
	statsConcurrency = 4
	statsTimeout     = 10 * time.Second
	statsBudget      = 20 * time.Second
	// staleAfter is how long a slow part's last good result outlives
	// failures to collect it again.
	staleAfter = time.Hour
)

// slowPart is a part of the snapshot collected less often than the rest:
// it costs more and changes slowly. In between, the last result is reused.
type slowPart[T any] struct {
	mu    sync.Mutex
	at    time.Time // the last attempt
	okAt  time.Time // the last usable result
	value T
	err   error
}

// get returns the part, collecting it again with load when every has
// passed. load says whether its value is usable; one may come with an error
// that says what is missing from it.
func (p *slowPart[T]) get(now time.Time, every time.Duration, load func() (T, bool, error)) (T, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.at.IsZero() || now.Sub(p.at) >= every {
		p.at = now
		v, ok, err := load()
		p.err = err
		switch {
		case ok:
			p.value, p.okAt = v, now
		case now.Sub(p.okAt) > staleAfter:
			var zero T
			p.value = zero
		}
	}
	return p.value, p.err
}

// fsStats is a file system as /stats/summary describes it.
type fsStats struct {
	UsedBytes      *int64 `json:"usedBytes"`
	CapacityBytes  *int64 `json:"capacityBytes"`
	AvailableBytes *int64 `json:"availableBytes"`
	InodesUsed     *int64 `json:"inodesUsed"`
	Inodes         *int64 `json:"inodes"`
}

// disk tells how full the file system is. What is no longer available is
// what counts: on ext4, blocks kept for root are neither used nor available.
func (f *fsStats) disk() (protocol.Disk, bool) {
	if f == nil || f.CapacityBytes == nil || *f.CapacityBytes <= 0 {
		return protocol.Disk{}, false
	}
	d := protocol.Disk{CapacityBytes: *f.CapacityBytes}
	switch {
	case f.AvailableBytes != nil:
		d.UsedBytes = max(0, d.CapacityBytes-*f.AvailableBytes)
	case f.UsedBytes != nil:
		d.UsedBytes = *f.UsedBytes
	default:
		return protocol.Disk{}, false
	}
	if f.Inodes != nil && f.InodesUsed != nil {
		d.Inodes, d.InodesUsed = *f.Inodes, *f.InodesUsed
	}
	return d, true
}

// statsSummary is the part of the kubelet's /stats/summary the agent
// uses: the node's file systems, and each pod's ephemeral storage and
// volumes.
type statsSummary struct {
	Node struct {
		FS      *fsStats `json:"fs"`
		Runtime *struct {
			ImageFS *fsStats `json:"imageFs"`
		} `json:"runtime"`
	} `json:"node"`
	Pods []struct {
		PodRef struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"podRef"`
		Ephemeral *fsStats `json:"ephemeral-storage"`
		Volume    []struct {
			PVCRef *struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"pvcRef"`
			fsStats
		} `json:"volume"`
	} `json:"pods"`
}

// kubeletStats is what the kubelets said: how full the volume claims are
// (by namespace/name), the nodes' file systems (by node) and how much
// ephemeral storage the pods use (by namespace/name).
type kubeletStats struct {
	claims map[string]protocol.Disk
	nodes  map[string]nodeDisks
	pods   map[string]int64
}

// nodeDisks are a node's root file system and, when they are on one of
// their own, its images'.
type nodeDisks struct {
	root, images *protocol.Disk
}

// volumeStats asks the kubelet of every ready node, through the API
// server, how full its file systems and its pods' volumes are, and how much
// ephemeral storage its pods use. Nodes that do not answer are left out and
// named in the error.
func (c *Collector) volumeStats(ctx context.Context, nodes []protocol.Node) (kubeletStats, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, statsBudget)
	defer cancel()
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		errs     []error
		answered int
	)
	out := kubeletStats{claims: map[string]protocol.Disk{}, nodes: map[string]nodeDisks{}, pods: map[string]int64{}}
	sem := make(chan struct{}, statsConcurrency)
	for _, n := range nodes {
		if !n.Ready {
			continue // its kubelet would not answer either
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			nctx, cancel := context.WithTimeout(ctx, statsTimeout)
			defer cancel()
			var s statsSummary
			err := c.Kube.Get(nctx, "/api/v1/nodes/"+kube.Seg(name)+"/proxy/stats/summary", &s)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				return
			}
			answered++
			var nd nodeDisks
			if d, ok := s.Node.FS.disk(); ok {
				nd.root = &d
			}
			if s.Node.Runtime != nil {
				// Images on the root file system are counted there already.
				if d, ok := s.Node.Runtime.ImageFS.disk(); ok && (nd.root == nil || d.CapacityBytes != nd.root.CapacityBytes) {
					nd.images = &d
				}
			}
			out.nodes[name] = nd
			for _, p := range s.Pods {
				if p.Ephemeral != nil && p.Ephemeral.UsedBytes != nil {
					out.pods[p.PodRef.Namespace+"/"+p.PodRef.Name] = *p.Ephemeral.UsedBytes
				}
				for _, v := range p.Volume {
					if v.PVCRef == nil {
						continue
					}
					if d, ok := v.disk(); ok {
						out.claims[v.PVCRef.Namespace+"/"+v.PVCRef.Name] = d
					}
				}
			}
		}(n.Name)
	}
	wg.Wait()
	if len(errs) > 3 {
		errs = append(errs[:3], fmt.Errorf("and %d more nodes", len(errs)-3))
	}
	return out, answered > 0, errors.Join(errs...)
}

// tlsSecret is a kubernetes.io/tls Secret as the agent reads it: Data has
// tls.crt only, so the decoder skips tls.key and the key is never kept.
type tlsSecret struct {
	Metadata kube.Meta `json:"metadata"`
	Data     struct {
		Cert string `json:"tls.crt"`
	} `json:"data"`
}

// certificates reads the certificates of the TLS Secrets.
func (c *Collector) certificates(ctx context.Context) ([]protocol.Certificate, bool, error) {
	var (
		out  []protocol.Certificate
		errs []error
	)
	q := url.Values{"fieldSelector": {"type=kubernetes.io/tls"}}
	for _, scope := range c.scopes() {
		items, err := kube.ListAll[tlsSecret](ctx, c.Kube, "/api/v1"+scope+"/secrets", q)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, s := range items {
			out = append(out, certificateOf(s))
		}
	}
	sortByNSName(out, func(x protocol.Certificate) (string, string) { return x.Namespace, x.Secret })
	return out, len(errs) < len(c.scopes()), errors.Join(errs...)
}

// certificateOf describes the first certificate of a Secret's tls.crt, the
// server's own; the rest of the chain follows it.
func certificateOf(s tlsSecret) protocol.Certificate {
	out := protocol.Certificate{Namespace: s.Metadata.Namespace, Secret: s.Metadata.Name}
	raw, err := base64.StdEncoding.DecodeString(s.Data.Cert)
	if err != nil || len(raw) == 0 {
		out.Error = "the Secret has no tls.crt"
		return out
	}
	block, rest := pem.Decode(raw)
	for block != nil && block.Type != "CERTIFICATE" {
		block, rest = pem.Decode(rest)
	}
	if block == nil {
		out.Error = "tls.crt holds no PEM certificate"
		return out
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		out.Error = "tls.crt: " + err.Error()
		return out
	}
	out.Subject = cert.Subject.CommonName
	if out.Subject == "" && len(cert.DNSNames) > 0 {
		out.Subject = cert.DNSNames[0]
	}
	out.DNSNames = cert.DNSNames[:min(len(cert.DNSNames), 20)]
	out.Issuer = cert.Issuer.CommonName
	if out.Issuer == "" && len(cert.Issuer.Organization) > 0 {
		out.Issuer = cert.Issuer.Organization[0]
	}
	out.NotBefore, out.NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
	return out
}

// addVolumeStats puts the kubelets' figures on the snapshot's claims,
// nodes and pods.
func (c *Collector) addVolumeStats(ctx context.Context, snap *protocol.Snapshot) {
	stats, err := c.volumes.get(c.now(), volumeEvery, func() (kubeletStats, bool, error) {
		return c.volumeStats(ctx, snap.Nodes)
	})
	if err != nil {
		snap.Errors = append(snap.Errors, "volume stats: "+err.Error())
	}
	for i := range snap.VolumeClaims {
		v := &snap.VolumeClaims[i]
		if d, ok := stats.claims[v.Namespace+"/"+v.Name]; ok {
			v.UsedBytes, v.CapacityBytes, v.InodesUsed, v.Inodes = d.UsedBytes, d.CapacityBytes, d.InodesUsed, d.Inodes
		}
	}
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if nd, ok := stats.nodes[n.Name]; ok {
			n.Disk, n.ImageDisk = nd.root, nd.images
		}
	}
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if used, ok := stats.pods[p.Namespace+"/"+p.Name]; ok {
			p.DiskBytes = &used
		}
	}
}
