package fakekube

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TLSKey stands for the private key in the fake TLS Secrets; it must never
// appear in anything the agent sends.
const TLSKey = "private-key-that-must-stay-put"

const gib = int64(1) << 30

// volumeUse is how full a fake volume is.
type volumeUse struct {
	ns, claim, node    string
	used, capacity     int64
	inodesUsed, inodes int64
}

// volumes are the claims' file systems, as their kubelets report them.
func (f *Server) volumes(x extra) []volumeUse {
	return append([]volumeUse{{ns: "demo", claim: "data", node: "cp1", used: 62 * gib / 10, capacity: 10 * gib, inodesUsed: 41_000, inodes: 655_360}}, x.volumes...)
}

// statsSummary is the kubelet's /stats/summary for a node: its file
// systems, and its pods' ephemeral storage and volumes.
func (f *Server) statsSummary(node string, x extra) string {
	type ref struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	type volume struct {
		Name           string `json:"name"`
		PVCRef         *ref   `json:"pvcRef,omitempty"`
		UsedBytes      int64  `json:"usedBytes"`
		CapacityBytes  int64  `json:"capacityBytes"`
		AvailableBytes int64  `json:"availableBytes"`
		InodesUsed     int64  `json:"inodesUsed"`
		Inodes         int64  `json:"inodes"`
	}
	type pod struct {
		PodRef    ref      `json:"podRef"`
		Ephemeral *volume  `json:"ephemeral-storage,omitempty"`
		Volume    []volume `json:"volume"`
	}
	// The node's root file system, which also holds the images, is 82%
	// full: past the warning level, short of the kubelet's evictions.
	const diskCapacity = 98 * gib
	root := volume{UsedBytes: diskCapacity * 80 / 100, CapacityBytes: diskCapacity, AvailableBytes: diskCapacity * 18 / 100,
		InodesUsed: 1_200_000, Inodes: 6_400_000}
	var pods []pod
	// The teams' second web pod runs here; each writes a little to its disk.
	for i := 1; i <= f.Extra; i++ {
		used := int64(i) * 9 << 20
		pods = append(pods, pod{PodRef: ref{Name: fmt.Sprintf("web-5d8c-%02d2", i), Namespace: fmt.Sprintf("team-%02d", i)},
			Ephemeral: &volume{UsedBytes: used, CapacityBytes: diskCapacity, AvailableBytes: root.AvailableBytes}})
	}
	for _, v := range f.volumes(x) {
		if v.node != node {
			continue
		}
		// Ext4 keeps some blocks for root: used and available do not add up.
		reserved := v.capacity / 20
		pods = append(pods, pod{PodRef: ref{Name: v.claim + "-0", Namespace: v.ns}, Volume: []volume{
			{Name: "data", PVCRef: &ref{Name: v.claim, Namespace: v.ns}, UsedBytes: v.used - reserved, CapacityBytes: v.capacity,
				AvailableBytes: max(0, v.capacity-v.used), InodesUsed: v.inodesUsed, Inodes: v.inodes},
			{Name: "kube-api-access", UsedBytes: 4096, CapacityBytes: 1 << 20, AvailableBytes: 1<<20 - 4096},
		}})
	}
	b, _ := json.Marshal(map[string]any{
		"node": map[string]any{"nodeName": node, "fs": root, "runtime": map[string]any{"imageFs": root}},
		"pods": pods,
	})
	return string(b)
}

var (
	caOnce sync.Once
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial atomic.Int64

	certsOnce sync.Once
	tlsItems  []string
)

// issue makes a certificate for hosts that expires in left, signed by a
// made-up authority. It returns the chain as PEM, and the key.
func issue(hosts []string, left time.Duration) ([]byte, *ecdsa.PrivateKey, error) {
	now := time.Now().UTC().Truncate(time.Hour)
	var err error
	caOnce.Do(func() {
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Kartal Demo CA"},
			NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		var der []byte
		if der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey); err == nil {
			ca, err = x509.ParseCertificate(der)
		}
	})
	if err != nil || ca == nil {
		return nil, nil, fmt.Errorf("the demo authority: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1) + 1), Subject: pkix.Name{CommonName: hosts[0]},
		DNSNames: hosts, NotBefore: now.Add(left - 90*24*time.Hour), NotAfter: now.Add(left)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...), key, nil
}

// ServingCertificate is a certificate for a demo HTTPS server that expires
// in left.
func ServingCertificate(hosts []string, left time.Duration) (tls.Certificate, error) {
	chain, key, err := issue(hosts, left)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// tlsSecrets are kubernetes.io/tls Secrets: one certificate expires in
// twelve days, so the demo has something to warn about.
func tlsSecrets() []string {
	certsOnce.Do(func() {
		now := time.Now().UTC().Truncate(time.Hour)
		for _, c := range []struct {
			ns, name string
			hosts    []string
			left     time.Duration
		}{
			{"demo", "api-tls", []string{"demo.example.org", "api.example.org"}, 12 * 24 * time.Hour},
			{"kube-system", "traefik-default", []string{"*.example.org"}, 80 * 24 * time.Hour},
		} {
			crt, _, err := issue(c.hosts, c.left)
			if err != nil {
				continue
			}
			b, _ := json.Marshal(map[string]any{
				"metadata": map[string]any{"name": c.name, "namespace": c.ns, "creationTimestamp": now.Add(c.left - 90*24*time.Hour)},
				"type":     "kubernetes.io/tls",
				"data": map[string]string{
					"tls.crt": base64.StdEncoding.EncodeToString(crt),
					"tls.key": base64.StdEncoding.EncodeToString([]byte(TLSKey)),
				},
			})
			tlsItems = append(tlsItems, string(b))
		}
	})
	return tlsItems
}

// serveStorage answers the kubelet's stats and the list of TLS Secrets.
func (f *Server) serveStorage(w http.ResponseWriter, r *http.Request, x extra, metaOnly bool) bool {
	p, q := r.URL.Path, r.URL.Query()
	switch {
	case strings.HasPrefix(p, "/api/v1/nodes/") && strings.HasSuffix(p, "/proxy/stats/summary"):
		node := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/nodes/"), "/proxy/stats/summary")
		if node != "cp1" {
			// Only cp1 is ready; a kubelet that is down does not answer.
			writeStatus(w, http.StatusServiceUnavailable, "ServiceUnavailable", fmt.Sprintf("no route to node %s", node))
			return true
		}
		io.WriteString(w, f.statsSummary(node, x))
	case q.Get("fieldSelector") == "type=kubernetes.io/tls" && strings.HasSuffix(p, "/secrets"):
		if metaOnly {
			writeStatus(w, http.StatusBadRequest, "BadRequest", "certificates need the Secrets' data")
			return true
		}
		only := ""
		if rest, ok := strings.CutPrefix(p, "/api/v1/namespaces/"); ok {
			only = strings.TrimSuffix(rest, "/secrets")
		}
		var items []string
		for _, s := range tlsSecrets() {
			if only == "" || strings.Contains(s, `"namespace":"`+only+`"`) {
				items = append(items, s)
			}
		}
		io.WriteString(w, list(items...))
	default:
		return false
	}
	return true
}
