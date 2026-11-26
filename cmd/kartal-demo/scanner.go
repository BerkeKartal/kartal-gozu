package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	mrand "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

// demoScanner plays kartal-scanner without Trivy: it makes up what it
// finds, the same for the same image each time, from a few packages each
// kind of image has. Its vulnerabilities are named DEMO-…, so that none is
// taken for a real one.
type demoScanner struct {
	mu      sync.Mutex
	updated time.Time
}

func newDemoScanner() *demoScanner {
	return &demoScanner{updated: time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)}
}

// demoPackage is a package an image may have, with what may be wrong in it.
type demoPackage struct {
	name, version, kind string
	vulns               []demoVuln
}

type demoVuln struct {
	severity, fixed, title string
	score                  float64
}

var demoPackages = map[string][]demoPackage{
	"alpine": {
		{"busybox", "1.36.1-r29", "alpine", []demoVuln{{scanner.Medium, "1.36.1-r30", "busybox: an out-of-bounds read in awk", 5.5}, {scanner.Low, "", "busybox: a crafted archive fills the disk", 3.3}}},
		{"musl", "1.2.5-r0", "alpine", []demoVuln{{scanner.High, "1.2.5-r1", "musl: iconv writes past its buffer", 7.5}}},
		{"ssl_client", "1.36.1-r29", "alpine", nil},
	},
	"debian": {
		{"openssl", "3.0.14-1~deb12u1", "debian", []demoVuln{{scanner.Critical, "3.0.15-1~deb12u1", "openssl: a crafted certificate runs code", 9.8},
			{scanner.High, "3.0.15-1~deb12u1", "openssl: a timing side channel leaks keys", 7.4}, {scanner.Medium, "", "openssl: a denial of service in name checks", 5.9}}},
		{"zlib1g", "1:1.2.13.dfsg-1", "debian", []demoVuln{{scanner.Critical, "", "zlib: inflate overflows its window", 9.1}}},
		{"libc6", "2.36-9+deb12u7", "debian", []demoVuln{{scanner.High, "2.36-9+deb12u8", "glibc: a buffer overflow in a printf family", 7.8}, {scanner.Low, "", "glibc: an assertion in a rarely used call", 2.9}}},
		{"nginx", "1.26.2-1", "debian", []demoVuln{{scanner.Medium, "1.26.3-1", "nginx: a crafted request exhausts memory", 5.3}}},
		{"tzdata", "2024a-0+deb12u1", "debian", nil},
	},
	"go": {
		{"stdlib", "v1.22.5", "gobinary", []demoVuln{{scanner.High, "1.22.7", "net/http: request smuggling through chunked bodies", 7.5}, {scanner.Medium, "1.22.7", "encoding/gob: a deep structure exhausts the stack", 5.9}}},
		{"golang.org/x/net", "v0.26.0", "gobinary", []demoVuln{{scanner.Medium, "0.33.0", "x/net/html: quadratic parsing of crafted HTML", 5.3}}},
		{"github.com/example/web", "(devel)", "gobinary", nil},
	},
}

// families are what an image of a repository is built of.
func families(repo string) []string {
	switch {
	case strings.Contains(repo, "alpine") || strings.Contains(repo, "busybox"):
		return []string{"alpine"}
	case strings.Contains(repo, "nginx"):
		return []string{"debian"}
	case strings.Contains(repo, "web") || strings.Contains(repo, "storefront") || strings.Contains(repo, "billing"):
		return []string{"alpine", "go"}
	}
	return []string{"alpine"}
}

func (d *demoScanner) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	// A scan takes a moment.
	select {
	case <-time.After(400 * time.Millisecond):
	case <-ctx.Done():
		return scanner.Result{}, ctx.Err()
	}
	_, rest, _ := strings.Cut(req.Image, "/")
	repo, digest, _ := strings.Cut(rest, "@")
	h := fnv.New64a()
	h.Write([]byte(digest))
	rnd := mrand.New(mrand.NewSource(int64(h.Sum64())))
	rep := scanner.Report{Scanner: d.status().Scanner, DB: d.status().DB.UpdatedAt, Vulnerabilities: []scanner.Vulnerability{}}
	type component struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var comps []component
	for _, fam := range families(repo) {
		if fam != "go" {
			rep.OS = map[string]string{"alpine": "alpine 3.20.3", "debian": "debian 12.7"}[fam]
		}
		for _, p := range demoPackages[fam] {
			rep.Packages++
			comps = append(comps, component{Type: "library", Name: p.name, Version: p.version})
			for i, v := range p.vulns {
				// Each image has some of them: a newer build fewer.
				if rnd.Intn(3) == 0 {
					continue
				}
				id := fmt.Sprintf("DEMO-2026-%04d", 1000+int(fnv32(p.name))%8000+i)
				target := repo + " (" + rep.OS + ")"
				if p.kind == "gobinary" {
					target = "usr/local/bin/web"
				}
				rep.Vulnerabilities = append(rep.Vulnerabilities, scanner.Vulnerability{ID: id, Package: p.name, Installed: p.version, Fixed: v.fixed,
					Severity: v.severity, Score: v.score, Title: v.title + " (made up by the demo)", Target: target, Type: p.kind, Status: status(v.fixed)})
			}
		}
	}
	scanner.Sort(rep.Vulnerabilities)
	sbom, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata": map[string]any{"component": map[string]string{"type": "container", "name": repo}}, "components": comps})
	return scanner.Result{Report: rep, SBOM: sbom}, nil
}

func status(fixed string) string {
	if fixed == "" {
		return "affected"
	}
	return "fixed"
}

func fnv32(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func (d *demoScanner) status() scanner.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	at, next := d.updated, d.updated.Add(24*time.Hour)
	java := d.updated.Add(-30 * time.Hour)
	return scanner.Status{Scanner: "Trivy 0.69.3 (demo)", DB: &scanner.DBStatus{UpdatedAt: &at, NextUpdate: &next, DownloadedAt: &at},
		JavaDB: &scanner.DBStatus{UpdatedAt: &java, DownloadedAt: &at}, Workers: 2, LastUpdate: &at}
}

func (d *demoScanner) UpdateDB(ctx context.Context) (scanner.Status, error) {
	select {
	case <-time.After(time.Second):
	case <-ctx.Done():
		return scanner.Status{}, ctx.Err()
	}
	d.mu.Lock()
	d.updated = time.Now().UTC().Add(-time.Hour).Truncate(time.Hour)
	d.mu.Unlock()
	return d.status(), nil
}

func (d *demoScanner) Status(context.Context) (scanner.Status, error) { return d.status(), nil }
