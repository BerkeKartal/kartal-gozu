package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The demo's image registry is kartal-registry's handlers in the demo's
// process, which the demo server answers sign-ins for, as it would
// kartal-registry's. The first time, it is filled with made-up images,
// pushed through those handlers as a client would push them, over a
// made-up past.

const (
	ociConfig = "application/vnd.oci.image.config.v1+json"
	ociLayer  = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// demoRegistry starts the registry: its admin API, where clients push and
// pull, and what stops it.
func demoRegistry(ctx context.Context, dir, serverURL, secret string, log *slog.Logger) (adminURL, public string, stop func(), err error) {
	store, err := blobstore.NewFile(filepath.Join(dir, "store"))
	if err != nil {
		return "", "", nil, err
	}
	db, err := meta.Open(filepath.Join(dir, "meta"))
	if err != nil {
		return "", "", nil, err
	}
	if len(db.Projects()) == 0 {
		if err := seedRegistry(store, db, log); err != nil {
			db.Close()
			return "", "", nil, fmt.Errorf("filling the demo's image registry: %w", err)
		}
	}
	pub, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		db.Close()
		return "", "", nil, err
	}
	adm, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		pub.Close()
		db.Close()
		return "", "", nil, err
	}
	public = pub.Addr().String()
	// Stopping it stops what runs beside it too, also when the demo stops
	// early.
	ctx, cancel := context.WithCancel(ctx)
	reg := registry.New(registry.Config{Store: store, DB: db, Auth: &registry.ServerAuth{URL: serverURL, Secret: secret},
		PublicURL: "http://" + public, Log: log})
	// What happens in it goes to the server's audit log.
	events := registry.NewForwarder(serverURL, secret, log)
	db.SetOnEvent(events.Hand)
	go events.Run(ctx)
	servers := []*http.Server{
		{Handler: reg.Public(), ReadHeaderTimeout: 10 * time.Second},
		{Handler: reg.Admin(secret), ReadHeaderTimeout: 10 * time.Second},
	}
	go servers[0].Serve(pub)
	go servers[1].Serve(adm)
	reg.Start(ctx)
	// Something in the jobs' history from the start.
	for _, job := range []struct {
		kind string
		dry  bool
	}{{registry.JobVerify, false}, {registry.JobGC, true}} {
		if _, err := reg.StartJob(job.kind, job.dry, "ayse"); err != nil {
			log.Warn("demo registry: a first job", "err", err)
		}
	}
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := db.Flush(); err != nil {
					log.Warn("demo registry: writing pull counts", "err", err)
				}
			}
		}
	}()
	stop = func() {
		cancel()
		for _, s := range servers {
			s.Close()
		}
		<-flushed
		if err := db.Close(); err != nil {
			log.Warn("demo registry: closing its metadata", "err", err)
		}
	}
	return "http://" + adm.Addr().String(), public, stop, nil
}

// seeder lets the demo push as whoever it says, an operator of every
// project.
type seeder struct{}

func (seeder) Authorize(_ context.Context, user, _ string, projects []string) (registry.Identity, error) {
	roles := map[string]auth.Role{}
	for _, p := range projects {
		roles[p] = auth.Operator
	}
	return registry.Identity{Subject: user, Roles: roles}, nil
}

// seedClient pushes through the registry's handlers, as a client does.
type seedClient struct {
	h    http.Handler
	user string
}

func (c *seedClient) do(method, path, token string, body []byte, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec
}

func (c *seedClient) token(repo string) (string, error) {
	req := httptest.NewRequest("GET", "/token?service=kartal-registry&scope="+url.QueryEscape("repository:"+repo+":pull,push"), nil)
	req.SetBasicAuth(c.user, "demo")
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	var out struct {
		Token string `json:"token"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Token == "" {
		return "", fmt.Errorf("a token for %s: %d %s", repo, rec.Code, rec.Body)
	}
	return out.Token, nil
}

// blob pushes a blob, and answers its descriptor.
func (c *seedClient) blob(repo, mediaType string, b []byte) (manifest.Descriptor, error) {
	tok, err := c.token(repo)
	if err != nil {
		return manifest.Descriptor{}, err
	}
	d := blobstore.Digest(b)
	if rec := c.do("POST", "/v2/"+repo+"/blobs/uploads/?digest="+url.QueryEscape(d), tok, b, "application/octet-stream"); rec.Code != http.StatusCreated {
		return manifest.Descriptor{}, fmt.Errorf("pushing a blob to %s: %d %s", repo, rec.Code, rec.Body)
	}
	return manifest.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(b))}, nil
}

// ociManifest is a manifest or an index as the demo writes them.
type ociManifest struct {
	SchemaVersion int                   `json:"schemaVersion"`
	MediaType     string                `json:"mediaType"`
	ArtifactType  string                `json:"artifactType,omitempty"`
	Config        *manifest.Descriptor  `json:"config,omitempty"`
	Layers        []manifest.Descriptor `json:"layers,omitempty"`
	Manifests     []manifest.Descriptor `json:"manifests,omitempty"`
	Subject       *manifest.Descriptor  `json:"subject,omitempty"`
	Annotations   map[string]string     `json:"annotations,omitempty"`
}

// manifest pushes a manifest under a tag, or by its digest when the tag is
// empty, and answers its descriptor.
func (c *seedClient) manifest(repo, tag string, m ociManifest) (manifest.Descriptor, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return manifest.Descriptor{}, err
	}
	d := manifest.Descriptor{MediaType: m.MediaType, Digest: blobstore.Digest(b), Size: int64(len(b))}
	ref := tag
	if ref == "" {
		ref = d.Digest
	}
	tok, err := c.token(repo)
	if err != nil {
		return manifest.Descriptor{}, err
	}
	if rec := c.do("PUT", "/v2/"+repo+"/manifests/"+ref, tok, b, m.MediaType); rec.Code != http.StatusCreated {
		return manifest.Descriptor{}, fmt.Errorf("pushing %s:%s: %d %s", repo, ref, rec.Code, rec.Body)
	}
	return d, nil
}

// step is a step of an image's build, and the files it added, if any.
// Steps that are not an app's own make the same layer in every image,
// which the images share, as they would share a base image's.
type step struct {
	by    string
	files map[string]int // name: size
	own   bool
}

// sharedAt is when the layers images share were made.
var sharedAt = time.Date(2024, 9, 6, 0, 0, 0, 0, time.UTC)

// layer makes a real gzipped tar of made-up files, so the images can be
// pulled: it answers the layer and its digest uncompressed.
func layer(rnd *mrand.Rand, files map[string]int, at time.Time) ([]byte, string, error) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, size := range files {
		b := make([]byte, size)
		rnd.Read(b)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(size), ModTime: at, Typeflag: tar.TypeReg}); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return gz.Bytes(), blobstore.Digest(raw.Bytes()), nil
}

// image pushes an image built in steps.
func (c *seedClient) image(rnd *mrand.Rand, repo, tag, arch string, created time.Time, labels map[string]string, steps []step) (manifest.Descriptor, error) {
	var layers []manifest.Descriptor
	var history []manifest.History
	diffIDs := []string{}
	for _, s := range steps {
		h := manifest.History{CreatedBy: s.by, Created: &created}
		if s.files == nil {
			h.EmptyLayer = true
		} else {
			seed := fnv.New64a()
			seed.Write([]byte(s.by))
			b, diffID, err := layer(mrand.New(mrand.NewSource(int64(seed.Sum64()))), s.files, sharedAt)
			if s.own {
				b, diffID, err = layer(rnd, s.files, created)
			}
			if err != nil {
				return manifest.Descriptor{}, err
			}
			d, err := c.blob(repo, ociLayer, b)
			if err != nil {
				return manifest.Descriptor{}, err
			}
			layers = append(layers, d)
			diffIDs = append(diffIDs, diffID)
		}
		history = append(history, h)
	}
	cfg, err := json.Marshal(map[string]any{
		"architecture": arch, "os": "linux", "created": created,
		"config":  map[string]any{"Labels": labels},
		"history": history, "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	if err != nil {
		return manifest.Descriptor{}, err
	}
	cd, err := c.blob(repo, ociConfig, cfg)
	if err != nil {
		return manifest.Descriptor{}, err
	}
	return c.manifest(repo, tag, ociManifest{SchemaVersion: 2, MediaType: manifest.OCIManifest, Config: &cd, Layers: layers})
}

// about pushes an artifact about another one: a signature or an SBOM.
func (c *seedClient) about(repo string, subject manifest.Descriptor, artifactType string, content []byte) error {
	empty, err := c.blob(repo, manifest.OCIEmpty, []byte("{}"))
	if err != nil {
		return err
	}
	body, err := c.blob(repo, artifactType, content)
	if err != nil {
		return err
	}
	_, err = c.manifest(repo, "", ociManifest{SchemaVersion: 2, MediaType: manifest.OCIManifest, ArtifactType: artifactType,
		Config: &empty, Layers: []manifest.Descriptor{body}, Subject: &subject})
	return err
}

// seedRegistry fills the registry: a public project of base images, and a
// team's project with its app's builds, a signature, an SBOM and a Helm
// chart, pushed over the last months and pulled since.
func seedRegistry(store blobstore.Store, db *meta.DB, log *slog.Logger) error {
	now := time.Now().UTC().Truncate(time.Minute)
	at := now
	db.SetClock(func() time.Time { return at })
	defer db.SetClock(time.Now)
	ago := func(days float64) time.Time {
		at = now.Add(-time.Duration(days * float64(24*time.Hour)))
		return at
	}
	h := registry.New(registry.Config{Store: store, DB: db, Auth: seeder{}, Log: log}).Public()
	admin := &seedClient{h: h, user: "ayse"}
	ci := &seedClient{h: h, user: "robot$ci"}
	rnd := mrand.New(mrand.NewSource(42))
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	ago(120)
	check(db.CreateProject(meta.Project{Name: "library", Public: true, Description: "Base images anyone may pull"}, "ayse"))
	ago(90)
	check(db.CreateProject(meta.Project{Name: "team-0", Description: "The web team's images and charts",
		// Released versions stay as they were pushed.
		Immutable: []string{"[0-9]*"}, Quota: 2 << 30}, "ayse"))

	// A multi-arch base image.
	base := func(arch string) []step {
		return []step{{by: "ADD alpine-minirootfs-3.20.3-" + arch + ".tar.gz /", files: map[string]int{"lib/ld-musl-" + arch + ".so.1": 1_100_000 + len(arch)}},
			{by: `CMD ["/bin/sh"]`}}
	}
	ago(60)
	amd, err := admin.image(rnd, "library/alpine", "", "amd64", at, nil, base("amd64"))
	check(err)
	arm, err := admin.image(rnd, "library/alpine", "", "arm64", at, nil, base("arm64"))
	check(err)
	amd.Platform = &manifest.Platform{OS: "linux", Architecture: "amd64"}
	arm.Platform = &manifest.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	alpine, err := admin.manifest("library/alpine", "3.20", ociManifest{SchemaVersion: 2, MediaType: manifest.OCIIndex, Manifests: []manifest.Descriptor{amd, arm}})
	check(err)
	check(db.Tag("library/alpine", "3", alpine.Digest, "ayse"))

	nginx := func(version string) []step {
		return []step{
			{by: "ADD debian-bookworm-slim.tar.gz /", files: map[string]int{"usr/lib/x86_64-linux-gnu/libc.so.6": 1_600_000}},
			{by: "RUN apt-get install -y nginx=" + version, files: map[string]int{"usr/sbin/nginx": 1_200_000 + len(version)*1000}},
			{by: "COPY dist /usr/share/nginx/html", files: map[string]int{"usr/share/nginx/html/index.html": 2_000}, own: true},
			{by: "EXPOSE 80/tcp"}, {by: `CMD ["nginx", "-g", "daemon off;"]`},
		}
	}
	ago(75)
	n126, err := admin.image(rnd, "library/nginx", "1.26", "amd64", at, map[string]string{"org.opencontainers.image.version": "1.26.2"}, nginx("1.26.2"))
	check(err)
	ago(20)
	n127, err := admin.image(rnd, "library/nginx", "1.27", "amd64", at, map[string]string{"org.opencontainers.image.version": "1.27.3"}, nginx("1.27.3"))
	check(err)
	check(db.Tag("library/nginx", "latest", n127.Digest, "ayse"))

	// The web team's app: a build of every release, by its CI's robot.
	web := func(days float64, tag, revision string) manifest.Descriptor {
		created := ago(days)
		d, err := ci.image(rnd, "team-0/web", tag, "amd64", created, map[string]string{
			"org.opencontainers.image.source":   "https://github.com/example/web",
			"org.opencontainers.image.revision": revision,
			"org.opencontainers.image.version":  tag,
			"org.opencontainers.image.title":    "web",
		}, []step{
			base("amd64")[0],
			{by: "RUN apk add --no-cache ca-certificates tzdata", files: map[string]int{"etc/ssl/certs/ca-certificates.crt": 220_000, "usr/share/zoneinfo/Europe/Istanbul": 1_200}},
			{by: "COPY web /usr/local/bin/web", files: map[string]int{"usr/local/bin/web": 2_400_000 + int(days)*1000}, own: true},
			{by: "USER 65532:65532"},
			{by: `ENTRYPOINT ["/usr/local/bin/web"]`},
		})
		check(err)
		return d
	}
	v130 := web(200, "1.3.0", "4f1c2a9e0b7d3c5a8e6f1b2d9c0a7e3f5b8d1c4a")
	v140 := web(45, "1.4.0", "9a7e3c1f5b2d8e0a4c6f9b1d3e5a7c2f0b8d6e4a")
	earlier := web(30, "latest", "c3e5a7f9b1d2e4f6a8c0b2d4e6f8a1c3e5b7d9f0")
	v141 := web(12, "1.4.1", "e1f3a5c7b9d2f4e6a8c1b3d5f7e9a2c4b6d8f0e2")
	// latest moved to 1.4.1; the main branch's earlier build is untagged now.
	check(db.Tag("team-0/web", "latest", v141.Digest, "robot$ci"))
	ago(11.9)
	check(ci.about("team-0/web", v141, "application/vnd.dev.sigstore.bundle.v0.3+json",
		[]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{}}`)))
	check(ci.about("team-0/web", v141, "application/spdx+json",
		[]byte(`{"spdxVersion":"SPDX-2.3","name":"web","packages":[{"name":"ca-certificates"},{"name":"tzdata"}]}`)))
	web(2, "1.5.0-rc1", "07b9d1f3e5a7c9b2d4f6e8a0c3e5b7d9f1a2c4e6")

	// The app's Helm chart.
	ago(12)
	cfg, err := ci.blob("team-0/charts/web", "application/vnd.cncf.helm.config.v1+json",
		[]byte(`{"name":"web","version":"0.4.1","apiVersion":"v2","appVersion":"1.4.1","description":"The web team's app"}`))
	check(err)
	chart, _, err := layer(rnd, map[string]int{"web/Chart.yaml": 180, "web/templates/deployment.yaml": 1_400}, at)
	check(err)
	content, err := ci.blob("team-0/charts/web", "application/vnd.cncf.helm.chart.content.v1.tar+gzip", chart)
	check(err)
	_, err = ci.manifest("team-0/charts/web", "0.4.1", ociManifest{SchemaVersion: 2, MediaType: manifest.OCIManifest, Config: &cfg,
		Layers: []manifest.Descriptor{content}})
	check(err)

	// Pulls since, n of them from first to last days ago: the nodes pull
	// what runs.
	pulls := func(repo string, d manifest.Descriptor, n int, first, last float64) {
		for i := 0; i < n; i++ {
			ago(first - (first-last)*float64(i)/float64(n-1))
			db.RecordPull(repo, d.Digest)
		}
	}
	pulls("library/alpine", alpine, 40, 59, 0.2)
	pulls("library/nginx", n126, 25, 74, 21)
	pulls("library/nginx", n127, 60, 19.9, 0.05)
	pulls("team-0/web", v130, 20, 199, 150)
	pulls("team-0/web", v140, 30, 44, 12.1)
	pulls("team-0/web", earlier, 18, 29.9, 12.5)
	pulls("team-0/web", v141, 96, 11.9, 0.01)
	check(db.Flush())
	return errors.Join(errs...)
}
