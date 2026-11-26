package main

import (
	"context"
	"errors"
	"log/slog"
	mrand "math/rand"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// The demo has an old registry to move from, as one would a Harbor: a
// registry of the Distribution API with two projects, which its own
// registry has as a source. Its user is mirror, its password
// mirror-password.

const (
	upstreamUser     = "mirror"
	upstreamPassword = "mirror-password"
	upstreamSource   = "Old registry"
)

// mirror signs in the old registry's one user.
type mirror struct{}

func (mirror) Authorize(_ context.Context, user, secret string, projects []string) (registry.Identity, error) {
	if user != upstreamUser || secret != upstreamPassword {
		return registry.Identity{}, registry.ErrBadCredentials
	}
	roles := map[string]auth.Role{}
	for _, p := range projects {
		roles[p] = auth.Operator
	}
	return registry.Identity{Subject: user, Roles: roles}, nil
}

// demoUpstream starts the old registry, filling it the first time, and
// answers where it is.
func demoUpstream(ctx context.Context, dir string, log *slog.Logger) (string, func(), error) {
	store, err := blobstore.NewFile(filepath.Join(dir, "store"))
	if err != nil {
		return "", nil, err
	}
	db, err := meta.Open(filepath.Join(dir, "meta"))
	if err != nil {
		return "", nil, err
	}
	if len(db.Projects()) == 0 {
		if err := seedUpstream(store, db, log); err != nil {
			db.Close()
			return "", nil, err
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		db.Close()
		return "", nil, err
	}
	srv := &http.Server{Handler: registry.New(registry.Config{Store: store, DB: db, Auth: mirror{}, Log: log}).Public(),
		ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	stop := func() {
		srv.Close()
		db.Close()
	}
	return "http://" + ln.Addr().String(), stop, nil
}

// seedUpstream fills the old registry: a team's services, and the tools
// everyone pulls.
func seedUpstream(store blobstore.Store, db *meta.DB, log *slog.Logger) error {
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	check(db.CreateProject(meta.Project{Name: "legacy-shop"}, "admin"))
	check(db.CreateProject(meta.Project{Name: "legacy-tools", Public: true}, "admin"))
	c := &seedClient{h: registry.New(registry.Config{Store: store, DB: db, Auth: seeder{}, Log: log}).Public(), user: "jenkins"}
	rnd := mrand.New(mrand.NewSource(7))
	at := time.Now().Add(-400 * 24 * time.Hour)
	base := step{by: "ADD debian-bullseye-slim.tar.gz /", files: map[string]int{"lib/x86_64-linux-gnu/libc.so.6": 900_000}}
	for i, v := range []string{"2.3.0", "2.4.0", "2.4.1"} {
		_, err := c.image(rnd, "legacy-shop/storefront", v, "amd64", at.Add(time.Duration(i)*30*24*time.Hour), map[string]string{"org.opencontainers.image.version": v},
			[]step{base, {by: "COPY storefront /app/storefront", files: map[string]int{"app/storefront": 600_000 + i*1000}, own: true}, {by: `CMD ["/app/storefront"]`}})
		check(err)
	}
	_, err := c.image(rnd, "legacy-shop/billing", "1.9.2", "amd64", at, nil,
		[]step{base, {by: "COPY billing /app/billing", files: map[string]int{"app/billing": 500_000}, own: true}, {by: `CMD ["/app/billing"]`}})
	check(err)
	var children []manifest.Descriptor
	for _, arch := range []string{"amd64", "arm64"} {
		d, err := c.image(rnd, "legacy-tools/busybox", "", arch, at, nil,
			[]step{{by: "ADD busybox-" + arch + ".tar /", files: map[string]int{"bin/busybox": 300_000 + len(arch)}}, {by: `CMD ["sh"]`}})
		check(err)
		d.Platform = &manifest.Platform{OS: "linux", Architecture: arch}
		children = append(children, d)
	}
	_, err = c.manifest("legacy-tools/busybox", "1.36", ociManifest{SchemaVersion: 2, MediaType: manifest.OCIIndex, Manifests: children})
	check(err)
	return errors.Join(errs...)
}

// upstreamSourceFor has the demo's registry know the old one as a source,
// at the address it has this time.
func upstreamSourceFor(reg *registry.Server, db *meta.DB, url string) error {
	pw := upstreamPassword
	for _, src := range db.Sources() {
		if src.Name == upstreamSource {
			src.URL = url
			return db.PutSource(src, "")
		}
	}
	_, err := reg.AddSource(registry.SourceInput{Name: upstreamSource, Kind: "registry", URL: url, Username: upstreamUser, Password: &pw}, "ayse")
	return err
}
