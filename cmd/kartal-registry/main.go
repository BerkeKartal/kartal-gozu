// Command kartal-registry is Kartal Gözü's image registry: the OCI
// Distribution API at a host's root (KARTAL_REGISTRY_LISTEN, :5000), and
// the API kartal-server manages it with (KARTAL_REGISTRY_ADMIN_LISTEN,
// :5001, to be reached from inside the cluster only). Both sides share a
// secret (KARTAL_REGISTRY_SECRET or _FILE): the registry asks kartal-server
// who signs in (KARTAL_SERVER_URL), and kartal-server calls the admin API.
//
// With a scanner (KARTAL_REGISTRY_SCANNER_URL, such as
// http://kartal-scanner:8090, and KARTAL_REGISTRY_SCANNER_SECRET or _FILE),
// images are scanned for known vulnerabilities; the scanner pulls them from
// KARTAL_REGISTRY_SCAN_ADDRESS (such as http://kartal-registry:5000), or else
// KARTAL_REGISTRY_PUBLIC_URL.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/config"
	"github.com/BerkeKartal/kartal-gozu/internal/cron"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
	"github.com/BerkeKartal/kartal-gozu/internal/registry"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

var version = "dev"

func main() {
	log := logging.New(config.String("KARTAL_LOG_LEVEL", "info"))
	if err := run(log); err != nil {
		log.Error("registry stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	secret, err := config.Secret("KARTAL_REGISTRY_SECRET")
	if err != nil {
		return err
	}
	if len(secret) < auth.MinTokenLength {
		return fmt.Errorf("KARTAL_REGISTRY_SECRET must be at least %d characters; it is shared with kartal-server", auth.MinTokenLength)
	}
	serverURL := config.String("KARTAL_SERVER_URL", "")
	if serverURL == "" {
		return errors.New("KARTAL_SERVER_URL is needed: kartal-server says who may sign in")
	}
	dir := config.String("KARTAL_REGISTRY_DATA_DIR", "/var/lib/kartal-registry")
	store, err := blobstore.NewFile(filepath.Join(dir, "store"))
	if err != nil {
		return fmt.Errorf("the blob store: %w", err)
	}
	db, err := meta.Open(filepath.Join(dir, "meta"))
	if err != nil {
		return fmt.Errorf("the metadata: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Warn("closing the metadata", "err", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The jobs' schedules are read in this time zone.
	zone, err := cron.Zone(config.String("KARTAL_REGISTRY_TIMEZONE", cron.DefaultZone))
	if err != nil {
		return fmt.Errorf("KARTAL_REGISTRY_TIMEZONE: %w", err)
	}
	events := registry.NewForwarder(serverURL, secret, log)
	db.SetOnEvent(events.Hand)
	go events.Run(ctx)
	// The server says who signs in, and what runs in the clusters.
	// The sources' passwords are sealed with a key of their own, or else
	// one made of the shared secret.
	sourcesKey, err := config.Secret("KARTAL_REGISTRY_SOURCES_KEY")
	if err != nil {
		return err
	}
	if sourcesKey == "" {
		sourcesKey = secret
	}
	server := &registry.ServerAuth{URL: serverURL, Secret: secret}
	cfg := registry.Config{
		Store: store, DB: db, Log: log, Zone: zone, Auth: server, Running: server, SourcesKey: registry.SourcesKey(sourcesKey),
		PublicURL: config.String("KARTAL_REGISTRY_PUBLIC_URL", ""),
		// S3 stores keep the uploads under way on the data volume.
		StagingDir: filepath.Join(dir, "staging"),
	}
	// The scanner, when there is one.
	if scannerURL := config.String("KARTAL_REGISTRY_SCANNER_URL", ""); scannerURL != "" {
		scannerSecret, err := config.Secret("KARTAL_REGISTRY_SCANNER_SECRET")
		if err != nil {
			return err
		}
		if len(scannerSecret) < auth.MinTokenLength {
			return fmt.Errorf("KARTAL_REGISTRY_SCANNER_SECRET must be at least %d characters; it is the scanner's KARTAL_SCANNER_SECRET", auth.MinTokenLength)
		}
		workers, err := config.Number("KARTAL_REGISTRY_SCAN_WORKERS", 2, 1, 16)
		if err != nil {
			return err
		}
		cfg.Scanner = &scanner.Client{URL: scannerURL, Secret: scannerSecret}
		cfg.ScanDir = filepath.Join(dir, "scans")
		cfg.ScanAddress = config.String("KARTAL_REGISTRY_SCAN_ADDRESS", "")
		cfg.ScanWorkers = int(workers)
		if cfg.ScanAddress == "" && cfg.PublicURL == "" {
			return errors.New("the scanner pulls from KARTAL_REGISTRY_SCAN_ADDRESS (such as http://kartal-registry:5000) or KARTAL_REGISTRY_PUBLIC_URL; set one")
		}
	}
	reg := registry.New(cfg)
	// Garbage collection and the blobs' checks, on their schedules.
	reg.Start(ctx)
	// Pull counts are written every half minute.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := db.Flush(); err != nil {
					log.Warn("writing pull counts", "err", err)
				}
			}
		}
	}()

	public := &http.Server{
		Addr:              config.String("KARTAL_REGISTRY_LISTEN", ":5000"),
		Handler:           logging.Requests(log, reg.Public()),
		ReadHeaderTimeout: 30 * time.Second,
		// Layers take as long as they take; only an idle connection ends.
		IdleTimeout: 2 * time.Minute,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	admin := &http.Server{
		Addr:              config.String("KARTAL_REGISTRY_ADMIN_LISTEN", ":5001"),
		Handler:           logging.Requests(log, reg.Admin(secret)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 2)
	go func() { errc <- public.ListenAndServe() }()
	go func() { errc <- admin.ListenAndServe() }()
	log.Info("kartal-registry started", "version", version, "listen", public.Addr, "admin", admin.Addr, "data", dir, "server", serverURL,
		"scanner", cfg.Scanner != nil)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	public.Shutdown(shutdown)
	admin.Shutdown(shutdown)
	return nil
}
