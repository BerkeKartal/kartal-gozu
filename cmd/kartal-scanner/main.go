// Command kartal-scanner scans the registry's images for known
// vulnerabilities with Trivy, which runs next to it in the same container
// (see Dockerfile.scanner). The registry calls its API (KARTAL_SCANNER_LISTEN,
// :8090) with a secret both share (KARTAL_SCANNER_SECRET or _FILE), and gives
// it short-lived credentials to pull each image with.
//
// Trivy's vulnerability databases come from Trivy's own repositories, or
// from a mirror (KARTAL_SCANNER_DB_REPOSITORY, KARTAL_SCANNER_JAVA_DB_REPOSITORY)
// such as one the registry keeps where the internet is out of reach.
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
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/config"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

var version = "dev"

func main() {
	log := logging.New(config.String("KARTAL_LOG_LEVEL", "info"))
	if err := run(log); err != nil {
		log.Error("scanner stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	secret, err := config.Secret("KARTAL_SCANNER_SECRET")
	if err != nil {
		return err
	}
	if len(secret) < auth.MinTokenLength {
		return fmt.Errorf("KARTAL_SCANNER_SECRET must be at least %d characters; it is shared with the registry", auth.MinTokenLength)
	}
	timeout, err := config.Duration("KARTAL_SCANNER_TIMEOUT", 15*time.Minute)
	if err != nil {
		return err
	}
	workers, err := config.Number("KARTAL_SCANNER_WORKERS", 2, 1, 16)
	if err != nil {
		return err
	}
	offline, err := config.Bool("KARTAL_SCANNER_OFFLINE", false)
	if err != nil {
		return err
	}
	svc := scanner.New(scanner.Config{
		Trivy:            config.String("KARTAL_SCANNER_TRIVY", "trivy"),
		CacheDir:         config.String("KARTAL_SCANNER_CACHE_DIR", "/var/cache/trivy"),
		Secret:           secret,
		Workers:          int(workers),
		Timeout:          timeout,
		DBRepository:     config.String("KARTAL_SCANNER_DB_REPOSITORY", ""),
		JavaDBRepository: config.String("KARTAL_SCANNER_JAVA_DB_REPOSITORY", ""),
		Offline:          offline,
		Log:              log,
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// A Trivy that is not there, or is a known malicious build, stops it
	// before it takes any credentials.
	check, cancel := context.WithTimeout(ctx, time.Minute)
	st, err := svc.Status(check)
	cancel()
	if err != nil {
		return err
	}
	// A scanner without databases gets them now, rather than on its first
	// scan.
	if st.DB == nil {
		go func() {
			if err := svc.UpdateDB(ctx); err != nil {
				log.Warn("getting the vulnerability databases", "err", err)
			}
		}()
	}

	srv := &http.Server{
		Addr:              config.String("KARTAL_SCANNER_LISTEN", ":8090"),
		Handler:           logging.Requests(log, svc.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		// A scan takes as long as it takes, up to its timeout.
		IdleTimeout: 2 * time.Minute,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("kartal-scanner started", "version", version, "trivy", st.Scanner, "listen", srv.Addr, "workers", int(workers))
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelShutdown()
	return srv.Shutdown(shutdown)
}
