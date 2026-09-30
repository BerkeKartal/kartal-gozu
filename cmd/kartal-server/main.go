// Command kartal-server receives snapshots from agents and serves the API.
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

	"github.com/BerkeKartal/kartal-gozu/internal/api"
	"github.com/BerkeKartal/kartal-gozu/internal/config"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
)

var version = "dev"

func main() {
	log := logging.New(config.String("KARTAL_LOG_LEVEL", "info"))
	if err := run(log); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	rawTokens, err := config.Secret("KARTAL_AGENT_TOKENS")
	if err != nil {
		return err
	}
	tokens, clusters, err := config.AgentTokens(rawTokens)
	if err != nil {
		return err
	}
	if len(clusters) == 0 {
		return errors.New("KARTAL_AGENT_TOKENS is empty: define at least one cluster=token entry")
	}
	adminToken, err := config.Secret("KARTAL_ADMIN_TOKEN")
	if err != nil {
		return err
	}
	anonymous, err := config.Bool("KARTAL_ALLOW_ANONYMOUS", false)
	if err != nil {
		return err
	}
	if adminToken == "" && !anonymous {
		return errors.New("KARTAL_ADMIN_TOKEN is required (or set KARTAL_ALLOW_ANONYMOUS=true for local testing)")
	}
	staleAfter, err := config.Duration("KARTAL_STALE_AFTER", time.Minute)
	if err != nil {
		return err
	}
	pollWait, err := config.Duration("KARTAL_MAX_POLL_WAIT", 25*time.Second)
	if err != nil {
		return err
	}
	cmdTimeout, err := config.Duration("KARTAL_COMMAND_TIMEOUT", 20*time.Second)
	if err != nil {
		return err
	}

	cfg := api.Config{
		AgentTokens:    tokens,
		AdminToken:     adminToken,
		StaleAfter:     staleAfter,
		MaxPollWait:    pollWait,
		CommandTimeout: cmdTimeout,
	}
	handler := logging.Requests(log, api.New(cfg, store.New(clusters...), log))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              config.String("KARTAL_LISTEN", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		// Long-polls and command round trips must fit inside the write timeout.
		WriteTimeout: pollWait + cmdTimeout + 15*time.Second,
		IdleTimeout:  2 * time.Minute,
		// Cancelling request contexts on shutdown releases held long-polls at once.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("kartal-server started", "version", version, "addr", srv.Addr, "clusters", clusters, "admin_auth", adminToken != "")

	select {
	case err := <-errc:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
