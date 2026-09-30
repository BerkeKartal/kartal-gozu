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

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/api"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/config"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
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
	rawUsers, err := config.Secret("KARTAL_USERS")
	if err != nil {
		return err
	}
	users, err := auth.ParseUsers(rawUsers)
	if err != nil {
		return fmt.Errorf("KARTAL_USERS: %w", err)
	}
	if adminToken != "" && len(adminToken) < auth.MinTokenLength {
		return fmt.Errorf("KARTAL_ADMIN_TOKEN is shorter than %d characters", auth.MinTokenLength)
	}
	anonymous, err := config.Bool("KARTAL_ALLOW_ANONYMOUS", false)
	if err != nil {
		return err
	}
	if adminToken == "" && len(users) == 0 && !anonymous {
		return errors.New("set KARTAL_USERS or KARTAL_ADMIN_TOKEN (or KARTAL_ALLOW_ANONYMOUS=true for local testing)")
	}
	alerts, mail, err := notifications(log)
	if err != nil {
		return err
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
		Users:          users,
		AdminToken:     adminToken,
		StaleAfter:     staleAfter,
		MaxPollWait:    pollWait,
		CommandTimeout: cmdTimeout,
		Alerts:         alerts,
		Mail:           mail,
	}
	server := api.New(cfg, store.New(clusters...), log)
	handler := logging.Requests(log, server)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go server.Watch(ctx)

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
	log.Info("kartal-server started", "version", version, "addr", srv.Addr, "clusters", clusters,
		"users", len(users)+min(len(adminToken), 1), "notification_channels", alerts.Channels(), "settings", mail.View().Where)

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

// notifications sets up the alert manager and its channels: Teams and
// webhooks from the environment, and e-mail from the environment or else
// from the settings admins make in the UI.
func notifications(log *slog.Logger) (*alert.Manager, *settings.Mail, error) {
	after, err := config.Duration("KARTAL_ALERT_AFTER", 2*time.Minute)
	if err != nil {
		return nil, nil, err
	}
	// Teams and other webhooks are often reached through an outbound proxy.
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	var notifiers []alert.Notifier
	if u := config.String("KARTAL_ALERT_TEAMS_URL", ""); u != "" {
		notifiers = append(notifiers, alert.Teams{URL: u, Client: client})
	}
	if u := config.String("KARTAL_ALERT_WEBHOOK_URL", ""); u != "" {
		notifiers = append(notifiers, alert.Webhook{URL: u, Client: client})
	}
	var env *settings.Email
	if addr := config.String("KARTAL_SMTP_ADDR", ""); addr != "" {
		password, err := config.Secret("KARTAL_SMTP_PASSWORD")
		if err != nil {
			return nil, nil, err
		}
		env = &settings.Email{
			Enabled:  true,
			Addr:     addr,
			From:     config.String("KARTAL_SMTP_FROM", ""),
			To:       config.List("KARTAL_SMTP_TO"),
			Username: config.String("KARTAL_SMTP_USERNAME", ""),
			Password: password,
		}
		if err := env.Check(); err != nil {
			return nil, nil, fmt.Errorf("KARTAL_SMTP_*: %w", err)
		}
	}
	st, err := settingsStore()
	if err != nil {
		return nil, nil, err
	}
	email := alert.NewSwitchable("email")
	m := alert.NewManager(after, log, append(notifiers, email)...)
	m.PublicURL = config.String("KARTAL_PUBLIC_URL", "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return m, settings.NewMail(ctx, st, email, env, log), nil
}

// settingsStore picks where the settings made in the UI are kept: a Secret
// next to the server, a file, or, with neither, memory until a restart.
func settingsStore() (settings.Store, error) {
	secret := config.String("KARTAL_SETTINGS_SECRET", "")
	file := config.String("KARTAL_SETTINGS_FILE", "")
	switch {
	case secret != "" && file != "":
		return nil, errors.New("set only one of KARTAL_SETTINGS_SECRET and KARTAL_SETTINGS_FILE")
	case secret != "":
		kc, err := kube.InCluster()
		if err != nil {
			return nil, fmt.Errorf("KARTAL_SETTINGS_SECRET needs the server to run in Kubernetes: %w", err)
		}
		ns, err := kube.InClusterNamespace()
		if err != nil {
			return nil, err
		}
		return settings.Secret{Kube: kc, Namespace: ns, Name: secret}, nil
	case file != "":
		return settings.File{Path: file}, nil
	}
	return settings.Memory{}, nil
}
