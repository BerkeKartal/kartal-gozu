// Command kartal-server receives snapshots from agents and serves the API.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/accounts"
	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/api"
	"github.com/BerkeKartal/kartal-gozu/internal/appmetrics"
	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/collect"
	"github.com/BerkeKartal/kartal-gozu/internal/config"
	"github.com/BerkeKartal/kartal-gozu/internal/dashboard"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/ldap"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/sizing"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
	"github.com/BerkeKartal/kartal-gozu/internal/uptime"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if err := hashPassword(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
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
	users, passwords, err := auth.ParseUsers(rawUsers)
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
	directory, err := directoryLogin(log)
	if err != nil {
		return err
	}
	sessionTTL, err := config.Duration("KARTAL_SESSION_TTL", 12*time.Hour)
	if err != nil {
		return err
	}
	if adminToken == "" && len(users) == 0 && passwords.Len() == 0 && directory == nil && !anonymous {
		return errors.New("set KARTAL_LDAP_URL, KARTAL_USERS or KARTAL_ADMIN_TOKEN (or KARTAL_ALLOW_ANONYMOUS=true for local testing)")
	}
	alerts, err := notifications(log)
	if err != nil {
		return err
	}
	st, err := settingsStore()
	if err != nil {
		return err
	}
	// Settings admins make in the UI: the e-mail channel (unless the
	// environment sets it), the URL checks and the watched metrics.
	loadCtx, cancelLoad := context.WithTimeout(context.Background(), 15*time.Second)
	keeper := settings.NewKeeper(loadCtx, st, log)
	cancelLoad()
	env, err := emailFromEnv()
	if err != nil {
		return err
	}
	mail := settings.NewMail(keeper, alerts.Email, env)
	checks := uptime.New(keeper, alerts.Manager, log)
	watches := appmetrics.New(keeper, alerts.Manager, log)
	collector, err := metricStore(keeper, log)
	if err != nil {
		return err
	}
	// What each workload used, day by day, for the requests and limits
	// suggested: next to the metric store, or in memory without one.
	usage := sizing.New()
	if dir := config.String("KARTAL_DATA_DIR", ""); dir != "" {
		if usage, err = sizing.Open(filepath.Join(dir, "sizing.json")); err != nil {
			log.Warn("the workloads' usage could not be read; it starts over", "err", err)
		}
	}
	keeper.OnLoad(mail.Reload)
	keeper.OnLoad(checks.Reload)
	// The users the server was started with, whose names the users admins
	// add in the UI cannot take.
	var fixed []auth.User
	for _, u := range users {
		fixed = append(fixed, u)
	}
	fixed = append(fixed, passwords.Users()...)
	if adminToken != "" {
		fixed = append(fixed, auth.User{Name: "admin", Role: auth.Admin})
	}
	// Admins add users in the UI, unless the server lets everyone in
	// without signing in.
	var accts *accounts.Manager
	if len(fixed) > 0 || directory != nil {
		accts = accounts.New(keeper, fixed)
	}
	// The groups of the admin panel give their grants to directory users
	// too: by name, or by the directory groups mapped to them.
	if directory != nil && accts != nil {
		directory.Extra = accts.GroupGrants
	}
	// Passwords of KARTAL_USERS first, then the UI's users, then the
	// directory.
	var login auth.Chain
	if passwords.Len() > 0 {
		if accts != nil {
			login = append(login, accts.WithGroups(passwords))
		} else {
			login = append(login, passwords)
		}
	}
	if accts != nil {
		login = append(login, accts)
	}
	if directory != nil {
		login = append(login, directory)
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
		Alerts:         alerts.Manager,
		Mail:           mail,
		Checks:         checks,
		Watches:        watches,
		Collect:        collector,
		Sizing:         usage,
		DataSources:    datasource.NewManager(keeper),
		Dashboards:     dashboard.New(keeper),
		SessionTTL:     sessionTTL,
	}
	if len(login) > 0 {
		cfg.Login = login
		cfg.Directory = directory != nil
		cfg.FilePasswords = passwords.Len() > 0
	}
	if accts != nil {
		cfg.Accounts = accts
	}
	if directory != nil {
		for _, r := range directory.Rules {
			cfg.DirectoryRules = append(cfg.DirectoryRules, r.Group+" => "+r.Grant.String())
		}
	}
	server := api.New(cfg, store.New(clusters...), log)
	handler := logging.Requests(log, server)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go server.Watch(ctx)
	checks.Start(ctx)
	watches.Start(ctx)
	if collector != nil {
		// Samples still in memory are written every minute, and on the way out.
		go collector.DB().Run(ctx, time.Minute)
		defer collector.DB().Close()
		// Days that earlier versions wrote in chunks of a minute are
		// written again in full ones.
		go func() {
			days, err := collector.DB().Compact()
			if len(days) > 0 {
				log.Info("metric store compacted", "days", days)
			}
			if err != nil {
				log.Warn("compacting the metric store", "err", err)
			}
		}()
		collector.Start(ctx)
	}
	// Settings that could not be read at the start are read again.
	go keeper.Retry(ctx, time.Minute)
	// The workloads' usage is written every ten minutes, and on the way out.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := usage.Save(); err != nil {
					log.Warn("saving the workloads' usage", "err", err)
				}
			}
		}
	}()
	defer func() {
		if err := usage.Save(); err != nil {
			log.Warn("saving the workloads' usage", "err", err)
		}
	}()

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
		"users", len(users)+min(len(adminToken), 1)+passwords.Len(), "ui_users", len(keeper.Get().Users),
		"notification_channels", alerts.Channels(), "settings", keeper.Where(),
		"url_checks", len(keeper.Get().Checks), "metric_store", storeDir(collector))

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

// alerting is the alert manager with its e-mail channel, which the
// settings turn on and off.
type alerting struct {
	*alert.Manager
	Email *alert.Switchable
}

// notifications sets up the alert manager and its channels: Teams and
// webhooks from the environment, and e-mail, whose settings come later.
func notifications(log *slog.Logger) (alerting, error) {
	after, err := config.Duration("KARTAL_ALERT_AFTER", 2*time.Minute)
	if err != nil {
		return alerting{}, err
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
	email := alert.NewSwitchable("email")
	m := alert.NewManager(after, log, append(notifiers, email)...)
	m.PublicURL = config.String("KARTAL_PUBLIC_URL", "")
	if m.VolumeWarning, err = config.Number("KARTAL_ALERT_VOLUME_WARNING", 85, 1, 100); err != nil {
		return alerting{}, err
	}
	if m.VolumeCritical, err = config.Number("KARTAL_ALERT_VOLUME_CRITICAL", 95, 1, 100); err != nil {
		return alerting{}, err
	}
	if m.NodeDiskWarning, err = config.Number("KARTAL_ALERT_NODE_DISK_WARNING", 80, 1, 100); err != nil {
		return alerting{}, err
	}
	if m.NodeDiskCritical, err = config.Number("KARTAL_ALERT_NODE_DISK_CRITICAL", 90, 1, 100); err != nil {
		return alerting{}, err
	}
	warnDays, err := config.Number("KARTAL_ALERT_CERT_WARNING_DAYS", 14, 1, 365)
	if err != nil {
		return alerting{}, err
	}
	critDays, err := config.Number("KARTAL_ALERT_CERT_CRITICAL_DAYS", 3, 1, 365)
	if err != nil {
		return alerting{}, err
	}
	if m.VolumeWarning > m.VolumeCritical || m.NodeDiskWarning > m.NodeDiskCritical || warnDays < critDays {
		return alerting{}, errors.New("KARTAL_ALERT_*: a warning must come before the critical level")
	}
	day := float64(24 * time.Hour)
	m.CertificateWarning, m.CertificateCritical = time.Duration(warnDays*day), time.Duration(critDays*day)
	return alerting{Manager: m, Email: email}, nil
}

// emailFromEnv reads the e-mail channel from KARTAL_SMTP_*, if set; it then
// wins over the settings made in the UI.
func emailFromEnv() (*settings.Email, error) {
	addr := config.String("KARTAL_SMTP_ADDR", "")
	if addr == "" {
		return nil, nil
	}
	password, err := config.Secret("KARTAL_SMTP_PASSWORD")
	if err != nil {
		return nil, err
	}
	env := &settings.Email{
		Enabled:  true,
		Addr:     addr,
		From:     config.String("KARTAL_SMTP_FROM", ""),
		To:       config.List("KARTAL_SMTP_TO"),
		Username: config.String("KARTAL_SMTP_USERNAME", ""),
		Password: password,
	}
	if err := env.Check(); err != nil {
		return nil, fmt.Errorf("KARTAL_SMTP_*: %w", err)
	}
	return env, nil
}

// metricStore opens the metric store in KARTAL_DATA_DIR, with the collector
// that fills it; without the directory there is no store.
func metricStore(keeper *settings.Keeper, log *slog.Logger) (*collect.Collector, error) {
	dir := config.String("KARTAL_DATA_DIR", "")
	if dir == "" {
		return nil, nil
	}
	db, err := tsdb.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("KARTAL_DATA_DIR: %w", err)
	}
	return collect.New(keeper, db, dir, log), nil
}

func storeDir(c *collect.Collector) string {
	if c == nil {
		return "off"
	}
	return c.Dir()
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

// directoryLogin sets up signing in with a directory (Active Directory or
// LDAP) from KARTAL_LDAP_*; nil when KARTAL_LDAP_URL is not set.
func directoryLogin(log *slog.Logger) (*ldap.Authenticator, error) {
	url := config.String("KARTAL_LDAP_URL", "")
	if url == "" {
		return nil, nil
	}
	startTLS, err := config.Bool("KARTAL_LDAP_STARTTLS", false)
	if err != nil {
		return nil, err
	}
	insecure, err := config.Bool("KARTAL_LDAP_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	if file := config.String("KARTAL_LDAP_CA_FILE", ""); file != "" {
		pem, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("KARTAL_LDAP_CA_FILE: %w", err)
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("KARTAL_LDAP_CA_FILE holds no certificate")
		}
	}
	bindPassword, err := config.Secret("KARTAL_LDAP_BIND_PASSWORD")
	if err != nil {
		return nil, err
	}
	rawRules, err := config.Secret("KARTAL_LDAP_GROUPS")
	if err != nil {
		return nil, err
	}
	rules, err := ldap.ParseRules(rawRules)
	if err != nil {
		return nil, fmt.Errorf("KARTAL_LDAP_GROUPS: %w", err)
	}
	nested, err := config.Bool("KARTAL_LDAP_NESTED_GROUPS", false)
	if err != nil {
		return nil, err
	}
	a := &ldap.Authenticator{Rules: rules, Config: ldap.Config{
		URL:          url,
		StartTLS:     startTLS,
		TLS:          tc,
		BindDN:       config.String("KARTAL_LDAP_BIND_DN", ""),
		BindPassword: bindPassword,
		UPNDomain:    config.String("KARTAL_LDAP_UPN_DOMAIN", ""),
		UserBase:     config.String("KARTAL_LDAP_USER_BASE", ""),
		UserAttr:     config.String("KARTAL_LDAP_USER_ATTR", "sAMAccountName"),
		NestedGroups: nested,
		GroupBase:    config.String("KARTAL_LDAP_GROUP_BASE", ""),
	}}
	switch {
	case a.Config.UserBase == "":
		return nil, errors.New("KARTAL_LDAP_URL needs KARTAL_LDAP_USER_BASE, where people are searched for")
	case a.Config.BindDN == "" && a.Config.UPNDomain == "":
		return nil, errors.New("KARTAL_LDAP_URL needs KARTAL_LDAP_BIND_DN (a service account) or KARTAL_LDAP_UPN_DOMAIN (Active Directory)")
	}
	if len(rules) == 0 {
		// Groups mapped in the admin panel let people in too; until there
		// are some, nobody from the directory can sign in.
		log.Warn("KARTAL_LDAP_GROUPS is empty: only the directory groups mapped in the admin panel let people in")
	}
	if strings.HasPrefix(url, "ldap://") && !startTLS {
		log.Warn("KARTAL_LDAP_URL is plain ldap:// without KARTAL_LDAP_STARTTLS: passwords cross the network readable")
	}
	return a, nil
}

// hashPassword reads a password, one line, and writes the hash that goes in
// KARTAL_USERS in place of a token (name:grant:hash): kartal-server
// hash-password.
func hashPassword(in io.Reader, out io.Writer) error {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	hash, err := auth.HashPassword(strings.TrimRight(line, "\r\n"))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, hash)
	return err
}
