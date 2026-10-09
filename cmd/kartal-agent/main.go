// Command kartal-agent runs in a managed cluster and reports to kartal-server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/agent"
	"github.com/BerkeKartal/kartal-gozu/internal/config"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
)

var version = "dev"

func main() {
	log := logging.New(config.String("KARTAL_LOG_LEVEL", "info"))
	if err := run(log); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	serverURL := config.String("KARTAL_SERVER_URL", "")
	if serverURL == "" {
		return errors.New("KARTAL_SERVER_URL is required, e.g. https://example.org/devops/kartal")
	}
	if u, err := url.Parse(serverURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("KARTAL_SERVER_URL %q is not a valid http(s) URL", serverURL)
	}
	token, err := config.Secret("KARTAL_TOKEN")
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("KARTAL_TOKEN (or KARTAL_TOKEN_FILE) is required")
	}
	interval, err := config.Duration("KARTAL_INTERVAL", 15*time.Second)
	if err != nil {
		return err
	}
	pollWait, err := config.Duration("KARTAL_POLL_WAIT", 25*time.Second)
	if err != nil {
		return err
	}
	allowWrite, err := config.Bool("KARTAL_ALLOW_WRITE", false)
	if err != nil {
		return err
	}
	allowExec, err := config.Bool("KARTAL_ALLOW_EXEC", false)
	if err != nil {
		return err
	}
	allowEdit, err := config.Bool("KARTAL_ALLOW_EDIT", false)
	if err != nil {
		return err
	}
	podMetrics, err := config.Bool("KARTAL_POD_METRICS", false)
	if err != nil {
		return err
	}
	includeSecrets, err := config.Bool("KARTAL_INCLUDE_SECRETS", false)
	if err != nil {
		return err
	}
	volumeStats, err := config.Bool("KARTAL_VOLUME_STATS", false)
	if err != nil {
		return err
	}
	tlsSecrets, err := config.Bool("KARTAL_TLS_SECRETS", false)
	if err != nil {
		return err
	}
	namespaces := config.List("KARTAL_NAMESPACES")
	dataSources, err := agent.ParseDataSourceURLs(config.List("KARTAL_DATASOURCE_URLS"))
	if err != nil {
		return fmt.Errorf("KARTAL_DATASOURCE_URLS: %w", err)
	}

	kc, err := kubeClient()
	if err != nil {
		return err
	}
	httpClient, err := serverClient(pollWait)
	if err != nil {
		return err
	}

	a := &agent.Agent{
		ServerURL: serverURL,
		Token:     token,
		HTTP:      httpClient,
		Collector: &agent.Collector{Kube: kc, Namespaces: namespaces, IncludeSecrets: includeSecrets, VolumeStats: volumeStats,
			TLSSecrets: tlsSecrets, MaxEvents: 200, Version: version},
		Executor: &agent.Executor{
			Kube:           kc,
			AllowWrite:     allowWrite,
			AllowExec:      allowExec,
			AllowEdit:      allowEdit,
			AllowScrape:    podMetrics,
			DataSourceURLs: dataSources,
			Namespaces:     namespaces,
			MaxLogBytes:    1 << 20,
		},
		Interval: interval,
		PollWait: pollWait,
		// The server's own reading of metrics takes a few of these; what
		// people ask for in the UI must find one free.
		Concurrency: 8,
		Log:         log,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if addr := config.String("KARTAL_HEALTH_LISTEN", ":8081"); addr != "off" {
		go serveHealth(ctx, addr, a, log)
	}
	scope := "all namespaces"
	if len(namespaces) > 0 {
		scope = fmt.Sprint(namespaces)
	}
	log.Info("kartal-agent started", "version", version, "server", serverURL, "scope", scope, "interval", interval, "allow_write", allowWrite, "allow_exec", allowExec, "allow_edit", allowEdit, "data_sources", len(dataSources))
	a.Run(ctx)
	log.Info("agent stopped")
	return nil
}

func kubeClient() (*kube.Client, error) {
	if api := config.String("KARTAL_KUBE_API", ""); api != "" {
		insecure, err := config.Bool("KARTAL_KUBE_INSECURE", false)
		if err != nil {
			return nil, err
		}
		tok, err := config.Secret("KARTAL_KUBE_TOKEN")
		if err != nil {
			return nil, err
		}
		return kube.New(api, tok, insecure), nil
	}
	return kube.InCluster()
}

// serverClient trusts the system CAs, plus KARTAL_CA_FILE when the server
// uses a private CA.
func serverClient(pollWait time.Duration) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if f := config.String("KARTAL_CA_FILE", ""); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("KARTAL_CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("KARTAL_CA_FILE contains no certificates")
		}
		tc.RootCAs = pool
	}
	insecure, err := config.Bool("KARTAL_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return nil, err
	}
	tc.InsecureSkipVerify = insecure
	return &http.Client{
		// Must outlive the long-poll the server is allowed to hold.
		Timeout: pollWait + 20*time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     tc,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}, nil
}

func serveHealth(ctx context.Context, addr string, a *agent.Agent, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !a.Healthy(time.Now()) {
			http.Error(w, "the report loop is stuck", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ok\n")
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Warn("health endpoint stopped", "err", err)
	}
}
