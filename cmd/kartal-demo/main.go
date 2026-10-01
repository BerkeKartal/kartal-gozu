// Command kartal-demo runs a Kartal Gözü server together with agents that
// watch made-up clusters, so the web UI can be tried without Kubernetes:
//
//	go run ./cmd/kartal-demo
//
// and open http://127.0.0.1:8080/. The data is made up: actions answer as if
// they worked, and the usage charts start with six hours of invented history.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/agent"
	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/api"
	"github.com/BerkeKartal/kartal-gozu/internal/fakekube"
	"github.com/BerkeKartal/kartal-gozu/internal/history"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/ldap"
	"github.com/BerkeKartal/kartal-gozu/internal/logging"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/store"
	"github.com/BerkeKartal/kartal-gozu/internal/uptime"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address to serve the UI and API on")
	adminToken := flag.String("admin-token", "", "token to sign in with; empty leaves the demo open")
	namespaces := flag.Int("namespaces", 14, "generated namespaces (3 pods each) in the \"production\" cluster; raise it to try a big cluster")
	withLDAP := flag.Bool("ldap", false, "sign in with a built-in directory: ayse (admin), mehmet (operator in the team-0* namespaces), zeynep (viewer); the password is demo")
	flag.Parse()
	log := logging.New("warn")
	if err := run(*listen, *adminToken, max(*namespaces, 0), *withLDAP, log); err != nil {
		log.Error("demo stopped", "err", err)
		os.Exit(1)
	}
}

type demoCluster struct {
	name string
	kube *fakekube.Server
}

func run(listen, adminToken string, namespaces int, withLDAP bool, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	clusters := []demoCluster{
		{"production", &fakekube.Server{Extra: namespaces, Live: true}},
		// Staging runs release candidates of every other team's app.
		{"staging", &fakekube.Server{Extra: 4, NoMetrics: true, Variant: "-rc1"}},
	}
	// "lab" has no agent, to show how a cluster that never connected looks.
	st := store.New("production", "staging", "lab")
	tokens := map[string]string{}
	for i, c := range clusters {
		tokens[fmt.Sprintf("demo-agent-token-%02d", i)] = c.name
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	hist := history.New()
	// Until e-mail is set up on the Alerts page (the demo keeps it in memory),
	// the demo's problems are only shown there.
	email := alert.NewSwitchable("email")
	alerts := alert.NewManager(30*time.Second, log, email)
	keeper := settings.NewKeeper(ctx, settings.Memory{}, log)
	checks := uptime.New(keeper, alerts, log)
	if err := demoChecks(ctx, keeper); err != nil {
		return err
	}
	cfg := api.Config{
		AgentTokens:    tokens,
		AdminToken:     adminToken,
		StaleAfter:     time.Minute,
		MaxPollWait:    20 * time.Second,
		CommandTimeout: 18 * time.Second,
		Alerts:         alerts,
		Mail:           settings.NewMail(keeper, email, nil),
		Checks:         checks,
		History:        hist,
	}
	if withLDAP {
		login, err := demoDirectory()
		if err != nil {
			return err
		}
		cfg.Login = login
	}
	server := api.New(cfg, st, log)
	go backfill(ctx, st, hist, "production")
	srv := &http.Server{
		Handler:           logging.Requests(log, server),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go srv.Serve(ln)
	go server.Watch(ctx)
	checks.Start(ctx)
	serverURL := "http://" + ln.Addr().String()

	for i, c := range clusters {
		kubeURL, err := serveFake(ctx, c.kube)
		if err != nil {
			return err
		}
		kc := kube.New(kubeURL, fakekube.Token, false)
		a := &agent.Agent{
			ServerURL:   serverURL,
			Token:       fmt.Sprintf("demo-agent-token-%02d", i),
			HTTP:        &http.Client{Timeout: 30 * time.Second},
			Collector:   &agent.Collector{Kube: kc, Version: "demo", IncludeSecrets: true, VolumeStats: true, TLSSecrets: true},
			Executor:    &agent.Executor{Kube: kc, AllowWrite: true, AllowExec: true, AllowEdit: true},
			Interval:    5 * time.Second,
			PollWait:    15 * time.Second,
			Concurrency: 2,
			Log:         log,
		}
		go a.Run(ctx)
	}

	fmt.Printf("Kartal Gözü demo is running: open %s/\n", serverURL)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// backfill invents six hours of usage history for a cluster, so the demo's
// charts have something to show from the start: its first real snapshot,
// replayed into the past on a slow wave.
func backfill(ctx context.Context, st *store.Store, hist *history.Store, cluster string) {
	var snap *protocol.Snapshot
	for snap == nil {
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
		if ci, ok := st.Cluster(cluster); ok {
			snap = ci.Snapshot
		}
	}
	now := time.Now()
	for m := history.Points - 1; m >= 1; m-- {
		x := float64(m)
		hist.Record(cluster, scaled(snap, 0.85+0.25*math.Sin(x/37)+0.08*math.Sin(x/5.3)), now.Add(-time.Duration(m)*time.Minute))
	}
}

// scaled copies the usage in a snapshot, CPU times f; memory moves less.
func scaled(snap *protocol.Snapshot, f float64) *protocol.Snapshot {
	scale := func(u *protocol.Resources) *protocol.Resources {
		if u == nil {
			return nil
		}
		return &protocol.Resources{CPUMilli: int64(float64(u.CPUMilli) * f), MemoryBytes: int64(float64(u.MemoryBytes) * (0.92 + 0.08*f))}
	}
	out := &protocol.Snapshot{MetricsAvailable: snap.MetricsAvailable}
	for _, n := range snap.Nodes {
		n.Usage = scale(n.Usage)
		out.Nodes = append(out.Nodes, n)
	}
	for _, p := range snap.Pods {
		p.Usage = scale(p.Usage)
		out.Pods = append(out.Pods, p)
	}
	return out
}

// demoChecks starts two small sites and sets up URL checks: one answers
// fine, one has a certificate that expires in twelve days, and one asks a
// port where nothing listens.
func demoChecks(ctx context.Context, keeper *settings.Keeper) error {
	site := http.NewServeMux()
	site.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	cert, err := fakekube.ServingCertificate([]string{"localhost", "127.0.0.1"}, 12*24*time.Hour)
	if err != nil {
		return err
	}
	secure, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return err
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0") // closed at once: nothing will answer there
	if err != nil {
		return err
	}
	closed.Close()
	for _, ln := range []net.Listener{plain, secure} {
		srv := &http.Server{Handler: site, ReadHeaderTimeout: 10 * time.Second}
		go srv.Serve(ln)
		go func() { <-ctx.Done(); srv.Close() }()
	}
	_, err = keeper.Update(ctx, func(s *settings.Settings) error {
		for _, c := range []settings.Check{
			{Name: "Portal", URL: "http://" + plain.Addr().String() + "/healthz", Contains: "ok", Interval: 30},
			// Signed by the demo's own authority, which nothing trusts.
			{Name: "Partner API", URL: "https://" + secure.Addr().String() + "/healthz", Insecure: true, Interval: 30},
			{Name: "Payments", URL: "http://" + closed.Addr().String() + "/", Interval: 30, Timeout: 5},
		} {
			c.ID = settings.NewCheckID()
			if err := c.Normalize(); err != nil {
				return err
			}
			s.Checks = append(s.Checks, c)
		}
		return nil
	})
	return err
}

// serveFake starts a fake Kubernetes API on a random local port.
func serveFake(ctx context.Context, f *fakekube.Server) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	go func() { <-ctx.Done(); srv.Close() }()
	return "http://" + ln.Addr().String(), nil
}

// demoDirectory starts a small directory with three people, whose groups
// give them different roles in different places, and signs people in
// against it.
func demoDirectory() (ldap.Authenticator, error) {
	const (
		admins    = "CN=Kartal-Admins,OU=Groups,DC=example,DC=org"
		teamA     = "CN=Team-A,OU=Groups,DC=example,DC=org"
		watchers  = "CN=Watchers,OU=Groups,DC=example,DC=org"
		password  = "demo"
		userBase  = "DC=example,DC=org"
		upnDomain = "example.org"
	)
	dir := &ldap.Fake{Domain: upnDomain, People: map[string]ldap.FakePerson{
		"ayse":   {Password: password, DisplayName: "Ayşe", Groups: []string{admins}},
		"mehmet": {Password: password, DisplayName: "Mehmet", Groups: []string{teamA}},
		"zeynep": {Password: password, DisplayName: "Zeynep", Groups: []string{watchers}},
	}}
	url, err := dir.Start()
	if err != nil {
		return ldap.Authenticator{}, err
	}
	rules, err := ldap.ParseRules("Kartal-Admins => admin\nTeam-A => operator@production/team-0*+staging/*\nWatchers => viewer@production/*")
	if err != nil {
		return ldap.Authenticator{}, err
	}
	fmt.Println("Sign in as ayse (admin), mehmet (operator in production/team-0* and all of staging) or zeynep (viewer in production); the password is \"demo\".")
	return ldap.Authenticator{Config: ldap.Config{URL: url, UPNDomain: upnDomain, UserBase: userBase}, Rules: rules}, nil
}
