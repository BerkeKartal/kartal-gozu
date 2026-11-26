package scanner

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config sets a Service up.
type Config struct {
	// Trivy is the trivy binary; "trivy" (from PATH) when empty.
	Trivy string
	// CacheDir is Trivy's cache: its databases, and what it learned of the
	// layers it saw, which later scans of them reuse.
	CacheDir string
	// Secret is what callers send (as a Bearer token).
	Secret string
	// Workers is how many scans run at once (2 when zero); Timeout how long
	// one may take (15 minutes when zero).
	Workers int
	Timeout time.Duration
	// DBRepository and JavaDBRepository are where the databases come from,
	// such as a mirror in the registry (registry.example.org/trivy/trivy-db:2);
	// Trivy's own when empty.
	DBRepository     string
	JavaDBRepository string
	// Offline keeps the scans from asking the internet anything (such as
	// Maven Central about jars the Java DB does not know).
	Offline bool
	// Env is more environment for Trivy, such as for tests.
	Env []string
	Log *slog.Logger
}

// Service runs Trivy for the registry.
type Service struct {
	cfg Config
	sem chan struct{}

	// db is held to read the databases (by scans) and to replace them (by
	// updates), which nothing may read meanwhile.
	db sync.RWMutex

	mu          sync.Mutex
	waiting     int
	scanning    int
	updating    bool
	updated     chan struct{} // closed when the update under way ends
	lastUpdate  *time.Time
	updateError string
	version     string
}

// New makes a Service.
func New(cfg Config) *Service {
	if cfg.Trivy == "" {
		cfg.Trivy = "trivy"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{cfg: cfg, sem: make(chan struct{}, cfg.Workers)}
}

// compromised are Trivy's versions that were made by those who broke into
// its release process in March 2026: they steal credentials.
var compromised = map[string]bool{"0.69.4": true, "0.69.5": true, "0.69.6": true}

// ErrCompromised is a Trivy of a version known to be malicious.
var ErrCompromised = errors.New("this Trivy version is a known malicious build (March 2026); use 0.69.3 or a later verified release")

// env is what Trivy runs with: little of the scanner's own (not its
// secret), the proxies, and Trivy's settings.
func (s *Service) env(extra ...string) []string {
	var out []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	if _, ok := os.LookupEnv("HOME"); !ok {
		out = append(out, "HOME="+os.TempDir())
	}
	// Settings later Trivys know; earlier ones let them be.
	out = append(out, "TRIVY_NO_PROGRESS=true", "TRIVY_SKIP_VERSION_CHECK=true", "TRIVY_DISABLE_TELEMETRY=true")
	if s.cfg.DBRepository != "" {
		out = append(out, "TRIVY_DB_REPOSITORY="+s.cfg.DBRepository)
	}
	if s.cfg.JavaDBRepository != "" {
		out = append(out, "TRIVY_JAVA_DB_REPOSITORY="+s.cfg.JavaDBRepository)
	}
	if s.cfg.Offline {
		out = append(out, "TRIVY_OFFLINE_SCAN=true")
	}
	out = append(out, s.cfg.Env...)
	return append(out, extra...)
}

// run runs Trivy, and says why it failed from what it logged last.
func (s *Service) run(ctx context.Context, args []string, extraEnv ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.cfg.Trivy, args...)
	cmd.Env = s.env(extraEnv...)
	cmd.WaitDelay = 5 * time.Second
	var stdout bytes.Buffer
	stderr := &tail{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = &stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if msg := stderr.reason(); msg != "" {
			return nil, errors.New(msg)
		}
		return nil, fmt.Errorf("trivy %s: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}

// tail keeps the end of what is written to it.
type tail struct {
	max int
	b   []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

// reason is the last thing Trivy logged as fatal or as an error, or else
// its last line.
func (t *tail) reason() string {
	lines := strings.Split(strings.TrimSpace(string(t.b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.Contains(l, "FATAL") || strings.Contains(l, "ERROR") {
			return trimLog(l)
		}
	}
	if len(lines) > 0 {
		return trimLog(lines[len(lines)-1])
	}
	return ""
}

// trimLog drops a log line's time and level.
func trimLog(l string) string {
	for _, level := range []string{"FATAL", "ERROR"} {
		if i := strings.Index(l, level); i >= 0 {
			l = strings.TrimSpace(l[i+len(level):])
		}
	}
	if len(l) > 600 {
		l = l[:600] + "…"
	}
	return l
}

// ---------------------------------------------------------------- status

// trivyVersion is what `trivy version --format json` says.
type trivyVersion struct {
	Version         string     `json:"Version"`
	VulnerabilityDB *trivyMeta `json:"VulnerabilityDB"`
	JavaDB          *trivyMeta `json:"JavaDB"`
}

type trivyMeta struct {
	UpdatedAt    *time.Time `json:"UpdatedAt"`
	NextUpdate   *time.Time `json:"NextUpdate"`
	DownloadedAt *time.Time `json:"DownloadedAt"`
}

func (m *trivyMeta) status() *DBStatus {
	if m == nil || m.UpdatedAt == nil || m.UpdatedAt.IsZero() {
		return nil
	}
	return &DBStatus{UpdatedAt: m.UpdatedAt, NextUpdate: m.NextUpdate, DownloadedAt: m.DownloadedAt}
}

// Status is the scanner's state: Trivy's version and its databases.
func (s *Service) Status(ctx context.Context) (Status, error) {
	s.db.RLock()
	out, err := s.run(ctx, []string{"version", "--format", "json", "--cache-dir", s.cfg.CacheDir})
	s.db.RUnlock()
	if err != nil {
		return Status{}, fmt.Errorf("asking Trivy its version: %w", err)
	}
	var v trivyVersion
	if err := json.Unmarshal(out, &v); err != nil {
		return Status{}, fmt.Errorf("the version Trivy gave cannot be read: %w", err)
	}
	v.Version = strings.TrimPrefix(v.Version, "v")
	s.mu.Lock()
	s.version = v.Version
	st := Status{Scanner: "Trivy " + v.Version, DB: v.VulnerabilityDB.status(), JavaDB: v.JavaDB.status(),
		DBRepository: s.cfg.DBRepository, JavaDBRepository: s.cfg.JavaDBRepository,
		Scanning: s.scanning, Waiting: s.waiting, Workers: s.cfg.Workers, Updating: s.updating, LastUpdate: s.lastUpdate, UpdateError: s.updateError}
	s.mu.Unlock()
	if compromised[v.Version] {
		return st, ErrCompromised
	}
	return st, nil
}

// ---------------------------------------------------------------- the databases

// UpdateDB gets the vulnerability databases anew. While it does, no scan
// runs; one asked for meanwhile waits. An update asked for while one is
// under way waits for it.
func (s *Service) UpdateDB(ctx context.Context) error {
	s.mu.Lock()
	if s.updating {
		done := s.updated
		s.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.updateError != "" {
			return errors.New(s.updateError)
		}
		return nil
	}
	s.updating, s.updated = true, make(chan struct{})
	s.mu.Unlock()

	err := s.updateDB(ctx)

	now := time.Now().UTC()
	s.mu.Lock()
	s.updating = false
	close(s.updated)
	s.lastUpdate, s.updateError = &now, ""
	if err != nil {
		s.updateError = err.Error()
	}
	s.mu.Unlock()
	return err
}

func (s *Service) updateDB(ctx context.Context) error {
	// An update outlives the call that asked for it, which may give up
	// waiting; half a database would be worse.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	defer cancel()
	s.db.Lock()
	defer s.db.Unlock()
	if _, err := s.run(ctx, []string{"image", "--download-db-only", "--cache-dir", s.cfg.CacheDir}); err != nil {
		return fmt.Errorf("downloading the vulnerability DB: %w", err)
	}
	if _, err := s.run(ctx, []string{"image", "--download-java-db-only", "--cache-dir", s.cfg.CacheDir}); err != nil {
		return fmt.Errorf("downloading the Java DB: %w", err)
	}
	s.cfg.Log.Info("the vulnerability databases are updated")
	return nil
}

// ---------------------------------------------------------------- scans

// imageRE is an image by digest: host[:port]/path@sha256:hex.
var imageRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)+@sha256:[a-f0-9]{64}$`)

// ErrRequest is a request to scan that cannot be done as asked.
var ErrRequest = errors.New("bad request")

// Scan scans an image, waiting for its turn, and reports what it found
// with the image's SBOM.
func (s *Service) Scan(ctx context.Context, req Request) (Result, error) {
	if !imageRE.MatchString(req.Image) {
		return Result{}, fmt.Errorf("%w: %q is not an image by digest, as host/repository@sha256:…", ErrRequest, req.Image)
	}
	s.mu.Lock()
	s.waiting++
	s.mu.Unlock()
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		s.mu.Lock()
		s.waiting--
		s.mu.Unlock()
		return Result{}, ctx.Err()
	}
	s.mu.Lock()
	s.waiting--
	s.scanning++
	s.mu.Unlock()
	defer func() {
		<-s.sem
		s.mu.Lock()
		s.scanning--
		s.mu.Unlock()
	}()

	// A scanner that has no database yet gets one first.
	st, err := s.Status(ctx)
	if err != nil {
		return Result{}, err
	}
	if st.DB == nil {
		if err := s.UpdateDB(ctx); err != nil {
			return Result{}, fmt.Errorf("the scanner has no vulnerability DB yet, and getting one failed: %w", err)
		}
		if st, err = s.Status(ctx); err != nil {
			return Result{}, err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	s.db.RLock()
	defer s.db.RUnlock()
	dir, err := os.MkdirTemp("", "kartal-scan-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(dir)
	report := filepath.Join(dir, "report.json")
	args := []string{"image", "--format", "json", "--list-all-pkgs", "--scanners", "vuln",
		"--skip-db-update", "--skip-java-db-update", "--cache-dir", s.cfg.CacheDir,
		"--timeout", s.cfg.Timeout.String(), "--output", report}
	if req.Insecure {
		args = append(args, "--insecure")
	}
	args = append(args, "--", req.Image)
	// The credentials go in the environment, which other processes do not
	// see, unlike the arguments.
	var env []string
	if req.Username != "" {
		env = append(env, "TRIVY_USERNAME="+req.Username, "TRIVY_PASSWORD="+req.Password)
	}
	started := time.Now()
	if _, err := s.run(ctx, args, env...); err != nil {
		return Result{}, err
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		return Result{}, fmt.Errorf("no report was written: %w", err)
	}
	rep, err := Trim(raw)
	if err != nil {
		return Result{}, err
	}
	rep.Scanner = st.Scanner
	if st.DB != nil {
		rep.DB = st.DB.UpdatedAt
	}
	res := Result{Report: rep}
	// The SBOM comes of the same scan.
	sbom := filepath.Join(dir, "sbom.json")
	if _, err := s.run(ctx, []string{"convert", "--format", "cyclonedx", "--output", sbom, report}); err != nil {
		s.cfg.Log.Warn("making an SBOM", "image", req.Image, "err", err)
	} else if b, err := os.ReadFile(sbom); err == nil && json.Valid(b) {
		res.SBOM = b
	}
	s.cfg.Log.Info("scanned", "image", req.Image, "vulnerabilities", len(rep.Vulnerabilities), "seconds", int(time.Since(started).Seconds()))
	return res, nil
}

// trivyReport is what of Trivy's JSON report is kept.
type trivyReport struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string            `json:"Target"`
		Type            string            `json:"Type"`
		Packages        []json.RawMessage `json:"Packages"`
		Vulnerabilities []struct {
			VulnerabilityID  string     `json:"VulnerabilityID"`
			PkgName          string     `json:"PkgName"`
			InstalledVersion string     `json:"InstalledVersion"`
			FixedVersion     string     `json:"FixedVersion"`
			Status           string     `json:"Status"`
			Severity         string     `json:"Severity"`
			Title            string     `json:"Title"`
			PrimaryURL       string     `json:"PrimaryURL"`
			PublishedDate    *time.Time `json:"PublishedDate"`
			CVSS             map[string]struct {
				V3Score  float64 `json:"V3Score"`
				V40Score float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// Trim makes a Report of Trivy's JSON report, leaving out what lists do
// not show (descriptions, references), which is most of it.
func Trim(raw []byte) (Report, error) {
	var tr trivyReport
	if err := json.Unmarshal(raw, &tr); err != nil {
		return Report{}, fmt.Errorf("the report cannot be read: %w", err)
	}
	rep := Report{Vulnerabilities: []Vulnerability{}}
	if dist := tr.Metadata.OS; dist != nil && dist.Family != "" {
		rep.OS = strings.TrimSpace(dist.Family + " " + dist.Name)
	}
	for _, r := range tr.Results {
		rep.Packages += len(r.Packages)
		for _, v := range r.Vulnerabilities {
			sev := strings.ToUpper(v.Severity)
			if Rank(sev) < 0 {
				sev = Unknown
			}
			out := Vulnerability{ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion, Fixed: v.FixedVersion,
				Severity: sev, Title: v.Title, URL: v.PrimaryURL, Status: v.Status, Published: v.PublishedDate, Target: r.Target, Type: r.Type}
			// NVD's score where it has one, or else the highest given.
			if c, ok := v.CVSS["nvd"]; ok && c.V3Score > 0 {
				out.Score = c.V3Score
			} else {
				for _, c := range v.CVSS {
					out.Score = max(out.Score, c.V3Score, c.V40Score)
				}
			}
			if len(out.Title) > 200 {
				out.Title = out.Title[:200] + "…"
			}
			rep.Vulnerabilities = append(rep.Vulnerabilities, out)
		}
	}
	Sort(rep.Vulnerabilities)
	return rep, nil
}

// ---------------------------------------------------------------- the API

// Handler serves the scanner's API: POST /scan, POST /db/update, GET
// /status, and GET /healthz, which alone needs no secret.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan", func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			apiError(w, http.StatusBadRequest, "the body is not the JSON expected: "+err.Error())
			return
		}
		res, err := s.Scan(r.Context(), req)
		switch {
		case errors.Is(err, ErrRequest):
			apiError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrCompromised):
			apiError(w, http.StatusServiceUnavailable, err.Error())
		case err != nil:
			apiError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			apiJSON(w, http.StatusOK, res)
		}
	})
	mux.HandleFunc("POST /db/update", func(w http.ResponseWriter, r *http.Request) {
		if err := s.UpdateDB(r.Context()); err != nil {
			apiError(w, http.StatusBadGateway, err.Error())
			return
		}
		st, err := s.Status(r.Context())
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		apiJSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		st, err := s.Status(r.Context())
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		apiJSON(w, http.StatusOK, st)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("ok\n"))
			return
		}
		h := r.Header.Get("Authorization")
		tok := ""
		if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
		if s.cfg.Secret == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.Secret)) != 1 {
			apiError(w, http.StatusUnauthorized, "the scanner's secret is needed")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}
