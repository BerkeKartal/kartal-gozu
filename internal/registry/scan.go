package registry

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

// Images are scanned for known vulnerabilities by a scanner (kartal-scanner,
// which runs Trivy). It pulls each image from the registry as ScannerUser,
// with a password the registry makes for that one scan, which pulls from
// that one repository and nothing else. Scans wait in a queue that a few
// workers take from. What a scan found is kept in the metadata, summed up,
// and next to it in full, with the image's SBOM.

// Scanner scans images; scanner.Client is the one that calls kartal-scanner.
type Scanner interface {
	Scan(ctx context.Context, req scanner.Request) (scanner.Result, error)
	UpdateDB(ctx context.Context) (scanner.Status, error)
	Status(ctx context.Context) (scanner.Status, error)
}

// ScannerUser is the name the scanner signs in with. No one else can sign
// in by it: it is not a name kartal-server gives.
const ScannerUser = "kartal$scanner"

// JobScan scans every image again, after updating the scanner's databases.
const JobScan = "scan"

const (
	// scanTimeout is the longest a scan may take; ticketTTL how long its
	// password pulls, a little longer.
	scanTimeout = 20 * time.Minute
	ticketTTL   = scanTimeout + 5*time.Minute
	// defaultScanWorkers is how many images are scanned at once.
	defaultScanWorkers = 2
)

var (
	// ErrNoScanner is scanning asked of a registry without a scanner.
	ErrNoScanner = errors.New("the registry has no scanner")
	// ErrNotScannable is a scan of what is not an image.
	ErrNotScannable = errors.New("only images are scanned")
)

// queued is a scan waiting its turn, with what was known before, to go
// back to if it is taken out of the queue.
type queued struct {
	digest string
	prev   *meta.Scan
}

// ticket is what a scan's password lets the scanner pull.
type ticket struct {
	repo    string
	expires time.Time
}

// scanTarget is where the scanner pulls from: the registry's host, and
// whether it is reached over plain HTTP.
func (s *Server) scanTarget() (string, bool, error) {
	addr := s.cfg.ScanAddress
	if addr == "" {
		addr = s.cfg.PublicURL
	}
	if addr == "" {
		return "", false, errors.New("the scanner does not know where to pull from: set KARTAL_REGISTRY_SCAN_ADDRESS or KARTAL_REGISTRY_PUBLIC_URL")
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false, fmt.Errorf("%q is not an address such as https://registry.example.org", addr)
	}
	return u.Host, u.Scheme == "http", nil
}

// scanRealm is the token service at the scanner's address, for a request
// that came by it, when it is not the public one.
func (s *Server) scanRealm(host string) string {
	if s.cfg.ScanAddress == "" {
		return ""
	}
	u, err := url.Parse(s.cfg.ScanAddress)
	if err != nil || !strings.EqualFold(u.Host, host) {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/token"
}

// scanTicket is what a scanner's password lets it pull, if it is one.
func (s *Server) scanTicket(password string) (ticket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[password]
	if !ok || s.now().After(t.expires) {
		return ticket{}, false
	}
	return t, true
}

// ---------------------------------------------------------------- the queue

// QueueScan has an image scanned, or an index's images; it answers the
// images that are being scanned. One already waiting or under way is not
// queued again.
func (s *Server) QueueScan(repo, digest, by string) ([]string, error) {
	if s.cfg.Scanner == nil {
		return nil, ErrNoScanner
	}
	a, ok := s.cfg.DB.Artifact(repo, digest)
	if !ok {
		return nil, meta.ErrNotFound
	}
	var images []string
	switch a.Kind {
	case "image":
		images = []string{digest}
	case "index":
		for _, m := range a.Manifests {
			if c, ok := s.cfg.DB.Artifact(repo, m.Digest); ok && c.Kind == "image" {
				images = append(images, m.Digest)
			}
		}
		if len(images) == 0 {
			return nil, fmt.Errorf("%w: the index has none here", ErrNotScannable)
		}
	default:
		return nil, fmt.Errorf("%w: this is a %s", ErrNotScannable, a.Kind)
	}
	for _, d := range images {
		if _, err := s.queue(repo, d, by); err != nil {
			return nil, err
		}
	}
	return images, nil
}

// queue puts an image in the queue, unless it is there or being scanned;
// it tells whether it put it there.
func (s *Server) queue(repo, digest, by string) (bool, error) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scanPending[digest] {
		return false, nil
	}
	prev, had := s.cfg.DB.Scan(digest)
	sc := prev
	if !had {
		sc = meta.Scan{Digest: digest}
	}
	sc.Repo, sc.Status, sc.Queued, sc.By, sc.Start = repo, meta.ScanQueued, s.now().UTC(), by, nil
	if err := s.cfg.DB.PutScan(sc); err != nil {
		return false, err
	}
	q := queued{digest: digest}
	if had {
		q.prev = &prev
	}
	s.scanQueue = append(s.scanQueue, q)
	s.scanPending[digest] = true
	s.wakeScanner()
	return true, nil
}

// wakeScanner tells a worker there is something to scan; the lock is held.
func (s *Server) wakeScanner() {
	select {
	case s.scanWake <- struct{}{}:
	default:
	}
}

// unqueue takes images out of the queue that are not being scanned yet,
// and puts back what was known of them.
func (s *Server) unqueue(digests map[string]bool) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	kept := s.scanQueue[:0]
	for _, q := range s.scanQueue {
		if !digests[q.digest] {
			kept = append(kept, q)
			continue
		}
		delete(s.scanPending, q.digest)
		var err error
		if q.prev != nil {
			err = s.cfg.DB.PutScan(*q.prev)
		} else {
			err = s.cfg.DB.DeleteScan(q.digest)
		}
		if err != nil {
			s.cfg.Log.Warn("registry: taking a scan out of the queue", "digest", q.digest, "err", err)
		}
	}
	s.scanQueue = kept
}

// pendingScan tells whether an image waits or is being scanned.
func (s *Server) pendingScan(digest string) bool {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	return s.scanPending[digest]
}

// QueuedScans is how many images wait or are being scanned.
func (s *Server) QueuedScans() int {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	return len(s.scanPending)
}

// startScans starts the workers, and queues again what was waiting or
// under way when the registry stopped.
func (s *Server) startScans(ctx context.Context) {
	if s.cfg.Scanner == nil {
		return
	}
	s.scanMu.Lock()
	for _, sc := range s.cfg.DB.Scans() {
		if sc.Status != meta.ScanQueued && sc.Status != meta.ScanScanning || s.scanPending[sc.Digest] {
			continue
		}
		// What it goes back to if it is taken out: its last result.
		prev := sc
		prev.Status = meta.ScanDone
		if prev.Scanned == nil {
			prev.Status = ""
		}
		q := queued{digest: sc.Digest}
		if prev.Status != "" {
			q.prev = &prev
		}
		s.scanQueue = append(s.scanQueue, q)
		s.scanPending[sc.Digest] = true
	}
	s.scanMu.Unlock()
	workers := s.cfg.ScanWorkers
	if workers <= 0 {
		workers = defaultScanWorkers
	}
	for i := 0; i < workers; i++ {
		go s.scanWorker(ctx)
	}
	s.scanMu.Lock()
	s.wakeScanner()
	s.scanMu.Unlock()
}

func (s *Server) scanWorker(ctx context.Context) {
	for {
		s.scanMu.Lock()
		var q queued
		ok := len(s.scanQueue) > 0
		if ok {
			q = s.scanQueue[0]
			s.scanQueue = s.scanQueue[1:]
			if len(s.scanQueue) > 0 {
				// Another worker may take the next.
				s.wakeScanner()
			}
		}
		s.scanMu.Unlock()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-s.scanWake:
			}
			continue
		}
		s.scanOne(ctx, q.digest)
		s.scanMu.Lock()
		delete(s.scanPending, q.digest)
		s.scanMu.Unlock()
		if ctx.Err() != nil {
			return
		}
	}
}

// scanOne scans an image and keeps what the scan found.
func (s *Server) scanOne(ctx context.Context, digest string) {
	sc, ok := s.cfg.DB.Scan(digest)
	if !ok {
		return
	}
	// The repository it was queued from may have lost it; another may
	// have it.
	if _, ok := s.cfg.DB.Artifact(sc.Repo, digest); !ok {
		holders := s.cfg.DB.Holders(digest)
		if len(holders) == 0 {
			s.dropScan(digest)
			return
		}
		sc.Repo = holders[0]
	}
	fail := func(err error) {
		sc.Status, sc.Error = meta.ScanFailed, err.Error()
		s.cfg.Log.Warn("registry: a scan failed", "repo", sc.Repo, "digest", digest, "err", err)
		if err := s.cfg.DB.PutScan(sc); err != nil {
			s.cfg.Log.Warn("registry: recording a scan", "digest", digest, "err", err)
		}
	}
	host, insecure, err := s.scanTarget()
	if err != nil {
		fail(err)
		return
	}
	start := s.now().UTC()
	sc.Status, sc.Start = meta.ScanScanning, &start
	if err := s.cfg.DB.PutScan(sc); err != nil {
		s.cfg.Log.Warn("registry: recording a scan", "digest", digest, "err", err)
	}
	password := newToken()
	s.mu.Lock()
	s.tickets[password] = ticket{repo: sc.Repo, expires: s.now().Add(ticketTTL)}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tickets, password)
		s.mu.Unlock()
	}()
	sctx, cancel := context.WithTimeout(ctx, scanTimeout)
	res, err := s.cfg.Scanner.Scan(sctx, scanner.Request{Image: host + "/" + sc.Repo + "@" + digest,
		Username: ScannerUser, Password: password, Insecure: insecure})
	cancel()
	if ctx.Err() != nil {
		// The registry stops: it is queued again when it is back.
		return
	}
	if err != nil {
		fail(err)
		return
	}
	if err := s.writeReport(digest, res); err != nil {
		fail(fmt.Errorf("keeping the report: %w", err))
		return
	}
	s.forgetVulns(digest)
	end := s.now().UTC()
	sum := scanner.Summarize(res.Report.Vulnerabilities)
	sc.Status, sc.Error, sc.Scanned, sc.Summary = meta.ScanDone, "", &end, &sum
	sc.Scanner, sc.DB, sc.OS, sc.Packages = res.Report.Scanner, res.Report.DB, res.Report.OS, res.Report.Packages
	if err := s.cfg.DB.PutScan(sc); err != nil {
		s.cfg.Log.Warn("registry: recording a scan", "digest", digest, "err", err)
	}
}

// dropScan forgets an image's scan and its report.
func (s *Server) dropScan(digest string) {
	s.forgetVulns(digest)
	if err := s.cfg.DB.DeleteScan(digest); err != nil {
		s.cfg.Log.Warn("registry: forgetting a scan", "digest", digest, "err", err)
	}
	if p := s.reportPath(digest); p != "" {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.cfg.Log.Warn("registry: removing a scan's report", "digest", digest, "err", err)
		}
	}
}

// dropOrphanScans forgets the scans of images no repository has any more;
// it answers how many there were.
func (s *Server) dropOrphanScans(dryRun bool) int {
	held := s.cfg.DB.Images("image")
	n := 0
	for _, sc := range s.cfg.DB.Scans() {
		if _, ok := held[sc.Digest]; ok || s.pendingScan(sc.Digest) {
			continue
		}
		n++
		if !dryRun {
			s.dropScan(sc.Digest)
		}
	}
	return n
}

// ---------------------------------------------------------------- reports

// reportPath is where an image's report is kept, or "" without a place.
func (s *Server) reportPath(digest string) string {
	if s.cfg.ScanDir == "" {
		return ""
	}
	alg, hex, ok := strings.Cut(digest, ":")
	if !ok {
		return ""
	}
	return filepath.Join(s.cfg.ScanDir, alg, hex+".json.gz")
}

func (s *Server) writeReport(digest string, res scanner.Result) error {
	p := s.reportPath(digest)
	if p == "" {
		return errors.New("there is no place for reports (Config.ScanDir)")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".report-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	zw := gzip.NewWriter(tmp)
	if err := json.NewEncoder(zw).Encode(res); err != nil {
		tmp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// readReport is an image's last report, with its SBOM; os.ErrNotExist when
// there is none.
func (s *Server) readReport(digest string) (scanner.Result, error) {
	p := s.reportPath(digest)
	if p == "" {
		return scanner.Result{}, os.ErrNotExist
	}
	f, err := os.Open(p)
	if err != nil {
		return scanner.Result{}, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return scanner.Result{}, err
	}
	var res scanner.Result
	if err := json.NewDecoder(io.LimitReader(zr, 256<<20)).Decode(&res); err != nil {
		return scanner.Result{}, err
	}
	return res, nil
}

// ---------------------------------------------------------------- views

// ScanView is what lists show of an artifact's vulnerabilities: an image's
// last scan, or the worst of an index's images.
type ScanView struct {
	// Status is none (never scanned), queued, scanning, done or failed.
	Status   string           `json:"status"`
	Summary  *scanner.Summary `json:"summary,omitempty"`
	Scanned  *time.Time       `json:"scanned,omitempty"`
	Scanner  string           `json:"scanner,omitempty"`
	DB       *time.Time       `json:"db,omitempty"`
	OS       string           `json:"os,omitempty"`
	Packages int              `json:"packages,omitempty"`
	Error    string           `json:"error,omitempty"`
	// Images are an index's images here, Done how many have a result.
	Images int `json:"images,omitempty"`
	Done   int `json:"done,omitempty"`
	// Blocked counts the vulnerabilities its project refuses pulls for.
	Blocked int `json:"blocked,omitempty"`
}

func viewOf(sc meta.Scan, ok bool) ScanView {
	if !ok {
		return ScanView{Status: "none"}
	}
	return ScanView{Status: sc.Status, Summary: sc.Summary, Scanned: sc.Scanned, Scanner: sc.Scanner, DB: sc.DB, OS: sc.OS,
		Packages: sc.Packages, Error: sc.Error}
}

// scanView is an artifact's ScanView: nil for what is not scanned, or for
// all when the registry has no scanner and never had one.
func (s *Server) scanView(a meta.Artifact, byDigest map[string]meta.Artifact) *ScanView {
	switch a.Kind {
	case "image":
		sc, ok := s.cfg.DB.Scan(a.Digest)
		if !ok && s.cfg.Scanner == nil {
			return nil
		}
		v := viewOf(sc, ok)
		return &v
	case "index":
		var views []ScanView
		for _, m := range a.Manifests {
			if c, ok := byDigest[m.Digest]; ok && c.Kind == "image" {
				sc, ok := s.cfg.DB.Scan(m.Digest)
				views = append(views, viewOf(sc, ok))
			}
		}
		if len(views) == 0 {
			return nil
		}
		out := ScanView{Images: len(views)}
		var sums []scanner.Summary
		states := map[string]int{}
		for _, v := range views {
			states[v.Status]++
			if v.Summary != nil {
				out.Done++
				sums = append(sums, *v.Summary)
			}
			if v.Scanned != nil && (out.Scanned == nil || v.Scanned.After(*out.Scanned)) {
				out.Scanned, out.Scanner, out.DB = v.Scanned, v.Scanner, v.DB
			}
			if v.Error != "" {
				out.Error = v.Error
			}
		}
		if len(sums) > 0 {
			w := scanner.Worst(sums...)
			out.Summary = &w
		}
		switch {
		case states[meta.ScanScanning] > 0:
			out.Status = meta.ScanScanning
		case states[meta.ScanQueued] > 0:
			out.Status = meta.ScanQueued
		case states[meta.ScanFailed] > 0:
			out.Status = meta.ScanFailed
		case states[meta.ScanDone] == len(views):
			out.Status = meta.ScanDone
		default:
			out.Status = "none"
		}
		if out.Done == 0 && s.cfg.Scanner == nil {
			return nil
		}
		return &out
	}
	return nil
}

// ---------------------------------------------------------------- scanning all

// ScanReport is what scanning every image found.
type ScanReport struct {
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	// Scanner is what scanned them, DB when its database was gathered, and
	// DBError why updating it failed (they were scanned with the old one).
	Scanner string     `json:"scanner,omitempty"`
	DB      *time.Time `json:"db,omitempty"`
	DBError string     `json:"dbError,omitempty"`
	// Images were scanned, of which Failed failed; Critical and High are
	// how many have such a vulnerability.
	Images   int        `json:"images"`
	Scanned  int        `json:"scanned"`
	Failed   int        `json:"failed"`
	Critical int        `json:"critical"`
	High     int        `json:"high"`
	Failures []ScanItem `json:"failures,omitempty"`
}

// ScanItem is an image a scan of all failed for.
type ScanItem struct {
	Repo   string `json:"repo"`
	Digest string `json:"digest"`
	Error  string `json:"error"`
}

// maxFailures is how many failures a report lists.
const maxFailures = 50

func (r ScanReport) String() string {
	s := fmt.Sprintf("%d images scanned, %d failed; %d with critical and %d with high vulnerabilities", r.Scanned, r.Failed, r.Critical, r.High)
	if r.DBError != "" {
		s += "; the vulnerability DB was not updated"
	}
	return s
}

// ScanAll updates the scanner's databases and scans every image again,
// waiting for each; progress hears how far it got. Stopped, it takes out
// of the queue what it put there and was not scanned yet.
func (s *Server) ScanAll(ctx context.Context, by string, progress func(meta.JobProgress)) (ScanReport, error) {
	start := time.Now()
	rep := ScanReport{Started: s.now().UTC()}
	if s.cfg.Scanner == nil {
		return rep, ErrNoScanner
	}
	st, err := s.cfg.Scanner.UpdateDB(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		rep.DBError = err.Error()
		st, _ = s.cfg.Scanner.Status(ctx)
	}
	rep.Scanner = st.Scanner
	if st.DB != nil {
		rep.DB = st.DB.UpdatedAt
	}
	images := s.cfg.DB.Images("image")
	digests := make([]string, 0, len(images))
	for d := range images {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	rep.Images = len(digests)
	mine := map[string]bool{}
	for _, d := range digests {
		added, err := s.queue(images[d], d, by)
		if err != nil {
			s.unqueue(mine)
			return rep, err
		}
		if added {
			mine[d] = true
		}
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		done := 0
		for _, d := range digests {
			if !s.pendingScan(d) {
				done++
			}
		}
		if progress != nil {
			progress(meta.JobProgress{Done: done, Total: len(digests)})
		}
		if done == len(digests) {
			break
		}
		select {
		case <-ctx.Done():
			s.unqueue(mine)
			return rep, ctx.Err()
		case <-tick.C:
		}
	}
	for _, d := range digests {
		sc, ok := s.cfg.DB.Scan(d)
		if !ok {
			continue
		}
		switch sc.Status {
		case meta.ScanDone:
			rep.Scanned++
			if sc.Summary != nil && sc.Summary.Critical > 0 {
				rep.Critical++
			}
			if sc.Summary != nil && sc.Summary.High > 0 {
				rep.High++
			}
		case meta.ScanFailed:
			rep.Failed++
			if len(rep.Failures) < maxFailures {
				rep.Failures = append(rep.Failures, ScanItem{Repo: sc.Repo, Digest: d, Error: sc.Error})
			}
		}
	}
	rep.Seconds = time.Since(start).Seconds()
	return rep, nil
}
