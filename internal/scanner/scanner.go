// Package scanner scans images for known vulnerabilities. kartal-scanner
// runs Trivy on the registry's behalf (Service) behind a small HTTP API,
// which the registry calls with a Client. What both send is here: what to
// scan, the report, the SBOM, and the scanner's state.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// The severities, the most severe first.
const (
	Critical = "CRITICAL"
	High     = "HIGH"
	Medium   = "MEDIUM"
	Low      = "LOW"
	Unknown  = "UNKNOWN"
)

// Severities are the severities, the most severe first.
var Severities = []string{Critical, High, Medium, Low, Unknown}

// Rank orders severities: 4 for critical down to 0 for unknown, and -1 for
// what is not a severity.
func Rank(severity string) int {
	switch strings.ToUpper(severity) {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	case Unknown:
		return 0
	}
	return -1
}

// Request asks for an image to be scanned: where to pull it from, by
// digest, and with what credentials.
type Request struct {
	// Image is host[:port]/repository@sha256:...
	Image    string `json:"image"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Insecure pulls over plain HTTP, or without checking the certificate.
	Insecure bool `json:"insecure,omitempty"`
}

// Vulnerability is a known vulnerability of a package the image holds.
type Vulnerability struct {
	ID        string     `json:"id"`
	Package   string     `json:"package"`
	Installed string     `json:"installed"`
	Fixed     string     `json:"fixed,omitempty"`
	Severity  string     `json:"severity"`
	Score     float64    `json:"score,omitempty"`
	Title     string     `json:"title,omitempty"`
	URL       string     `json:"url,omitempty"`
	Status    string     `json:"status,omitempty"`
	Published *time.Time `json:"published,omitempty"`
	// Target is where in the image it is (the OS, a jar, a Go binary), and
	// Type the kind of package (debian, alpine, jar, gobinary...).
	Target string `json:"target,omitempty"`
	Type   string `json:"type,omitempty"`
}

// Report is what a scan found.
type Report struct {
	// Scanner is what scanned it ("Trivy 0.69.3"); DB when the
	// vulnerabilities it knows were last gathered.
	Scanner string     `json:"scanner"`
	DB      *time.Time `json:"db,omitempty"`
	// OS is the image's distribution, as "debian 12.5", if it has one.
	OS              string          `json:"os,omitempty"`
	Packages        int             `json:"packages"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Result is a scan's report with the image's SBOM, as CycloneDX.
type Result struct {
	Report Report          `json:"report"`
	SBOM   json.RawMessage `json:"sbom,omitempty"`
}

// Summary counts vulnerabilities by severity; Fixable are those a newer
// version of their package fixes.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Fixable  int `json:"fixable"`
}

// Summarize counts vulnerabilities.
func Summarize(vulns []Vulnerability) Summary {
	var s Summary
	for _, v := range vulns {
		s.add(v.Severity, 1)
		if v.Fixed != "" {
			s.Fixable++
		}
	}
	return s
}

func (s *Summary) add(severity string, n int) {
	switch Rank(severity) {
	case 4:
		s.Critical += n
	case 3:
		s.High += n
	case 2:
		s.Medium += n
	case 1:
		s.Low += n
	default:
		s.Unknown += n
	}
}

// Total counts them all.
func (s Summary) Total() int { return s.Critical + s.High + s.Medium + s.Low + s.Unknown }

// AtLeast counts those of a severity and the more severe.
func (s Summary) AtLeast(severity string) int {
	n := 0
	for _, c := range []struct {
		rank, n int
	}{{4, s.Critical}, {3, s.High}, {2, s.Medium}, {1, s.Low}, {0, s.Unknown}} {
		if c.rank >= Rank(severity) {
			n += c.n
		}
	}
	return n
}

// Worst is, of each severity, the most any of them has: what the images of
// a multi-platform index have at worst.
func Worst(all ...Summary) Summary {
	var w Summary
	for _, s := range all {
		w.Critical = max(w.Critical, s.Critical)
		w.High = max(w.High, s.High)
		w.Medium = max(w.Medium, s.Medium)
		w.Low = max(w.Low, s.Low)
		w.Unknown = max(w.Unknown, s.Unknown)
		w.Fixable = max(w.Fixable, s.Fixable)
	}
	return w
}

// Sort orders vulnerabilities the most severe first, then by score, then
// by ID and package.
func Sort(vulns []Vulnerability) {
	sort.SliceStable(vulns, func(i, j int) bool {
		a, b := vulns[i], vulns[j]
		if ra, rb := Rank(a.Severity), Rank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Package < b.Package
	})
}

// DBStatus is a vulnerability database the scanner has.
type DBStatus struct {
	// UpdatedAt is when it was built; NextUpdate when a newer one is due;
	// DownloadedAt when the scanner got it.
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
	NextUpdate   *time.Time `json:"nextUpdate,omitempty"`
	DownloadedAt *time.Time `json:"downloadedAt,omitempty"`
}

// Status is the scanner's state.
type Status struct {
	// Scanner is its name and version ("Trivy 0.69.3").
	Scanner string    `json:"scanner"`
	DB      *DBStatus `json:"db,omitempty"`
	JavaDB  *DBStatus `json:"javaDB,omitempty"`
	// Where it gets its databases; empty for Trivy's own.
	DBRepository     string `json:"dbRepository,omitempty"`
	JavaDBRepository string `json:"javaDBRepository,omitempty"`
	// Scanning is how many scans run now, of Workers at once; Waiting how
	// many wait their turn.
	Scanning int `json:"scanning"`
	Waiting  int `json:"waiting"`
	Workers  int `json:"workers"`
	// Updating says the databases are being updated; LastUpdate when they
	// last were, UpdateError why that last failed.
	Updating    bool       `json:"updating,omitempty"`
	LastUpdate  *time.Time `json:"lastUpdate,omitempty"`
	UpdateError string     `json:"updateError,omitempty"`
}

// ---------------------------------------------------------------- the client

// Client calls a kartal-scanner.
type Client struct {
	// URL is where it is, such as http://kartal-scanner:8090.
	URL    string
	Secret string
	// HTTP makes the calls; one without a timeout when nil, as scans take
	// their time: the calls' contexts end them.
	HTTP *http.Client
}

// ErrScanner is the scanner refusing, or failing, to do what was asked;
// its message says why.
var ErrScanner = errors.New("the scanner")

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("the scanner could not be reached: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResult))
	if err != nil {
		return fmt.Errorf("reading the scanner's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%w: %s", ErrScanner, e.Error)
		}
		return fmt.Errorf("%w answered %d", ErrScanner, resp.StatusCode)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("the scanner's answer cannot be read: %w", err)
	}
	return nil
}

// maxResult is the most a scan's result may be: its report and its SBOM.
const maxResult = 64 << 20

// Scan scans an image.
func (c *Client) Scan(ctx context.Context, req Request) (Result, error) {
	var res Result
	err := c.call(ctx, http.MethodPost, "/scan", req, &res)
	return res, err
}

// UpdateDB has the scanner get its databases anew.
func (c *Client) UpdateDB(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, http.MethodPost, "/db/update", struct{}{}, &st)
	return st, err
}

// Status is the scanner's state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, http.MethodGet, "/status", nil, &st)
	return st, err
}
