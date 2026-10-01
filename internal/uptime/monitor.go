package uptime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

const (
	// keepFor is how long results are kept, for the uptime and the bars.
	keepFor = 24 * time.Hour
	// keepResults bounds a check's history; 24 hours every 30 seconds.
	keepResults = 2880
	// maxConcurrent bounds the requests in flight at once.
	maxConcurrent = 20
)

// ErrNotFound is a check that does not exist (any more).
var ErrNotFound = errors.New("no such check")

// Monitor runs the checks kept in the settings.
type Monitor struct {
	keeper *settings.Keeper
	alerts *alert.Manager // nil: no alerts
	log    *slog.Logger
	// Probe, Now and Jitter can be replaced in tests. Jitter picks when
	// a check is first requested, up to the given time.
	Probe  func(context.Context, settings.Check) Result
	Now    func() time.Time
	Jitter func(time.Duration) time.Duration

	sem chan struct{}

	mu      sync.Mutex
	ctx     context.Context
	running map[string]*runner
	history map[string][]Result // by check ID, oldest first
	// edit keeps changes to the checks in order; raising keeps the alerts
	// in order, so an older picture never replaces a newer one.
	raising sync.Mutex
	edit    sync.Mutex
}

type runner struct {
	check  settings.Check
	cancel context.CancelFunc
}

func New(keeper *settings.Keeper, alerts *alert.Manager, log *slog.Logger) *Monitor {
	return &Monitor{keeper: keeper, alerts: alerts, log: log, Probe: Probe, Now: time.Now, Jitter: jitter,
		sem: make(chan struct{}, maxConcurrent), running: map[string]*runner{}, history: map[string][]Result{}}
}

// Start runs the checks until ctx ends. Their first requests are spread
// over a little while, so a restart does not fire them all at once.
func (m *Monitor) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	m.reconcile(30 * time.Second)
}

// reconcile starts and stops runners to match the saved checks. A new or
// changed check is first requested within spread.
func (m *Monitor) reconcile(spread time.Duration) {
	checks := m.keeper.Get().Checks
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil {
		return // not started
	}
	want := map[string]settings.Check{}
	for _, c := range checks {
		want[c.ID] = c
	}
	for id, r := range m.running {
		if c, ok := want[id]; !ok || c != r.check {
			r.cancel()
			delete(m.running, id)
		}
	}
	for id, c := range want {
		if _, ok := m.running[id]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(m.ctx)
		m.running[id] = &runner{check: c, cancel: cancel}
		first := m.Jitter(min(spread, time.Duration(c.Interval)*time.Second))
		go m.run(ctx, c, first)
	}
	for id := range m.history {
		if _, ok := want[id]; !ok {
			delete(m.history, id)
		}
	}
}

func (m *Monitor) run(ctx context.Context, c settings.Check, first time.Duration) {
	wait := first
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = time.Duration(c.Interval) * time.Second
		select {
		case m.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		res := m.Probe(ctx, c)
		<-m.sem
		if ctx.Err() != nil {
			return // stopped or changed while asking: not this check's result any more
		}
		m.record(c, res)
	}
}

// record adds a result of a check that still runs as it was, and brings
// the alerts up to date.
func (m *Monitor) record(c settings.Check, res Result) {
	m.mu.Lock()
	if r, ok := m.running[c.ID]; !ok || r.check != c {
		m.mu.Unlock()
		return
	}
	h := m.history[c.ID]
	// Only the latest result keeps its certificate; it is all that is shown.
	if n := len(h); n > 0 {
		h[n-1].Cert = nil
	}
	h = append(h, res)
	cut := 0
	for cut < len(h) && (res.Time.Sub(h[cut].Time) > keepFor || len(h)-cut > keepResults) {
		cut++
	}
	m.history[c.ID] = h[cut:]
	m.mu.Unlock()
	m.raise()
}

// raise tells the alert manager which checks fail and which certificates
// expire soon, by the latest result of each.
func (m *Monitor) raise() {
	if m.alerts == nil {
		return
	}
	m.raising.Lock()
	defer m.raising.Unlock()
	now := m.Now()
	var found []alert.Alert
	m.mu.Lock()
	for _, r := range m.running {
		h := m.history[r.check.ID]
		if len(h) == 0 {
			continue
		}
		last := h[len(h)-1]
		if !last.OK {
			found = append(found, alert.Alert{Kind: "URLDown", Severity: "critical", Object: r.check.Name, Detail: last.Error})
		}
		if last.Cert != nil {
			if a, ok := m.alerts.CertificateAlert(last.Cert.NotAfter, now); ok {
				a.Object = r.check.Name
				a.Detail = hostOf(r.check.URL) + ": " + a.Detail
				found = append(found, a)
			}
		}
	}
	m.mu.Unlock()
	m.alerts.ObserveChecks(found, now)
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// Status is a check with how it has been doing.
type Status struct {
	settings.Check
	Last *Result `json:"last,omitempty"`
	// Since is when the check's current state, up or down, began, as far
	// as the kept results go back.
	Since *time.Time `json:"since,omitempty"`
	// Uptime is the share of good results over the kept ones, in percent.
	Uptime    *float64 `json:"uptime,omitempty"`
	AvgMillis int64    `json:"avgMs,omitempty"`
	// Hours are the last 24 hours, oldest first.
	Hours []Hour `json:"hours"`
}

// Hour sums up an hour of a check's results.
type Hour struct {
	Start  time.Time `json:"start"`
	Checks int       `json:"checks"`
	Failed int       `json:"failed"`
}

// List describes every check, by name.
func (m *Monitor) List() []Status {
	now := m.Now().UTC()
	checks := m.keeper.Get().Checks
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(checks))
	hourStart := now.Truncate(time.Hour).Add(-23 * time.Hour)
	for _, c := range checks {
		st := Status{Check: c, Hours: make([]Hour, 24)}
		for i := range st.Hours {
			st.Hours[i].Start = hourStart.Add(time.Duration(i) * time.Hour)
		}
		h := m.history[c.ID]
		if len(h) > 0 {
			last := h[len(h)-1]
			st.Last = &last
			since := h[0].Time
			for i := len(h) - 1; i >= 0; i-- {
				if h[i].OK != last.OK {
					break
				}
				since = h[i].Time
			}
			st.Since = &since
			ok, total := 0, int64(0)
			for _, r := range h {
				if r.OK {
					ok++
				}
				total += r.Millis
				if i := int(r.Time.Sub(hourStart) / time.Hour); i >= 0 && i < 24 {
					st.Hours[i].Checks++
					if !r.OK {
						st.Hours[i].Failed++
					}
				}
			}
			up := 100 * float64(ok) / float64(len(h))
			st.Uptime, st.AvgMillis = &up, total/int64(len(h))
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Where names the store the checks are kept in; empty means memory.
func (m *Monitor) Where() string { return m.keeper.Where() }

// LoadError is why the saved checks could not be read, if they could not.
func (m *Monitor) LoadError() string { return m.keeper.LoadError() }

// prepare checks a check against the others.
func prepare(c *settings.Check, others []settings.Check) error {
	if err := c.Normalize(); err != nil {
		return &settings.InvalidError{Err: err}
	}
	for _, o := range others {
		if o.ID != c.ID && strings.EqualFold(o.Name, c.Name) {
			return &settings.InvalidError{Err: fmt.Errorf("there is already a check named %q", c.Name)}
		}
	}
	return nil
}

// Add saves a new check and starts it.
func (m *Monitor) Add(ctx context.Context, c settings.Check) (settings.Check, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	c.ID = settings.NewCheckID()
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if len(s.Checks) >= settings.MaxChecks {
			return &settings.InvalidError{Err: fmt.Errorf("at most %d checks", settings.MaxChecks)}
		}
		if err := prepare(&c, s.Checks); err != nil {
			return err
		}
		s.Checks = append(s.Checks, c)
		return nil
	})
	if err != nil {
		return settings.Check{}, err
	}
	m.reconcile(2 * time.Second)
	return c, nil
}

// Change saves a check's new settings. A check that now asks another
// address starts its history over.
func (m *Monitor) Change(ctx context.Context, id string, c settings.Check) (settings.Check, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	c.ID = id
	var before settings.Check
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Checks, func(x settings.Check) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		if err := prepare(&c, s.Checks); err != nil {
			return err
		}
		before, s.Checks[i] = s.Checks[i], c
		return nil
	})
	if err != nil {
		return settings.Check{}, err
	}
	if before.URL != c.URL {
		m.mu.Lock()
		delete(m.history, id)
		m.mu.Unlock()
	}
	m.reconcile(2 * time.Second)
	m.raise()
	return c, nil
}

// Remove deletes a check, with its history and alerts.
func (m *Monitor) Remove(ctx context.Context, id string) (settings.Check, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	var gone settings.Check
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Checks, func(x settings.Check) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		gone = s.Checks[i]
		s.Checks = slices.Delete(s.Checks, i, i+1)
		return nil
	})
	if err != nil {
		return settings.Check{}, err
	}
	m.reconcile(0)
	m.raise()
	return gone, nil
}

// Try requests a check's address once, without saving the check.
func (m *Monitor) Try(ctx context.Context, c settings.Check) (Result, error) {
	if err := c.Normalize(); err != nil {
		return Result{}, &settings.InvalidError{Err: err}
	}
	return m.Probe(ctx, c), nil
}

// jitter picks a random wait up to most.
func jitter(most time.Duration) time.Duration {
	if most <= 0 {
		return 0
	}
	return rand.N(most)
}

// Reload starts and stops checks to match the kept ones, for when they
// could be read only after the server started.
func (m *Monitor) Reload() { m.reconcile(30 * time.Second) }
