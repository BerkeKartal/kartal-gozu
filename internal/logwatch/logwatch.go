// Package logwatch runs the log rules kept in the settings: every minute it
// counts, in an Elasticsearch data source, the lines of the last while that
// match each rule's query, and tells the alert manager which rules have
// more than they allow. It finds what goes wrong while the pods keep
// running, such as an application's database errors.
package logwatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

const (
	// maxConcurrent bounds the counts in flight at once.
	maxConcurrent = 5
	countTimeout  = 30 * time.Second
)

// ErrNotFound is a rule that does not exist (any more).
var ErrNotFound = errors.New("no such log rule")

// Result is one count of a rule's lines.
type Result struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
	// Error is why the lines could not be counted, if they could not.
	Error string `json:"error,omitempty"`
}

// Monitor counts the rules' lines.
type Monitor struct {
	keeper  *settings.Keeper
	sources *datasource.Manager
	alerts  *alert.Manager // nil: no alerts
	log     *slog.Logger
	// Every is how often the rules are counted; Now and Count can be
	// replaced in tests.
	Every time.Duration
	Now   func() time.Time
	Count func(ctx context.Context, src settings.DataSource, rule settings.LogRule, from, to time.Time) (int64, error)

	// round keeps the rounds in order, so an older picture never replaces a
	// newer one; edit, the changes to the rules.
	round sync.Mutex
	edit  sync.Mutex

	mu  sync.Mutex
	ctx context.Context
	// By rule ID: the rule as it was last counted, that count, and the
	// alert it makes, if it does.
	counted map[string]settings.LogRule
	last    map[string]Result
	firing  map[string]string
}

func New(keeper *settings.Keeper, sources *datasource.Manager, alerts *alert.Manager, log *slog.Logger) *Monitor {
	m := &Monitor{keeper: keeper, sources: sources, alerts: alerts, log: log, Every: time.Minute, Now: time.Now,
		counted: map[string]settings.LogRule{}, last: map[string]Result{}, firing: map[string]string{}}
	m.Count = func(ctx context.Context, src settings.DataSource, rule settings.LogRule, from, to time.Time) (int64, error) {
		// A rule is an admin's: it counts in every namespace.
		return sources.Client.ESCount(ctx, src, rule.Index, rule.Query, from.UnixMilli(), to.UnixMilli(), nil)
	}
	return m
}

// Start counts the rules until ctx ends, the first time a little after
// the start, when the agents some sources are reached through are back.
func (m *Monitor) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	go func() {
		wait := min(m.Every, 20*time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = m.Every
			m.Round(ctx)
		}
	}()
}

// again counts the rules once more, soon, after they changed.
func (m *Monitor) again() {
	m.mu.Lock()
	ctx := m.ctx
	m.mu.Unlock()
	if ctx != nil {
		go m.Round(ctx)
	}
}

// source finds the Elasticsearch a rule counts in, among the sources.
func source(sources []settings.DataSource, rule settings.LogRule) (settings.DataSource, error) {
	i := slices.IndexFunc(sources, func(d settings.DataSource) bool { return d.ID == rule.Source })
	if i < 0 {
		return settings.DataSource{}, errors.New("its data source is gone; choose another")
	}
	if sources[i].Type != settings.SourceElasticsearch {
		return sources[i], fmt.Errorf("the data source %s is not an Elasticsearch", sources[i].Name)
	}
	return sources[i], nil
}

// count counts a rule's lines of the window that ends now.
func (m *Monitor) count(ctx context.Context, rule settings.LogRule, now time.Time) Result {
	res := Result{Time: now.UTC()}
	src, err := source(m.sources.List(), rule)
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, countTimeout)
		defer cancel()
		res.Count, err = m.Count(ctx, src, rule, now.Add(-time.Duration(rule.Window)*time.Second), now)
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// span is a number of seconds as people say it: 5m, 1h, 90s.
func span(seconds int) string {
	switch {
	case seconds%3600 == 0:
		return fmt.Sprintf("%dh", seconds/3600)
	case seconds%60 == 0:
		return fmt.Sprintf("%dm", seconds/60)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Round counts every rule once and brings the alerts up to date. A rule
// that could not be counted stays as it was: an Elasticsearch that does
// not answer neither raises its rules' alerts nor resolves them, also
// right after a restart, when only the alert manager knows of them.
func (m *Monitor) Round(ctx context.Context) {
	m.round.Lock()
	defer m.round.Unlock()
	rules := m.keeper.Get().LogRules
	now := m.Now()
	results := make([]Result, len(rules))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, r := range rules {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = m.count(ctx, r, now)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return // stopping: the counts were cut short
	}
	counted, last, firing := map[string]settings.LogRule{}, map[string]Result{}, map[string]string{}
	var found []alert.Alert
	var unsure []string
	m.mu.Lock()
	for i, r := range rules {
		res := results[i]
		// Said once, not every minute an Elasticsearch stays away.
		if res.Error != "" && res.Error != m.last[r.ID].Error && m.log != nil {
			m.log.Warn("a log rule could not be counted", "rule", r.Name, "err", res.Error)
		}
		detail := ""
		switch {
		case res.Error != "":
			unsure = append(unsure, r.Name)
			if m.counted[r.ID] == r {
				detail = m.firing[r.ID]
			}
		case res.Count > r.Above:
			detail = fmt.Sprintf("%d lines in the last %s, more than %d", res.Count, span(r.Window), r.Above)
			found = append(found, alert.Alert{Severity: r.Severity, Object: r.Name, Detail: detail})
		}
		counted[r.ID], last[r.ID] = r, res
		if detail != "" {
			firing[r.ID] = detail
		}
	}
	m.counted, m.last, m.firing = counted, last, firing
	m.mu.Unlock()
	if m.alerts != nil {
		m.alerts.ObserveLogs(found, unsure, now)
	}
}

// Status is a rule with how it is doing.
type Status struct {
	settings.LogRule
	// SourceName is the data source's name, for the list.
	SourceName string  `json:"sourceName,omitempty"`
	Last       *Result `json:"last,omitempty"`
	Firing     bool    `json:"firing"`
}

// List describes every rule, by name.
func (m *Monitor) List() []Status {
	all := m.keeper.Get()
	rules := all.LogRules
	names := map[string]string{}
	for _, d := range all.DataSources {
		names[d.ID] = d.Name
	}
	out := make([]Status, 0, len(rules))
	m.mu.Lock()
	for _, r := range rules {
		st := Status{LogRule: r, SourceName: names[r.Source]}
		// A rule changed since it was counted has no count yet.
		if m.counted[r.ID] == r {
			if res, ok := m.last[r.ID]; ok {
				st.Last = &res
			}
			st.Firing = m.firing[r.ID] != ""
		}
		out = append(out, st)
	}
	m.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Where names the store the rules are kept in; empty means memory.
func (m *Monitor) Where() string { return m.keeper.Where() }

// LoadError is why the saved rules could not be read, if they could not.
func (m *Monitor) LoadError() string { return m.keeper.LoadError() }

func invalid(err error) error { return &settings.InvalidError{Err: err} }

// prepare checks a rule by itself, against the others and its source. It
// reads the settings it is given: while they are being changed, asking
// the keeper for them would wait for itself.
func prepare(r *settings.LogRule, all *settings.Settings) error {
	others := all.LogRules
	if err := r.Normalize(); err != nil {
		return invalid(err)
	}
	for _, o := range others {
		if o.ID != r.ID && strings.EqualFold(o.Name, r.Name) {
			return invalid(fmt.Errorf("there is already a log rule named %q", r.Name))
		}
	}
	if _, err := source(all.DataSources, *r); err != nil {
		return invalid(err)
	}
	return nil
}

// Add saves a new rule; it is counted at once.
func (m *Monitor) Add(ctx context.Context, r settings.LogRule) (settings.LogRule, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	r.ID = settings.NewCheckID()
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if len(s.LogRules) >= settings.MaxLogRules {
			return invalid(fmt.Errorf("at most %d log rules", settings.MaxLogRules))
		}
		if err := prepare(&r, s); err != nil {
			return err
		}
		s.LogRules = append(s.LogRules, r)
		return nil
	})
	if err != nil {
		return settings.LogRule{}, err
	}
	m.again()
	return r, nil
}

// Change saves a rule's new settings; it is counted again at once.
func (m *Monitor) Change(ctx context.Context, id string, r settings.LogRule) (settings.LogRule, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	r.ID = id
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.LogRules, func(x settings.LogRule) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		if err := prepare(&r, s); err != nil {
			return err
		}
		s.LogRules[i] = r
		return nil
	})
	if err != nil {
		return settings.LogRule{}, err
	}
	m.again()
	return r, nil
}

// Remove deletes a rule, with its alert.
func (m *Monitor) Remove(ctx context.Context, id string) (settings.LogRule, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	var gone settings.LogRule
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.LogRules, func(x settings.LogRule) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		gone = s.LogRules[i]
		s.LogRules = slices.Delete(s.LogRules, i, i+1)
		return nil
	})
	if err != nil {
		return settings.LogRule{}, err
	}
	m.again()
	return gone, nil
}

// Try counts a rule's lines once, without saving the rule.
func (m *Monitor) Try(ctx context.Context, r settings.LogRule) (Result, error) {
	if err := r.Normalize(); err != nil {
		return Result{}, invalid(err)
	}
	if _, err := source(m.sources.List(), r); err != nil {
		return Result{}, invalid(err)
	}
	return m.count(ctx, r, m.Now()), nil
}
