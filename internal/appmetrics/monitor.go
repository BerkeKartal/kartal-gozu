// Package appmetrics follows the metrics that applications expose in their
// pods. The server reads the watched ones through each cluster's agent,
// keeps a day of them in memory, and raises an alert when one passes the
// limit set for it.
package appmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

const (
	// DefaultEvery is how often the watched metrics are read.
	DefaultEvery = 30 * time.Second
	// keepFor and keepPoints bound a watch's history: a day, every 30
	// seconds.
	keepFor    = 24 * time.Hour
	keepPoints = 2880
	// staleAfter is when the last value is too old to raise an alert on:
	// whatever stopped the reading is the problem then, and says so.
	staleAfter = 10 * time.Minute
	// One command reads at most this many pods and metrics (the agent's
	// own bounds); a watch reads at most maxPods pods.
	podsPerCommand    = 50
	metricsPerCommand = 20
	maxPods           = 50
	// shownPoints is the most a chart is sent: more would not show.
	shownPoints = 360
)

// ErrNotFound is a watch that does not exist (any more), or not where it
// was looked for.
var ErrNotFound = errors.New("no such watch")

// Point is one value of a watch.
type Point struct {
	T int64   `json:"t"` // Unix milliseconds
	V float64 `json:"v"`
}

type reading struct {
	v float64
	t time.Time
}

// series is what a watch has read so far.
type series struct {
	reads  string // settings.Watch.Reads of the points
	points []Point
	// last is a counter's previous value, by pod and labels, for its rate;
	// readAt is when the pods were last read.
	last   map[string]reading
	readAt time.Time
	err    string
	pods   int
}

// Monitor reads the watches kept in the settings.
type Monitor struct {
	keeper *settings.Keeper
	alerts *alert.Manager // nil: no alerts
	log    *slog.Logger
	// Every and Now can be replaced in tests and the demo.
	Every time.Duration
	Now   func() time.Time

	// pods lists a cluster's pods as its agent last reported them; ask
	// sends its agent a command and waits for the result. See Attach.
	pods func(cluster string) ([]protocol.Pod, bool)
	ask  func(ctx context.Context, cluster string, cmd protocol.Command) (protocol.Result, error)

	mu      sync.Mutex
	series  map[string]*series // by watch ID
	alerted map[string]bool    // clusters told about metric alerts
	// round keeps one reading at a time; edit keeps changes in order;
	// raising keeps the alerts in order.
	round   sync.Mutex
	edit    sync.Mutex
	raising sync.Mutex
}

func New(keeper *settings.Keeper, alerts *alert.Manager, log *slog.Logger) *Monitor {
	return &Monitor{keeper: keeper, alerts: alerts, log: log, Every: DefaultEvery, Now: time.Now,
		series: map[string]*series{}, alerted: map[string]bool{}}
}

// Attach gives the monitor its way to the clusters: their pods, from the
// latest snapshots, and a way to ask their agents.
func (m *Monitor) Attach(pods func(string) ([]protocol.Pod, bool), ask func(context.Context, string, protocol.Command) (protocol.Result, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pods, m.ask = pods, ask
}

// Start reads the watches every m.Every until ctx ends, the first time
// shortly after the agents had a chance to report.
func (m *Monitor) Start(ctx context.Context) {
	go func() {
		wait := min(10*time.Second, m.Every)
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

// Round reads every watch once, cluster by cluster, and brings the alerts
// up to date.
func (m *Monitor) Round(ctx context.Context) {
	m.round.Lock()
	defer m.round.Unlock()
	m.mu.Lock()
	attached := m.pods != nil && m.ask != nil
	m.mu.Unlock()
	if !attached {
		return
	}
	watches := m.keeper.Get().Watches
	m.forget(watches)
	byCluster := map[string][]settings.Watch{}
	for _, w := range watches {
		byCluster[w.Cluster] = append(byCluster[w.Cluster], w)
	}
	var wg sync.WaitGroup
	for cluster, list := range byCluster {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.readCluster(ctx, cluster, list)
		}()
	}
	wg.Wait()
	m.raise()
}

// forget drops the history of watches that are gone.
func (m *Monitor) forget(watches []settings.Watch) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.series {
		if !slices.ContainsFunc(watches, func(w settings.Watch) bool { return w.ID == id }) {
			delete(m.series, id)
		}
	}
}

// endpoint is where a group of pods is read from: one command reads all
// the watches' pods and metrics there.
type endpoint struct{ ns, port, path string }

type want struct {
	pods    map[string]bool
	metrics map[string]bool
}

func (m *Monitor) readCluster(ctx context.Context, cluster string, list []settings.Watch) {
	now := m.Now()
	pods, ok := m.pods(cluster)
	if !ok {
		for _, w := range list {
			m.fail(w, "the agent of this cluster is not connected")
		}
		return
	}
	targets := map[string][]string{}
	wants := map[endpoint]*want{}
	for _, w := range list {
		ps := podsOf(w, pods)
		if len(ps) == 0 {
			m.fail(w, "no running pod of "+w.Target)
			continue
		}
		targets[w.ID] = ps
		e := endpoint{w.Namespace, w.Port, w.Path}
		if wants[e] == nil {
			wants[e] = &want{pods: map[string]bool{}, metrics: map[string]bool{}}
		}
		for _, p := range ps {
			wants[e].pods[p] = true
		}
		wants[e].metrics[w.Metric] = true
	}
	got := map[endpoint]map[string]protocol.PodSamples{}
	failed := map[endpoint]string{}
	for e, wt := range wants {
		got[e] = map[string]protocol.PodSamples{}
		pods, metrics := sortedKeys(wt.pods), sortedKeys(wt.metrics)
		for p := 0; p < len(pods); p += podsPerCommand {
			for q := 0; q < len(metrics); q += metricsPerCommand {
				cmd := protocol.Command{Type: protocol.CommandSample, Namespace: e.ns, Port: e.port, Path: e.path,
					Pods: pods[p:min(p+podsPerCommand, len(pods))], Metrics: metrics[q:min(q+metricsPerCommand, len(metrics))]}
				res, err := m.ask(ctx, cluster, cmd)
				var answers []protocol.PodSamples
				if err == nil {
					err = json.Unmarshal([]byte(res.Output), &answers)
				}
				if err != nil {
					failed[e] = err.Error()
					continue
				}
				for _, a := range answers {
					have := got[e][a.Pod]
					have.Pod = a.Pod
					have.Samples = append(have.Samples, a.Samples...)
					if a.Error != "" {
						have.Error = a.Error
					}
					got[e][a.Pod] = have
				}
			}
		}
	}
	for _, w := range list {
		ps, ok := targets[w.ID]
		if !ok {
			continue
		}
		e := endpoint{w.Namespace, w.Port, w.Path}
		if msg, bad := failed[e]; bad {
			m.fail(w, msg)
			continue
		}
		m.record(w, ps, got[e], now)
	}
}

// podsOf are the running pods a watch reads, by name.
func podsOf(w settings.Watch, pods []protocol.Pod) []string {
	kind, name, _ := strings.Cut(w.Target, "/")
	var out []string
	for _, p := range pods {
		if p.Namespace != w.Namespace || p.Phase != "Running" {
			continue
		}
		if (kind == "Pod" && p.Name == name) || (kind != "Pod" && p.Owner == w.Target) {
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out[:min(len(out), maxPods)]
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// seriesOf is a watch's series; one that read something else starts over.
func (m *Monitor) seriesOf(w settings.Watch) *series {
	s := m.series[w.ID]
	if s == nil || s.reads != w.Reads() {
		s = &series{reads: w.Reads(), last: map[string]reading{}}
		m.series[w.ID] = s
	}
	return s
}

func (m *Monitor) fail(w settings.Watch, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.seriesOf(w)
	s.err, s.pods = msg, 0
}

// record turns what the pods answered into the watch's next point: each
// matching series' value, or for a counter how fast it grew since the last
// reading, joined over the pods.
//
// A metric that the pods expose, but with no series of the labels asked
// for, counts as zero: no request has failed with code 502 yet, no app is
// Degraded. A counter's series that appears between two readings started
// from zero, as counters do, so all it counts is new. Only a metric that is
// not there at all is an error: the wrong name, port or path.
func (m *Monitor) record(w settings.Watch, pods []string, answers map[string]protocol.PodSamples, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.seriesOf(w)
	var values []float64
	matched, failed := 0, 0
	named := false
	firstErr := ""
	seen := map[string]bool{}
	answered := map[string]bool{}
	for _, pod := range pods {
		a, ok := answers[pod]
		if !ok || a.Error != "" {
			failed++
			if firstErr == "" {
				firstErr = a.Error
				if !ok {
					firstErr = pod + " did not answer"
				}
			}
			continue
		}
		answered[pod] = true
		for _, smp := range a.Samples {
			v := float64(smp.Value)
			if smp.Name == w.Metric {
				named = true
			}
			if smp.Name != w.Metric || !labelsMatch(w.Labels, smp.Labels) || math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			matched++
			if !w.Rate {
				values = append(values, v)
				continue
			}
			key := pod + "\x00" + labelKey(smp.Labels)
			seen[key] = true
			prev, had := s.last[key]
			if !had && !s.readAt.IsZero() {
				prev, had = reading{v: 0, t: s.readAt}, true
			}
			if had && now.After(prev.t) {
				grew := v - prev.v
				if grew < 0 {
					grew = v // the counter started over, as a restarted pod's does
				}
				values = append(values, grew/now.Sub(prev.t).Seconds())
			}
			s.last[key] = reading{v: v, t: now}
		}
	}
	// A series is forgotten once its pod answered without it, or is no
	// longer read; a pod that did not answer keeps its own, so that a
	// counter is not taken for new when the pod answers again.
	for k := range s.last {
		pod, _, _ := strings.Cut(k, "\x00")
		if !seen[k] && (answered[pod] || !slices.Contains(pods, pod)) {
			delete(s.last, k)
		}
	}
	s.pods = len(pods) - failed
	switch {
	case failed == len(pods):
		s.err = firstErr
		return
	case !named:
		s.err = fmt.Sprintf("no sample named %s on %s", w.Metric, w.Target)
		return
	case failed > 0:
		s.err = fmt.Sprintf("%d of %d pods could not be read: %s", failed, len(pods), firstErr)
	default:
		s.err = ""
	}
	first := s.readAt.IsZero()
	s.readAt = now
	value := 0.0
	switch {
	case len(values) > 0:
		value = join(w.Aggregate, values)
	case matched > 0 && w.Rate && first:
		return // a rate needs two readings
	}
	s.points = append(s.points, Point{T: now.UnixMilli(), V: value})
	cut := 0
	for cut < len(s.points) && (now.UnixMilli()-s.points[cut].T > keepFor.Milliseconds() || len(s.points)-cut > keepPoints) {
		cut++
	}
	s.points = s.points[cut:]
}

func labelsMatch(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + labels[k] + "\x00")
	}
	return b.String()
}

func labelText(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var parts []string
	for k, v := range labels {
		parts = append(parts, k+"="+strconv.Quote(v))
	}
	sort.Strings(parts)
	return "{" + strings.Join(parts, ",") + "}"
}

func join(how string, values []float64) float64 {
	out := values[0]
	switch how {
	case "max":
		for _, v := range values[1:] {
			out = max(out, v)
		}
	case "min":
		for _, v := range values[1:] {
			out = min(out, v)
		}
	default:
		for _, v := range values[1:] {
			out += v
		}
		if how == "avg" {
			out /= float64(len(values))
		}
	}
	return out
}

// past tells whether a watch's last value, if recent, is past a limit.
func past(w settings.Watch, s *series, now time.Time) (string, float64, bool) {
	if s == nil || len(s.points) == 0 {
		return "", 0, false
	}
	last := s.points[len(s.points)-1]
	if now.UnixMilli()-last.T > staleAfter.Milliseconds() {
		return "", 0, false
	}
	switch {
	case w.Above != nil && last.V > *w.Above:
		return "above", last.V, true
	case w.Below != nil && last.V < *w.Below:
		return "below", last.V, true
	}
	return "", 0, false
}

// raise tells the alert manager which watches are past their limits, for
// every cluster that has watches or had alerts about them. It goes by the
// watches as they are now: a round that read a watch removed meanwhile
// must not bring its alert back. One picture is told at a time, so an
// older one never replaces a newer one.
func (m *Monitor) raise() {
	if m.alerts == nil {
		return
	}
	m.raising.Lock()
	defer m.raising.Unlock()
	watches := m.keeper.Get().Watches
	m.forget(watches)
	now := m.Now()
	byCluster := map[string][]alert.Alert{}
	m.mu.Lock()
	for _, w := range watches {
		list := byCluster[w.Cluster]
		s := m.series[w.ID]
		if s != nil && s.reads != w.Reads() {
			s = nil
		}
		if side, v, ok := past(w, s, now); ok {
			limit := w.Above
			if side == "below" {
				limit = w.Below
			}
			per := ""
			if w.Rate {
				per = " per second"
			}
			list = append(list, alert.Alert{Severity: "warning", Namespace: w.Namespace, Object: w.Name,
				Detail: fmt.Sprintf("%s%s is %s %s (%s of %s%s on %s)", Number(v), per, side, Number(*limit), w.Aggregate, w.Metric, labelText(w.Labels), w.Target)})
		}
		byCluster[w.Cluster] = list
	}
	for c := range m.alerted {
		if _, ok := byCluster[c]; !ok {
			byCluster[c] = nil
		}
	}
	m.alerted = map[string]bool{}
	for c := range byCluster {
		m.alerted[c] = true
	}
	m.mu.Unlock()
	for c, list := range byCluster {
		m.alerts.ObserveMetrics(c, list, now)
	}
}

// Number writes a value for people: a few significant digits.
func Number(v float64) string {
	return strconv.FormatFloat(v, 'g', 4, 64)
}

// Status is a watch with what it read.
type Status struct {
	settings.Watch
	// Points are the asked time's values, oldest first, averaged down to
	// what a chart can show.
	Points []Point `json:"points"`
	Last   *Point  `json:"last,omitempty"`
	Error  string  `json:"error,omitempty"`
	// Pods is how many pods answered the last reading.
	Pods int `json:"pods"`
	// Past is "above" or "below" while the value is past a limit.
	Past string `json:"past,omitempty"`
}

// List describes the watches that pick lets through, by name, with the
// last hours of their values.
func (m *Monitor) List(pick func(settings.Watch) bool, hours int) []Status {
	now := m.Now()
	from := now.Add(-time.Duration(hours) * time.Hour).UnixMilli()
	watches := m.keeper.Get().Watches
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Status{}
	for _, w := range watches {
		if !pick(w) {
			continue
		}
		st := Status{Watch: w, Points: []Point{}}
		if s := m.series[w.ID]; s != nil && s.reads == w.Reads() {
			st.Error, st.Pods = s.err, s.pods
			if n := len(s.points); n > 0 {
				last := s.points[n-1]
				st.Last = &last
			}
			st.Points = thin(s.points, from, shownPoints)
			st.Past, _, _ = past(w, s, now)
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// thin keeps the points from a time on, averaging neighbours together so
// that at most most remain.
func thin(points []Point, from int64, most int) []Point {
	i := sort.Search(len(points), func(i int) bool { return points[i].T >= from })
	points = points[i:]
	if len(points) <= most {
		return append([]Point{}, points...)
	}
	out := make([]Point, 0, most)
	per := float64(len(points)) / float64(most)
	for b := 0; b < most; b++ {
		lo, hi := int(float64(b)*per), int(float64(b+1)*per)
		if hi <= lo {
			continue
		}
		var t, v float64
		for _, p := range points[lo:hi] {
			t += float64(p.T)
			v += p.V
		}
		n := float64(hi - lo)
		out = append(out, Point{T: int64(t / n), V: v / n})
	}
	return out
}

// Where names the store the watches are kept in; empty means memory.
func (m *Monitor) Where() string { return m.keeper.Where() }

// LoadError is why the saved watches could not be read, if they could not.
func (m *Monitor) LoadError() string { return m.keeper.LoadError() }

// prepare checks a watch against the others of its namespace.
func prepare(w *settings.Watch, others []settings.Watch) error {
	if err := w.Normalize(); err != nil {
		return &settings.InvalidError{Err: err}
	}
	for _, o := range others {
		if o.ID != w.ID && o.Cluster == w.Cluster && o.Namespace == w.Namespace && strings.EqualFold(o.Name, w.Name) {
			return &settings.InvalidError{Err: fmt.Errorf("namespace %s already has a watch named %q", w.Namespace, w.Name)}
		}
	}
	return nil
}

// Add saves a new watch; it is first read in the next round.
func (m *Monitor) Add(ctx context.Context, w settings.Watch) (settings.Watch, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	w.ID = settings.NewCheckID()
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if len(s.Watches) >= settings.MaxWatches {
			return &settings.InvalidError{Err: fmt.Errorf("at most %d watches", settings.MaxWatches)}
		}
		if err := prepare(&w, s.Watches); err != nil {
			return err
		}
		s.Watches = append(s.Watches, w)
		return nil
	})
	if err != nil {
		return settings.Watch{}, err
	}
	return w, nil
}

// Change saves a watch's new settings, if mine says the watch is the
// caller's to change. One that reads something else starts its history
// over.
func (m *Monitor) Change(ctx context.Context, id string, w settings.Watch, mine func(settings.Watch) bool) (settings.Watch, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	w.ID = id
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Watches, func(x settings.Watch) bool { return x.ID == id })
		if i < 0 || !mine(s.Watches[i]) {
			return ErrNotFound
		}
		if err := prepare(&w, s.Watches); err != nil {
			return err
		}
		s.Watches[i] = w
		return nil
	})
	if err != nil {
		return settings.Watch{}, err
	}
	m.raise()
	return w, nil
}

// Remove deletes a watch, with its history and alert.
func (m *Monitor) Remove(ctx context.Context, id string, mine func(settings.Watch) bool) (settings.Watch, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	var gone settings.Watch
	s, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Watches, func(x settings.Watch) bool { return x.ID == id })
		if i < 0 || !mine(s.Watches[i]) {
			return ErrNotFound
		}
		gone = s.Watches[i]
		s.Watches = slices.Delete(s.Watches, i, i+1)
		return nil
	})
	if err != nil {
		return settings.Watch{}, err
	}
	m.forget(s.Watches)
	m.raise()
	return gone, nil
}
