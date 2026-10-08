// Package collect keeps every metric of chosen workloads in the server's
// metric store. Each round it asks the clusters' agents for the pages of
// metrics of the workloads' running pods and appends what they hold, with
// the cluster, namespace, pod and workload as labels, until someone deletes
// a range of time (or, with a retention set, until it is that old).
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/promtext"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

const (
	// One command reads at most podsPerCommand pods; a target reads at
	// most maxPods; a cluster runs at most perCluster commands at once:
	// an agent runs only a few commands at a time (agents built before
	// this collector ran four), and those people ask for in the UI must not
	// wait behind these.
	podsPerCommand = 5
	maxPods        = 100
	perCluster     = 2
	// maxSamples is what one pod may add each round (the agent's bound).
	maxSamples = 20000
	// pruneEvery is how often data past the retention is removed.
	pruneEvery = time.Hour
)

// The labels the collector adds; a metric's own label of the same name is
// kept as exported_<name>, as Prometheus does.
const (
	LabelCluster   = "cluster"
	LabelNamespace = "namespace"
	LabelPod       = "pod"
	LabelWorkload  = "workload"
)

// ErrNotFound is a target that does not exist (any more), or not where it
// was looked for.
var ErrNotFound = errors.New("no such collection target")

// Status is a target with how its last reading went.
type Status struct {
	settings.CollectTarget
	// Last is when the pods were last read, in Unix milliseconds; Took is
	// how long that took.
	Last int64 `json:"last,omitempty"`
	Took int64 `json:"took,omitempty"`
	// Pods answered; Failed did not.
	Pods   int `json:"pods"`
	Failed int `json:"failed"`
	// Samples were stored, Truncated pods had more than a round takes.
	Samples   int    `json:"samples"`
	Truncated int    `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Collector reads the targets kept in the settings into the store.
type Collector struct {
	keeper *settings.Keeper
	db     *tsdb.DB
	dir    string
	log    *slog.Logger
	// Now can be replaced in tests.
	Now func() time.Time

	// pods lists a cluster's pods as its agent last reported them; ask
	// sends its agent a command and waits for the result. See Attach.
	pods func(cluster string) ([]protocol.Pod, bool)
	ask  func(ctx context.Context, cluster string, cmd protocol.Command) (protocol.Result, error)

	mu     sync.Mutex
	status map[string]Status // by target ID
	pruned time.Time
	// wake tells the loop that the settings changed; true asks for a
	// round soon, for a new target.
	wake chan bool
	// round keeps one reading at a time; edit keeps changes in order.
	round sync.Mutex
	edit  sync.Mutex
}

// New returns a collector that stores into db, which lives in dir.
func New(keeper *settings.Keeper, db *tsdb.DB, dir string, log *slog.Logger) *Collector {
	return &Collector{keeper: keeper, db: db, dir: dir, log: log, Now: time.Now,
		status: map[string]Status{}, wake: make(chan bool, 1)}
}

// Attach gives the collector its way to the clusters: their pods, from the
// latest snapshots, and a way to ask their agents.
func (c *Collector) Attach(pods func(string) ([]protocol.Pod, bool), ask func(context.Context, string, protocol.Command) (protocol.Result, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pods, c.ask = pods, ask
}

// DB is the store the collector writes to, Dir where it lives.
func (c *Collector) DB() *tsdb.DB { return c.db }
func (c *Collector) Dir() string  { return c.dir }

func (c *Collector) interval() time.Duration {
	return time.Duration(c.keeper.Get().Collect.EffectiveInterval()) * time.Second
}

func (c *Collector) kick(soon bool) {
	select {
	case c.wake <- soon:
	default:
		if soon {
			// One wake is waiting; make sure it asks for a round.
			select {
			case <-c.wake:
			default:
			}
			select {
			case c.wake <- true:
			default:
			}
		}
	}
}

// Start reads the targets every interval until ctx ends, the first time
// shortly after the agents had a chance to report.
func (c *Collector) Start(ctx context.Context) {
	go func() {
		var last time.Time
		next := time.Now().Add(min(10*time.Second, c.interval()))
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Until(next)):
			case soon := <-c.wake:
				if !last.IsZero() {
					next = last.Add(c.interval())
				}
				if soon {
					if soonest := time.Now().Add(2 * time.Second); soonest.Before(next) {
						next = soonest
					}
				}
				continue
			}
			last = time.Now()
			c.Round(ctx)
			next = last.Add(c.interval())
		}
	}()
}

// Round reads every target once, the clusters side by side, and removes
// what is past the retention.
func (c *Collector) Round(ctx context.Context) {
	c.round.Lock()
	defer c.round.Unlock()
	c.mu.Lock()
	attached := c.pods != nil && c.ask != nil
	c.mu.Unlock()
	if !attached {
		return
	}
	cfg := c.keeper.Get().Collect
	c.forget(cfg.Targets)
	byCluster := map[string][]settings.CollectTarget{}
	for _, t := range cfg.Targets {
		byCluster[t.Cluster] = append(byCluster[t.Cluster], t)
	}
	var wg sync.WaitGroup
	for cluster, list := range byCluster {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.readCluster(ctx, cluster, list)
		}()
	}
	wg.Wait()
	if ctx.Err() == nil {
		c.prune(cfg.RetentionDays)
	}
}

// forget drops the status of targets that are gone.
func (c *Collector) forget(targets []settings.CollectTarget) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.status {
		if !slices.ContainsFunc(targets, func(t settings.CollectTarget) bool { return t.ID == id }) {
			delete(c.status, id)
		}
	}
}

func (c *Collector) set(t settings.CollectTarget, st Status) {
	st.CollectTarget = t
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status[t.ID] = st
}

func (c *Collector) readCluster(ctx context.Context, cluster string, list []settings.CollectTarget) {
	pods, ok := c.pods(cluster)
	if !ok {
		for _, t := range list {
			c.set(t, Status{Last: c.Now().UnixMilli(), Error: "the agent of this cluster is not connected"})
		}
		return
	}
	sem := make(chan struct{}, perCluster)
	var wg sync.WaitGroup
	for _, t := range list {
		ps := podsOf(t, pods)
		if len(ps) == 0 {
			c.set(t, Status{Last: c.Now().UnixMilli(), Error: "no running pod of " + t.Target})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.set(t, c.readTarget(ctx, cluster, t, ps, sem))
		}()
	}
	wg.Wait()
}

// podsOf are the running pods a target reads, by name.
func podsOf(t settings.CollectTarget, pods []protocol.Pod) []protocol.Pod {
	kind, name, _ := strings.Cut(t.Target, "/")
	var out []protocol.Pod
	for _, p := range pods {
		if p.Namespace != t.Namespace || p.Phase != "Running" {
			continue
		}
		if (kind == "Pod" && p.Name == name) || (kind != "Pod" && p.Owner == t.Target) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out[:min(len(out), maxPods)]
}

// filter keeps the metric families a target's patterns let through.
type filter struct{ include, exclude *regexp.Regexp }

func newFilter(t settings.CollectTarget) filter {
	var f filter
	if t.Include != "" {
		f.include, _ = regexp.Compile("^(?:" + t.Include + ")$")
	}
	if t.Exclude != "" {
		f.exclude, _ = regexp.Compile("^(?:" + t.Exclude + ")$")
	}
	return f
}

func (f filter) keep(name string) bool {
	return (f.include == nil || f.include.MatchString(name)) && (f.exclude == nil || !f.exclude.MatchString(name))
}

// readTarget reads a target's pods a few at a time and stores what they
// answered, each command's samples at the moment it was sent.
func (c *Collector) readTarget(ctx context.Context, cluster string, t settings.CollectTarget, pods []protocol.Pod, sem chan struct{}) Status {
	start := c.Now()
	st := Status{Last: start.UnixMilli()}
	owner := map[string]string{}
	names := make([]string, len(pods))
	for i, p := range pods {
		names[i], owner[p.Name] = p.Name, p.Owner
	}
	f := newFilter(t)
	fail := func(msg string) {
		if st.Error == "" {
			st.Error = msg
		}
	}
	var alone []string
	ask := func(batch []string) {
		sem <- struct{}{}
		defer func() { <-sem }()
		// Whole seconds: steady steps between samples take a bit each to store,
		// a millisecond's jitter a byte or more.
		at := c.Now().Truncate(time.Second)
		res, err := c.ask(ctx, cluster, protocol.Command{Type: protocol.CommandCollect, Namespace: t.Namespace,
			Port: t.Port, Path: t.Path, Pods: batch})
		if ctx.Err() != nil {
			// The server is stopping: the pods did not fail, nobody asked.
			return
		}
		var answers []protocol.PodMetrics
		if err == nil {
			err = json.Unmarshal([]byte(res.Output), &answers)
		}
		var samples []tsdb.Sample
		if err != nil {
			st.Failed += len(batch)
			fail(agentError(err))
			for _, p := range batch {
				samples = append(samples, up(cluster, t, p, owner[p], 0))
			}
		}
		for _, a := range answers {
			if a.Alone {
				alone = append(alone, a.Pod)
				continue
			}
			ok, n := false, 0
			if a.Error != "" {
				fail(a.Error)
			} else if fams, _, err := promtext.Parse(strings.NewReader(a.Text), maxSamples); err != nil {
				fail(a.Pod + ": " + err.Error())
			} else {
				ok = true
				samples, n = appendFamilies(samples, fams, f, cluster, t, a.Pod, owner[a.Pod])
			}
			if ok {
				st.Pods++
				st.Samples += n
				if a.Truncated {
					st.Truncated++
				}
				samples = append(samples, up(cluster, t, a.Pod, owner[a.Pod], 1))
			} else {
				st.Failed++
				samples = append(samples, up(cluster, t, a.Pod, owner[a.Pod], 0))
			}
		}
		if err := c.db.Append(at, samples); err != nil {
			fail("the metric store: " + err.Error())
			if c.log != nil {
				c.log.Error("collected metrics could not be stored", "cluster", cluster, "target", t.Target, "err", err)
			}
		}
	}
	for i := 0; i < len(names); i += podsPerCommand {
		ask(names[i:min(i+podsPerCommand, len(names))])
	}
	for _, p := range alone {
		ask([]string{p})
	}
	st.Took = c.Now().Sub(start).Milliseconds()
	if st.Truncated > 0 && st.Error == "" {
		st.Error = fmt.Sprintf("%d pods have more than %d samples; only the first are kept", st.Truncated, maxSamples)
	}
	return st
}

// agentError explains an agent that does not know the command.
func agentError(err error) string {
	if strings.Contains(err.Error(), "unsupported command") {
		return "the agent of this cluster is too old to collect metrics; update it"
	}
	return err.Error()
}

// targetLabels are the labels the collector puts on a pod's samples.
func targetLabels(cluster string, t settings.CollectTarget, pod, owner string) map[string]string {
	if owner == "" {
		owner = t.Target
	}
	return map[string]string{LabelCluster: cluster, LabelNamespace: t.Namespace, LabelPod: pod, LabelWorkload: owner}
}

// Samples are a pod's page as the collector stores it: the families the
// target's patterns let through, with the target's labels, and up at 1.
func Samples(fams []protocol.MetricFamily, cluster string, t settings.CollectTarget, pod, owner string) []tsdb.Sample {
	out, _ := appendFamilies(nil, fams, newFilter(t), cluster, t, pod, owner)
	return append(out, up(cluster, t, pod, owner, 1))
}

// up says whether a pod could be read, as Prometheus's own metric does.
func up(cluster string, t settings.CollectTarget, pod, owner string, v float64) tsdb.Sample {
	return tsdb.Sample{Labels: tsdb.FromMap("up", targetLabels(cluster, t, pod, owner)), Type: "gauge", Value: v}
}

// appendFamilies adds the samples of the families the filter lets
// through, with the target's labels, and says how many it added.
func appendFamilies(out []tsdb.Sample, fams []protocol.MetricFamily, f filter, cluster string, t settings.CollectTarget, pod, owner string) ([]tsdb.Sample, int) {
	ours := targetLabels(cluster, t, pod, owner)
	n := 0
	for _, fam := range fams {
		if !f.keep(fam.Name) {
			continue
		}
		for _, s := range fam.Samples {
			ls := make(map[string]string, len(s.Labels)+len(ours))
			for k, v := range s.Labels {
				if _, clash := ours[k]; clash {
					k = "exported_" + k
					// Prefixed again while the name is taken, as Prometheus does.
					for s.Labels[k] != "" {
						k = "exported_" + k
					}
				}
				ls[k] = v
			}
			for k, v := range ours {
				ls[k] = v
			}
			out = append(out, tsdb.Sample{Labels: tsdb.FromMap(s.Name, ls), Type: fam.Type, Value: float64(s.Value)})
			n++
		}
	}
	return out, n
}

// prune removes the days past the retention, at most once in a while.
func (c *Collector) prune(days int) {
	now := c.Now()
	c.mu.Lock()
	due := now.Sub(c.pruned) >= pruneEvery
	if due {
		c.pruned = now
	}
	c.mu.Unlock()
	if days <= 0 || !due {
		return
	}
	cutoff := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -days)
	stored := c.db.Days()
	if len(stored) == 0 || stored[0].Day >= cutoff.Format(time.DateOnly) {
		return
	}
	res, err := c.db.Delete(0, cutoff.UnixMilli()-1)
	if c.log != nil {
		if err != nil {
			c.log.Error("old metrics could not be removed", "before", cutoff, "err", err)
		} else {
			c.log.Info("old metrics removed", "before", cutoff, "days", res.Removed, "freed", res.Freed)
		}
	}
}

// List describes the targets that pick lets through.
func (c *Collector) List(pick func(settings.CollectTarget) bool) []Status {
	targets := c.keeper.Get().Collect.Targets
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Status{}
	for _, t := range targets {
		if !pick(t) {
			continue
		}
		st, ok := c.status[t.ID]
		if !ok || !st.Same(t) {
			st = Status{}
		}
		st.CollectTarget = t
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Cluster != b.Cluster {
			return a.Cluster < b.Cluster
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Target < b.Target
	})
	return out
}

// Stats is the store as a whole.
type Stats struct {
	Dir           string         `json:"dir"`
	Days          []tsdb.DayInfo `json:"days"`
	Bytes         int64          `json:"bytes"`
	Series        int            `json:"series"` // with samples today
	Interval      int            `json:"interval"`
	RetentionDays int            `json:"retentionDays"`
	Targets       int            `json:"targets"`
	Where         string         `json:"where"`
	LoadError     string         `json:"loadError,omitempty"`
}

func (c *Collector) Stats() Stats {
	cfg := c.keeper.Get().Collect
	st := Stats{Dir: c.dir, Days: c.db.Days(), Series: c.db.HeadSeries(), Interval: cfg.EffectiveInterval(),
		RetentionDays: cfg.RetentionDays, Targets: len(cfg.Targets), Where: c.keeper.Where(), LoadError: c.keeper.LoadError()}
	if st.Days == nil {
		st.Days = []tsdb.DayInfo{}
	}
	for _, d := range st.Days {
		st.Bytes += d.Bytes
	}
	return st
}

// Configure saves how often targets are read and how long data is kept
// (0 days: until deleted).
func (c *Collector) Configure(ctx context.Context, interval, retentionDays int) (settings.Collect, error) {
	c.edit.Lock()
	defer c.edit.Unlock()
	s, err := c.keeper.Update(ctx, func(s *settings.Settings) error {
		next := s.Collect
		next.Interval, next.RetentionDays = interval, retentionDays
		if err := next.Validate(); err != nil {
			return &settings.InvalidError{Err: err}
		}
		s.Collect = next
		return nil
	})
	if err != nil {
		return settings.Collect{}, err
	}
	c.mu.Lock()
	c.pruned = time.Time{} // a shorter retention applies at the next round
	c.mu.Unlock()
	c.kick(false)
	return s.Collect, nil
}

// Delete removes the stored samples within [from, to] (milliseconds).
func (c *Collector) Delete(from, to int64) (tsdb.DeleteResult, error) {
	return c.db.Delete(from, to)
}

func prepare(t *settings.CollectTarget, others []settings.CollectTarget) error {
	if err := t.Normalize(); err != nil {
		return &settings.InvalidError{Err: err}
	}
	for _, o := range others {
		if o.ID != t.ID && o.Same(*t) {
			return &settings.InvalidError{Err: fmt.Errorf("%s is already collected from port %s%s", t.Target, t.Port, t.Path)}
		}
	}
	return nil
}

// Add saves a new target; it is read shortly after.
func (c *Collector) Add(ctx context.Context, t settings.CollectTarget) (settings.CollectTarget, error) {
	c.edit.Lock()
	defer c.edit.Unlock()
	t.ID = settings.NewCheckID()
	_, err := c.keeper.Update(ctx, func(s *settings.Settings) error {
		if len(s.Collect.Targets) >= settings.MaxCollectTargets {
			return &settings.InvalidError{Err: fmt.Errorf("at most %d targets", settings.MaxCollectTargets)}
		}
		if err := prepare(&t, s.Collect.Targets); err != nil {
			return err
		}
		s.Collect.Targets = append(s.Collect.Targets, t)
		return nil
	})
	if err != nil {
		return settings.CollectTarget{}, err
	}
	c.kick(true)
	return t, nil
}

// Change saves a target's new settings, if mine says the target is the
// caller's to change.
func (c *Collector) Change(ctx context.Context, id string, t settings.CollectTarget, mine func(settings.CollectTarget) bool) (settings.CollectTarget, error) {
	c.edit.Lock()
	defer c.edit.Unlock()
	t.ID = id
	_, err := c.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Collect.Targets, func(x settings.CollectTarget) bool { return x.ID == id })
		if i < 0 || !mine(s.Collect.Targets[i]) {
			return ErrNotFound
		}
		if err := prepare(&t, s.Collect.Targets); err != nil {
			return err
		}
		s.Collect.Targets[i] = t
		return nil
	})
	if err != nil {
		return settings.CollectTarget{}, err
	}
	c.kick(true)
	return t, nil
}

// Remove stops collecting a target; what it stored stays.
func (c *Collector) Remove(ctx context.Context, id string, mine func(settings.CollectTarget) bool) (settings.CollectTarget, error) {
	c.edit.Lock()
	defer c.edit.Unlock()
	var gone settings.CollectTarget
	s, err := c.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Collect.Targets, func(x settings.CollectTarget) bool { return x.ID == id })
		if i < 0 || !mine(s.Collect.Targets[i]) {
			return ErrNotFound
		}
		gone = s.Collect.Targets[i]
		s.Collect.Targets = slices.Delete(s.Collect.Targets, i, i+1)
		return nil
	})
	if err != nil {
		return settings.CollectTarget{}, err
	}
	c.forget(s.Collect.Targets)
	return gone, nil
}
