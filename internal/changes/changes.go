// Package changes notices what changed in each cluster between one snapshot
// and the next: a new image rolled out, replicas scaled, a workload created
// or deleted, a node cordoned or gone not ready. Put next to Kartal Gözü's
// own audit log, it answers "what changed?" when something breaks.
package changes

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Change is one thing that changed.
type Change struct {
	Time      time.Time `json:"time"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace,omitempty"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	// What is created, deleted, image, replicas, template, schedule,
	// cordoned, uncordoned, ready, not-ready, suspended, resumed, or, for
	// changes made through Kartal Gözü, the action.
	What string `json:"what"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// By names who made the change through Kartal Gözü.
	By string `json:"by,omitempty"`
}

// keep is how many changes are remembered.
const keep = 5000

// Log remembers the latest changes of every cluster, in memory.
type Log struct {
	mu    sync.Mutex
	last  map[string]*baseline
	items []Change // oldest first
}

// baseline is what the next snapshot is compared with, by part.
type baseline struct {
	workloads map[string][]protocol.Workload // by kind
	nodes     []protocol.Node
	cronJobs  []protocol.CronJob
}

func New() *Log { return &Log{last: map[string]*baseline{}} }

var workloadKinds = map[string]string{"Deployment": "deployments", "StatefulSet": "statefulsets", "DaemonSet": "daemonsets"}

// Observe compares a cluster's snapshot with what it had before. The first
// snapshot after a start only sets the baseline. A part the agent could not
// collect this time (its list failed) is not compared: its objects did not
// all disappear, and the part keeps its earlier baseline.
func (l *Log) Observe(cluster string, snap *protocol.Snapshot, now time.Time) {
	failed := map[string]bool{}
	for _, e := range snap.Errors {
		what, _, _ := strings.Cut(e, ":")
		failed[what] = true
	}
	next := &baseline{workloads: map[string][]protocol.Workload{}}
	for _, w := range snap.Workloads {
		next.workloads[w.Kind] = append(next.workloads[w.Kind], w)
	}
	next.nodes, next.cronJobs = snap.Nodes, snap.CronJobs

	l.mu.Lock()
	defer l.mu.Unlock()
	prev := l.last[cluster]
	if prev != nil {
		for kind, resource := range workloadKinds {
			if failed[resource] {
				next.workloads[kind] = prev.workloads[kind]
			}
		}
		if failed["nodes"] {
			next.nodes = prev.nodes
		}
		if failed["cronjobs"] {
			next.cronJobs = prev.cronJobs
		}
	}
	l.last[cluster] = next
	if prev == nil {
		return
	}
	add := func(c Change) {
		c.Time, c.Cluster = now.UTC(), cluster
		l.items = append(l.items, c)
	}
	for kind := range workloadKinds {
		diffWorkloads(prev.workloads[kind], next.workloads[kind], add)
	}
	diffNodes(prev.nodes, next.nodes, add)
	diffCronJobs(prev.cronJobs, next.cronJobs, add)
	if len(l.items) > keep {
		l.items = append([]Change(nil), l.items[len(l.items)-keep:]...)
	}
}

// Recent returns the changes accept takes (nil: all), newest first, at most
// limit of them.
func (l *Log) Recent(accept func(Change) bool, limit int) []Change {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []Change{}
	for i := len(l.items) - 1; i >= 0 && len(out) < limit; i-- {
		if accept == nil || accept(l.items[i]) {
			out = append(out, l.items[i])
		}
	}
	return out
}

func images(w protocol.Workload) string {
	s := append([]string(nil), w.Images...)
	sort.Strings(s)
	return strings.Join(s, ", ")
}

func diffWorkloads(before, after []protocol.Workload, add func(Change)) {
	key := func(w protocol.Workload) string { return w.Namespace + "/" + w.Name }
	old := map[string]protocol.Workload{}
	for _, w := range before {
		old[key(w)] = w
	}
	for _, w := range after {
		c := Change{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name}
		p, ok := old[key(w)]
		delete(old, key(w))
		switch {
		case !ok:
			c.What, c.To = "created", images(w)
		case images(p) != images(w):
			c.What, c.From, c.To = "image", images(p), images(w)
		case p.Desired != w.Desired && w.Kind != "DaemonSet":
			c.What, c.From, c.To = "replicas", strconv.Itoa(int(p.Desired)), strconv.Itoa(int(w.Desired))
		case p.Generation != 0 && w.Generation > p.Generation:
			// The spec changed and neither images nor replicas did: the pod
			// template, such as a restart or a new setting.
			c.What = "template"
		default:
			continue
		}
		add(c)
	}
	for _, w := range old {
		add(Change{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, What: "deleted", From: images(w)})
	}
}

func diffNodes(before, after []protocol.Node, add func(Change)) {
	old := map[string]protocol.Node{}
	for _, n := range before {
		old[n.Name] = n
	}
	for _, n := range after {
		p, ok := old[n.Name]
		delete(old, n.Name)
		c := Change{Kind: "Node", Name: n.Name}
		switch {
		case !ok:
			c.What = "created"
		case p.Unschedulable != n.Unschedulable && n.Unschedulable:
			c.What = "cordoned"
		case p.Unschedulable != n.Unschedulable:
			c.What = "uncordoned"
		case p.Ready != n.Ready && n.Ready:
			c.What = "ready"
		case p.Ready != n.Ready:
			c.What, c.To = "not-ready", strings.Join(n.Pressure, ", ")
		default:
			continue
		}
		add(c)
	}
	for _, n := range old {
		add(Change{Kind: "Node", Name: n.Name, What: "deleted"})
	}
}

func diffCronJobs(before, after []protocol.CronJob, add func(Change)) {
	key := func(c protocol.CronJob) string { return c.Namespace + "/" + c.Name }
	old := map[string]protocol.CronJob{}
	for _, c := range before {
		old[key(c)] = c
	}
	for _, cj := range after {
		p, ok := old[key(cj)]
		delete(old, key(cj))
		c := Change{Namespace: cj.Namespace, Kind: "CronJob", Name: cj.Name}
		switch {
		case !ok:
			c.What, c.To = "created", cj.Schedule
		case p.Schedule != cj.Schedule:
			c.What, c.From, c.To = "schedule", p.Schedule, cj.Schedule
		case p.Suspended != cj.Suspended && cj.Suspended:
			c.What = "suspended"
		case p.Suspended != cj.Suspended:
			c.What = "resumed"
		default:
			continue
		}
		add(c)
	}
	for _, cj := range old {
		add(Change{Namespace: cj.Namespace, Kind: "CronJob", Name: cj.Name, What: "deleted"})
	}
}
