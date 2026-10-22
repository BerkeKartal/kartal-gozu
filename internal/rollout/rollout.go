// Package rollout follows each new version of a workload from the snapshot
// that first shows it until all its pods run it and are ready: how long
// that took, or that it got stuck, and on what (an image that does not
// pull, pods that crash). Kept in memory, like the changes.
package rollout

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// StuckAfter is how long a rollout may take before it counts as stuck.
const StuckAfter = 10 * time.Minute

// keep is how many rollouts are remembered, of all clusters.
const keep = 2000

// Rollout is one new version of a workload making its way out.
type Rollout struct {
	ID        int64     `json:"id"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Started   time.Time `json:"started"`
	// Cause is "image" (new images) or "template" (another change of the
	// pod template, such as a restart or a new setting).
	Cause string `json:"cause"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	// State is "progressing", "done", "stuck" (progressing for longer than
	// StuckAfter), "replaced" (another version came before it was done) or
	// "deleted".
	State    string     `json:"state"`
	Finished *time.Time `json:"finished,omitempty"`
	// Ready and Desired are the workload's replicas the last time it was
	// seen; Manual says its pods are replaced only as someone deletes them.
	Ready   int32 `json:"ready"`
	Desired int32 `json:"desired"`
	Manual  bool  `json:"manual,omitempty"`
	// Problems are what its troubled pods say, such as ImagePullBackOff.
	Problems []string `json:"problems,omitempty"`
	// WasStuck says it was stuck before it finished.
	WasStuck bool `json:"wasStuck,omitempty"`
}

// Done reports whether nothing more will happen to the rollout.
func (r Rollout) Done() bool {
	return r.State == "done" || r.State == "replaced" || r.State == "deleted"
}

type seen struct {
	images     string
	generation int64
	desired    int32
	active     *Rollout
}

// Tracker follows the rollouts of every cluster.
type Tracker struct {
	mu    sync.Mutex
	last  map[string]map[string]*seen // cluster → Kind/namespace/name
	items []*Rollout                  // oldest first
	next  int64
}

func New() *Tracker { return &Tracker{last: map[string]map[string]*seen{}} }

func images(w protocol.Workload) string {
	s := append([]string(nil), w.Images...)
	sort.Strings(s)
	return strings.Join(s, ", ")
}

// Observe takes a cluster's snapshot: new versions start rollouts, and the
// rollouts under way move on. The first snapshot of a cluster is only the
// baseline. Workloads whose list failed this time are left as they were.
func (t *Tracker) Observe(cluster string, snap *protocol.Snapshot, now time.Time) {
	failed := map[string]bool{}
	for _, e := range snap.Errors {
		what, _, _ := strings.Cut(e, ":")
		failed[what] = true
	}
	listed := map[string]bool{
		"Deployment": !failed["deployments"], "StatefulSet": !failed["statefulsets"], "DaemonSet": !failed["daemonsets"],
	}
	problems := map[string][]string{}
	for _, p := range snap.Pods {
		if p.Owner != "" && p.Troubled() && p.Reason != "" {
			key := p.Namespace + "/" + p.Owner
			if r := strings.TrimPrefix(p.Reason, "Init:"); !contains(problems[key], r) {
				problems[key] = append(problems[key], r)
			}
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	prev, first := t.last[cluster], t.last[cluster] == nil
	if first {
		prev = map[string]*seen{}
	}
	next := map[string]*seen{}
	for _, w := range snap.Workloads {
		key := w.Kind + "/" + w.Namespace + "/" + w.Name
		cur := &seen{images: images(w), generation: w.Generation, desired: w.Desired}
		p := prev[key]
		if p != nil {
			cur.active = p.active
		}
		next[key] = cur
		if first {
			continue
		}
		cause := ""
		switch {
		case p == nil:
			// A new workload rolls out its first version.
			cause = "image"
		case p.images != cur.images:
			cause = "image"
		case p.generation != 0 && cur.generation > p.generation && p.desired == w.Desired && !w.RolledOut():
			// The spec changed without new images or replicas: a restart or
			// a setting, which new pods roll out.
			cause = "template"
		}
		if cause != "" {
			if a := cur.active; a != nil && !a.Done() {
				a.State, a.Finished = "replaced", &now
			}
			r := &Rollout{Cluster: cluster, Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Started: now.UTC(),
				Cause: cause, To: cur.images, State: "progressing"}
			if p != nil {
				r.From = p.images
			}
			t.next++
			r.ID = t.next
			t.items = append(t.items, r)
			cur.active = r
		}
		if a := cur.active; a != nil && !a.Done() {
			a.Ready, a.Desired, a.Manual = w.Ready, w.Desired, w.ManualRollout
			a.Problems = problems[w.Namespace+"/"+w.Kind+"/"+w.Name]
			switch {
			case w.RolledOut():
				done := now.UTC()
				a.State, a.Finished = "done", &done
			case now.Sub(a.Started) >= StuckAfter && !w.ManualRollout:
				// One whose pods wait to be deleted by hand is not stuck.
				a.State, a.WasStuck = "stuck", true
			}
		}
	}
	for key, p := range prev {
		if _, ok := next[key]; ok {
			continue
		}
		kind, _, _ := strings.Cut(key, "/")
		if !listed[kind] {
			next[key] = p
			continue
		}
		if a := p.active; a != nil && !a.Done() {
			done := now.UTC()
			a.State, a.Finished = "deleted", &done
		}
	}
	t.last[cluster] = next
	if len(t.items) > keep {
		t.items = append([]*Rollout(nil), t.items[len(t.items)-keep:]...)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Recent returns the rollouts accept takes (nil: all), newest first, at most
// limit of them.
func (t *Tracker) Recent(accept func(Rollout) bool, limit int) []Rollout {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []Rollout{}
	for i := len(t.items) - 1; i >= 0 && len(out) < limit; i-- {
		r := *t.items[i]
		if accept == nil || accept(r) {
			out = append(out, r)
		}
	}
	return out
}

// Stuck returns a cluster's rollouts that are stuck now, as alert details:
// by workload, what is wrong.
func (t *Tracker) Stuck(cluster string, now time.Time) map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]string{}
	for _, r := range t.items {
		if r.Cluster != cluster || r.State != "stuck" {
			continue
		}
		detail := fmt.Sprintf("%d of %d ready after %s", r.Ready, r.Desired, now.Sub(r.Started).Round(time.Minute))
		if len(r.Problems) > 0 {
			detail += ": " + strings.Join(r.Problems, ", ")
		}
		out[r.Namespace+"\x00"+r.Kind+"/"+r.Name] = detail
	}
	return out
}
