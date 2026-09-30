// Package history keeps the last few hours of CPU and memory usage of every
// cluster, node and pod in memory, one point per minute. Nothing is written
// to disk: a restarted server starts over, and the agents' next reports
// fill it again.
package history

import (
	"sort"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Points is how many minutes are kept: six hours.
const Points = 360

// A sample takes 12 bytes: CPU in millicores, memory in KiB (up to 4 TiB),
// and the minute it belongs to.
type sample struct {
	minute uint32
	cpu    uint32
	memKiB uint32
}

type series struct {
	ring [Points]sample
	last uint32
}

func (s *series) put(minute uint32, cpu, mem int64) {
	s.ring[minute%Points] = sample{minute: minute, cpu: clamp(cpu), memKiB: clamp(mem >> 10)}
	s.last = max(s.last, minute)
}

func clamp(v int64) uint32 {
	switch {
	case v < 0:
		return 0
	case v > 1<<32-1:
		return 1<<32 - 1
	}
	return uint32(v)
}

// Point is one minute of usage.
type Point struct {
	Time        int64 `json:"t"` // Unix milliseconds
	CPUMilli    int64 `json:"cpu"`
	MemoryBytes int64 `json:"memory"`
}

type Store struct {
	mu       sync.Mutex
	clusters map[string]map[string]*series
}

func New() *Store { return &Store{clusters: map[string]map[string]*series{}} }

// epoch keeps minute numbers small enough for uint32 for thousands of years.
var epoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

func minuteOf(t time.Time) uint32 { return uint32(t.Sub(epoch) / time.Minute) }

// Key names a series: "cluster", "node/NAME" or "pod/NAMESPACE/NAME".
func Key(kind, namespace, name string) string {
	switch kind {
	case "node":
		return "node/" + name
	case "pod":
		return "pod/" + namespace + "/" + name
	}
	return "cluster"
}

// Record stores the usage in a snapshot; within a minute the latest wins.
func (s *Store) Record(cluster string, snap *protocol.Snapshot, at time.Time) {
	if !snap.MetricsAvailable {
		return
	}
	minute := minuteOf(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.clusters[cluster]
	if all == nil {
		all = map[string]*series{}
		s.clusters[cluster] = all
	}
	put := func(key string, u *protocol.Resources) {
		if u == nil {
			return
		}
		sr := all[key]
		if sr == nil {
			sr = &series{}
			all[key] = sr
		}
		sr.put(minute, u.CPUMilli, u.MemoryBytes)
	}
	var total protocol.Resources
	for _, n := range snap.Nodes {
		put(Key("node", "", n.Name), n.Usage)
		if n.Usage != nil {
			total.CPUMilli += n.Usage.CPUMilli
			total.MemoryBytes += n.Usage.MemoryBytes
		}
	}
	put(Key("cluster", "", ""), &total)
	for _, p := range snap.Pods {
		put(Key("pod", p.Namespace, p.Name), p.Usage)
	}
	// Forget series nothing has been reported for during the whole window,
	// such as pods replaced by a rollout. A sample older than a series' last
	// one (a clock stepping back) says nothing about that.
	for key, sr := range all {
		if minute > sr.last && minute-sr.last >= Points {
			delete(all, key)
		}
	}
}

// Query returns the points of the last window, oldest first.
func (s *Store) Query(cluster, key string, window time.Duration, now time.Time) []Point {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.clusters[cluster][key]
	if sr == nil {
		return []Point{}
	}
	end := minuteOf(now)
	span := uint32(min(window/time.Minute, Points))
	out := make([]Point, 0, span)
	for m := end - span + 1; m <= end; m++ {
		p := sr.ring[m%Points]
		if p.minute != m {
			continue
		}
		out = append(out, Point{
			Time:        epoch.Add(time.Duration(m) * time.Minute).UnixMilli(),
			CPUMilli:    int64(p.cpu),
			MemoryBytes: int64(p.memKiB) << 10,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time < out[j].Time })
	return out
}
