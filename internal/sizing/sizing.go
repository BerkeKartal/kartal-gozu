// Package sizing learns how much CPU and memory each workload's pods use,
// day by day, and suggests requests and limits from it: enough for most of
// the time, with room for the peaks, and no more. It also points out the
// workloads at risk: killed for memory, near their limits, or asking for
// far more than they use.
//
// Every minute, each running pod's usage goes into its workload's
// histogram of the day: buckets 5% apart, so a percentile is known to
// within 5%, in a few hundred bytes a day. A week of days is kept.
package sizing

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Days is how many days of usage a workload's suggestion is made from.
const Days = 7

// MinMinutes is how much usage a suggestion needs, in pod-minutes.
const MinMinutes = 60

// ratio is how far apart the buckets are.
const ratio = 1.05

var logRatio = math.Log(ratio)

// bucket is where a value falls; values below 1 share bucket 0.
func bucket(v int64) uint16 {
	if v <= 1 {
		return 0
	}
	return uint16(min(math.Log(float64(v))/logRatio, math.MaxUint16))
}

// upper is the largest value of a bucket.
func upper(b uint16) int64 { return int64(math.Ceil(math.Pow(ratio, float64(b)+1))) }

// Hist counts values by bucket, and keeps the largest exactly.
type Hist struct {
	Counts map[uint16]uint32 `json:"c"`
	Max    int64             `json:"m"`
	N      uint32            `json:"n"`
}

func (h *Hist) add(v int64) {
	if h.Counts == nil {
		h.Counts = map[uint16]uint32{}
	}
	h.Counts[bucket(v)]++
	h.N++
	h.Max = max(h.Max, v)
}

func (h *Hist) merge(o Hist) {
	for b, n := range o.Counts {
		if h.Counts == nil {
			h.Counts = map[uint16]uint32{}
		}
		h.Counts[b] += n
	}
	h.N += o.N
	h.Max = max(h.Max, o.Max)
}

// Quantile is the value q (0 to 1) of the counts are at or below, rounded
// up to its bucket's top, and never above the largest seen.
func (h Hist) Quantile(q float64) int64 {
	if h.N == 0 {
		return 0
	}
	keys := make([]int, 0, len(h.Counts))
	for b := range h.Counts {
		keys = append(keys, int(b))
	}
	sort.Ints(keys)
	need := uint32(math.Ceil(q * float64(h.N)))
	var seen uint32
	for _, b := range keys {
		seen += h.Counts[uint16(b)]
		if seen >= need {
			return min(upper(uint16(b)), h.Max)
		}
	}
	return h.Max
}

// Day is one day of a workload's usage, per pod and minute.
type Day struct {
	Day    string `json:"d"` // 2006-01-02, UTC
	CPU    Hist   `json:"cpu"`
	Memory Hist   `json:"mem"`
}

type workload struct {
	Days       []Day `json:"days"` // oldest first, at most Days
	LastMinute int64 `json:"last"`
	First      int64 `json:"first"` // Unix seconds of the first sample
}

// Store holds the usage of every workload of every cluster.
type Store struct {
	mu   sync.Mutex
	data map[string]map[string]*workload // cluster → namespace/Kind/name
	path string
}

// New returns an empty store, kept in memory only.
func New() *Store { return &Store{data: map[string]map[string]*workload{}} }

// Open returns a store kept in the file at path, with what it already holds;
// Save writes it back. A missing file is an empty store. A file that cannot
// be read gives an empty store too, which the next Save writes over, and
// the error.
func Open(path string) (*Store, error) {
	s := New()
	s.path = path
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var data map[string]map[string]*workload
	if err := json.Unmarshal(b, &data); err != nil {
		return s, err
	}
	if data != nil {
		s.data = data
	}
	return s, nil
}

// Path is the file the store is kept in; empty when in memory only.
func (s *Store) Path() string { return s.path }

// Save writes the store to its file, whole or not at all.
func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	b, err := json.Marshal(s.data)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(s.path))
}

// Key names a workload: namespace/Kind/name.
func Key(namespace, owner string) string { return namespace + "/" + owner }

// sized are the controllers whose pods are sized together.
var sized = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true}

// Record adds the usage of a snapshot's running pods, once a minute for
// each workload.
func (s *Store) Record(cluster string, snap *protocol.Snapshot, now time.Time) {
	if !snap.MetricsAvailable {
		return
	}
	minute := now.Unix() / 60
	day := now.UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.data[cluster]
	if all == nil {
		all = map[string]*workload{}
		s.data[cluster] = all
	}
	seen := map[string]bool{}
	for _, p := range snap.Pods {
		kind, _, _ := strings.Cut(p.Owner, "/")
		if p.Usage == nil || p.Phase != "Running" || !sized[kind] {
			continue
		}
		key := Key(p.Namespace, p.Owner)
		w := all[key]
		if w == nil {
			w = &workload{First: now.Unix()}
			all[key] = w
		}
		// Within a minute, only the first snapshot counts: every pod once.
		if w.LastMinute == minute && !seen[key] {
			continue
		}
		seen[key] = true
		w.LastMinute = minute
		if n := len(w.Days); n == 0 || w.Days[n-1].Day != day {
			w.Days = append(w.Days, Day{Day: day})
			if len(w.Days) > Days {
				w.Days = w.Days[len(w.Days)-Days:]
			}
		}
		d := &w.Days[len(w.Days)-1]
		d.CPU.add(p.Usage.CPUMilli)
		d.Memory.add(p.Usage.MemoryBytes)
	}
	// Forget workloads nothing was heard of for a week: deleted ones.
	for key, w := range all {
		if minute-w.LastMinute > Days*24*60 {
			delete(all, key)
		}
	}
}

// Usage is what a workload's pods used over the days kept.
type Usage struct {
	CPU, Memory Hist
	Minutes     uint32 // pod-minutes measured
	Since       time.Time
}

// Usage returns a workload's usage, and whether anything is known of it.
func (s *Store) Usage(cluster, key string) (Usage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.data[cluster][key]
	if w == nil {
		return Usage{}, false
	}
	u := Usage{Since: time.Unix(w.First, 0).UTC()}
	for _, d := range w.Days {
		u.CPU.merge(d.CPU)
		u.Memory.merge(d.Memory)
	}
	u.Minutes = u.CPU.N
	return u, true
}
