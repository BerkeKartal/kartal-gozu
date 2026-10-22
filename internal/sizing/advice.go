package sizing

import (
	"sort"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Stat summarizes one resource's usage per pod.
type Stat struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	Max int64 `json:"max"`
}

func statOf(h Hist) Stat { return Stat{P50: h.Quantile(.5), P95: h.Quantile(.95), Max: h.Max} }

// Advice is what is suggested for one workload, per pod.
type Advice struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Pods      int    `json:"pods"`
	// Requests and Limits are what its pods have now.
	Requests *protocol.Resources `json:"requests,omitempty"`
	Limits   *protocol.Resources `json:"limits,omitempty"`
	CPU      Stat                `json:"cpu"`
	Memory   Stat                `json:"memory"`
	// Minutes is how much usage the advice is made from, in pod-minutes.
	Minutes uint32    `json:"minutes"`
	Since   time.Time `json:"since,omitempty"`
	// Suggested requests and limits; nil until enough usage is known. A
	// CPU limit is suggested only to a workload that has one.
	Suggested *Suggestion `json:"suggested,omitempty"`
	// Issues are codes: oom, no-requests, memory-near-limit,
	// cpu-near-limit, cpu-under, memory-under, cpu-over, memory-over,
	// little-data.
	Issues  []string   `json:"issues"`
	LastOOM *time.Time `json:"lastOOM,omitempty"`
	// FreeCPU and FreeMemory are what the workload's requests would give
	// back, over all its pods, if it asked for what is suggested.
	FreeCPU    int64 `json:"freeCPU,omitempty"`
	FreeMemory int64 `json:"freeMemory,omitempty"`
}

type Suggestion struct {
	CPURequest    int64 `json:"cpuRequest"`
	CPULimit      int64 `json:"cpuLimit,omitempty"`
	MemoryRequest int64 `json:"memoryRequest"`
	MemoryLimit   int64 `json:"memoryLimit"`
}

const mib = 1 << 20

// roundUp rounds v up to a step that grows with it, so suggestions read
// like what people write: 35m, 120m, 1.25 cores, 96Mi, 1.5Gi.
func roundUp(v int64, steps [][2]int64) int64 {
	for _, s := range steps {
		if v <= s[0] {
			return (v + s[1] - 1) / s[1] * s[1]
		}
	}
	last := steps[len(steps)-1][1]
	return (v + last - 1) / last * last
}

var (
	cpuSteps = [][2]int64{{100, 5}, {1000, 10}, {4000, 50}, {1 << 40, 250}}
	memSteps = [][2]int64{{256 * mib, 16 * mib}, {1024 * mib, 32 * mib}, {4096 * mib, 128 * mib}, {1 << 50, 512 * mib}}
)

// Advise suggests requests and limits for the workloads of a snapshot that
// keep pods running (Deployments, StatefulSets, DaemonSets), from the usage
// the store holds, keeping those keep accepts.
func (s *Store) Advise(cluster string, snap *protocol.Snapshot, keep func(namespace string) bool, now time.Time) []Advice {
	type podInfo struct {
		pods     int
		req, lim *protocol.Resources
		lastOOM  *time.Time
	}
	info := map[string]*podInfo{}
	for _, p := range snap.Pods {
		if p.Owner == "" || p.Phase == "Succeeded" || p.Phase == "Failed" {
			continue
		}
		key := Key(p.Namespace, p.Owner)
		pi := info[key]
		if pi == nil {
			pi = &podInfo{}
			info[key] = pi
		}
		pi.pods++
		// The pods of a rollout differ for a while: the latest pod's values
		// are the template's, near enough. A limit that only some containers
		// have is no limit of the pod.
		if pi.req == nil {
			pi.req, pi.lim = p.Requests, p.Limits
			if p.Limits != nil && len(p.Unlimited) > 0 {
				lim := *p.Limits
				for _, res := range p.Unlimited {
					switch res {
					case "cpu":
						lim.CPUMilli = 0
					case "memory":
						lim.MemoryBytes = 0
					}
				}
				pi.lim = &lim
			}
		}
		if p.LastTermination == "OOMKilled" && p.LastTerminatedAt != nil && now.Sub(*p.LastTerminatedAt) < Days*24*time.Hour &&
			(pi.lastOOM == nil || p.LastTerminatedAt.After(*pi.lastOOM)) {
			pi.lastOOM = p.LastTerminatedAt
		}
	}
	var out []Advice
	for _, w := range snap.Workloads {
		if !sized[w.Kind] || (keep != nil && !keep(w.Namespace)) {
			continue
		}
		key := Key(w.Namespace, w.Kind+"/"+w.Name)
		a := Advice{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Issues: []string{}}
		if pi := info[key]; pi != nil {
			a.Pods, a.Requests, a.Limits, a.LastOOM = pi.pods, pi.req, pi.lim, pi.lastOOM
		}
		if u, ok := s.Usage(cluster, key); ok {
			a.CPU, a.Memory, a.Minutes, a.Since = statOf(u.CPU), statOf(u.Memory), u.Minutes, u.Since
		}
		advise(&a)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Kind+"/"+out[i].Name < out[j].Kind+"/"+out[j].Name
	})
	return out
}

func advise(a *Advice) {
	var req, lim protocol.Resources
	if a.Requests != nil {
		req = *a.Requests
	}
	if a.Limits != nil {
		lim = *a.Limits
	}
	if a.LastOOM != nil {
		a.Issues = append(a.Issues, "oom")
	}
	if a.Pods > 0 && req.CPUMilli == 0 && req.MemoryBytes == 0 {
		a.Issues = append(a.Issues, "no-requests")
	}
	if a.Minutes < MinMinutes {
		a.Issues = append(a.Issues, "little-data")
		return
	}
	sug := &Suggestion{
		CPURequest:    roundUp(max(a.CPU.P95*11/10, 10), cpuSteps),
		MemoryRequest: roundUp(max(a.Memory.P95*115/100, 32*mib), memSteps),
	}
	sug.MemoryLimit = roundUp(max(a.Memory.Max*13/10, sug.MemoryRequest), memSteps)
	// Usage read once a minute misses the short peaks that kill pods: a
	// memory limit is not lowered unless it is far above any use, and one
	// that killed a pod is raised.
	if lim.MemoryBytes > 0 && lim.MemoryBytes <= 2*sug.MemoryLimit {
		sug.MemoryLimit = max(sug.MemoryLimit, lim.MemoryBytes)
	}
	if a.LastOOM != nil && lim.MemoryBytes > 0 {
		sug.MemoryLimit = max(sug.MemoryLimit, roundUp(lim.MemoryBytes*5/4, memSteps))
	}
	sug.MemoryRequest = min(sug.MemoryRequest, sug.MemoryLimit)
	if lim.CPUMilli > 0 {
		sug.CPULimit = roundUp(max(a.CPU.Max*3/2, sug.CPURequest*2), cpuSteps)
	}
	a.Suggested = sug
	if lim.MemoryBytes > 0 && a.Memory.Max*10 >= lim.MemoryBytes*9 {
		a.Issues = append(a.Issues, "memory-near-limit")
	}
	if lim.CPUMilli > 0 && a.CPU.P95*10 >= lim.CPUMilli*8 {
		a.Issues = append(a.Issues, "cpu-near-limit")
	}
	if req.CPUMilli > 0 && a.CPU.P95*10 > req.CPUMilli*12 {
		a.Issues = append(a.Issues, "cpu-under")
	}
	if req.MemoryBytes > 0 && a.Memory.P95*10 > req.MemoryBytes*12 {
		a.Issues = append(a.Issues, "memory-under")
	}
	pods := int64(max(a.Pods, 1))
	if req.CPUMilli >= 2*sug.CPURequest && req.CPUMilli-sug.CPURequest >= 100 {
		a.Issues = append(a.Issues, "cpu-over")
		a.FreeCPU = (req.CPUMilli - sug.CPURequest) * pods
	}
	if req.MemoryBytes >= 2*sug.MemoryRequest && req.MemoryBytes-sug.MemoryRequest >= 128*mib {
		a.Issues = append(a.Issues, "memory-over")
		a.FreeMemory = (req.MemoryBytes - sug.MemoryRequest) * pods
	}
}

// Risky reports whether an issue puts the workload's pods at risk, rather
// than wasting room.
func Risky(issue string) bool {
	return issue == "oom" || issue == "no-requests" || strings.HasSuffix(issue, "-near-limit") || strings.HasSuffix(issue, "-under")
}
