package sizing

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestQuantile(t *testing.T) {
	var h Hist
	for v := int64(1); v <= 1000; v++ {
		h.add(v)
	}
	for _, c := range []struct {
		q    float64
		want int64
	}{{.5, 500}, {.95, 950}, {1, 1000}} {
		got := h.Quantile(c.q)
		// Within a bucket: 5% above at most, never below.
		if got < c.want || float64(got) > float64(c.want)*1.06 {
			t.Errorf("q%.2f = %d, want about %d", c.q, got, c.want)
		}
	}
	if h.Max != 1000 || h.N != 1000 {
		t.Errorf("max %d n %d", h.Max, h.N)
	}
	if (Hist{}).Quantile(.9) != 0 {
		t.Error("an empty histogram has no quantile")
	}
	// A large memory value stays within its bucket too.
	var m Hist
	m.add(3 << 30)
	if got := m.Quantile(.5); got != 3<<30 {
		t.Errorf("one value is its own quantile: %d", got)
	}
	if b := bucket(math.MaxInt64); b == 0 {
		t.Error("huge values must not wrap")
	}
}

func snapAt(pods ...protocol.Pod) *protocol.Snapshot {
	return &protocol.Snapshot{MetricsAvailable: true, Pods: pods,
		Workloads: []protocol.Workload{{Kind: "Deployment", Namespace: "shop", Name: "web", Desired: 2}}}
}

func pod(name string, cpu, mem int64) protocol.Pod {
	return protocol.Pod{Namespace: "shop", Name: name, Phase: "Running", Owner: "Deployment/web",
		Usage:    &protocol.Resources{CPUMilli: cpu, MemoryBytes: mem},
		Requests: &protocol.Resources{CPUMilli: 1000, MemoryBytes: 1 << 30},
		Limits:   &protocol.Resources{CPUMilli: 2000, MemoryBytes: 600 * mib}}
}

func TestRecordOncePerMinute(t *testing.T) {
	s := New()
	at := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ { // four snapshots within a minute
		s.Record("prod", snapAt(pod("web-1", 100, 200*mib), pod("web-2", 120, 220*mib),
			protocol.Pod{Namespace: "shop", Name: "job-1", Phase: "Running", Owner: "Job/x", Usage: &protocol.Resources{CPUMilli: 5}},
			protocol.Pod{Namespace: "shop", Name: "web-3", Phase: "Pending", Owner: "Deployment/web", Usage: &protocol.Resources{CPUMilli: 5}}),
			at.Add(time.Duration(i)*10*time.Second))
	}
	u, ok := s.Usage("prod", Key("shop", "Deployment/web"))
	if !ok || u.Minutes != 2 || u.CPU.Max != 120 {
		t.Fatalf("usage: %+v %v", u, ok)
	}
	if _, ok := s.Usage("prod", Key("shop", "Job/x")); ok {
		t.Error("Jobs are not sized")
	}
	s.Record("prod", &protocol.Snapshot{Pods: []protocol.Pod{pod("web-1", 900, 0)}}, at.Add(time.Minute))
	if u, _ := s.Usage("prod", Key("shop", "Deployment/web")); u.Minutes != 2 {
		t.Error("a snapshot without metrics says nothing of usage")
	}
	// A week of days is kept, and then the oldest goes.
	for d := 1; d <= Days; d++ {
		s.Record("prod", snapAt(pod("web-1", 100, 200*mib)), at.Add(time.Duration(d)*24*time.Hour))
	}
	s.mu.Lock()
	days := len(s.data["prod"][Key("shop", "Deployment/web")].Days)
	s.mu.Unlock()
	if days != Days {
		t.Errorf("%d days kept", days)
	}
	// A workload not seen for over a week is forgotten.
	s.Record("prod", snapAt(), at.Add(time.Duration(2*Days+1)*24*time.Hour))
	if _, ok := s.Usage("prod", Key("shop", "Deployment/web")); ok {
		t.Error("a workload gone for a week should be forgotten")
	}
}

func TestAdvise(t *testing.T) {
	s := New()
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for m := 0; m < 120; m++ {
		// Two pods using 80-120m and 400-500Mi, peaking once at 560Mi.
		mem := int64(400+m%100) * mib
		if m == 60 {
			mem = 560 * mib
		}
		s.Record("prod", snapAt(pod("web-1", int64(80+m%40), mem), pod("web-2", 100, 450*mib)), at.Add(time.Duration(m)*time.Minute))
	}
	oom := at.Add(119 * time.Minute)
	p1 := pod("web-1", 0, 0)
	p1.LastTermination, p1.LastTerminatedAt = "OOMKilled", &oom
	snap := snapAt(p1, pod("web-2", 0, 0))
	snap.Workloads = append(snap.Workloads, protocol.Workload{Kind: "Deployment", Namespace: "shop", Name: "new"},
		protocol.Workload{Kind: "Deployment", Namespace: "other", Name: "x"})
	snap.Pods = append(snap.Pods, protocol.Pod{Namespace: "shop", Name: "new-1", Phase: "Running", Owner: "Deployment/new"})
	list := s.Advise("prod", snap, func(ns string) bool { return ns == "shop" }, at.Add(2*time.Hour))
	if len(list) != 2 || list[0].Name != "new" || list[1].Name != "web" {
		t.Fatalf("advice: %+v", list)
	}
	fresh := list[0]
	if fresh.Suggested != nil || !slices.Contains(fresh.Issues, "little-data") || !slices.Contains(fresh.Issues, "no-requests") {
		t.Errorf("a workload without usage: %+v", fresh)
	}
	a := list[1]
	if a.Pods != 2 || a.Minutes != 240 || a.Suggested == nil || a.LastOOM == nil {
		t.Fatalf("web: %+v", a)
	}
	sug := *a.Suggested
	// p95 of CPU is about 118m: +10% is 130m. Memory p95 about 495Mi: +15%
	// is about 570Mi, rounded to 32Mi steps; the limit is 30% over the 560Mi
	// peak.
	if sug.CPURequest < 125 || sug.CPURequest > 140 || sug.CPURequest%10 != 0 {
		t.Errorf("cpu request %d", sug.CPURequest)
	}
	if sug.MemoryRequest < 560*mib || sug.MemoryRequest > 640*mib || sug.MemoryRequest%(32*mib) != 0 {
		t.Errorf("memory request %dMi", sug.MemoryRequest/mib)
	}
	if sug.MemoryLimit < 728*mib || sug.MemoryLimit%(32*mib) != 0 || sug.CPULimit == 0 {
		t.Errorf("limits %+v", sug)
	}
	// A pod was killed for memory: the 600Mi limit goes up by a quarter at
	// least, whatever the minute samples say.
	if sug.MemoryLimit < 750*mib {
		t.Errorf("after an OOM kill the memory limit must rise: %dMi", sug.MemoryLimit/mib)
	}
	calm := Advice{Pods: 1, Minutes: 500, Memory: Stat{P95: 100 * mib, Max: 110 * mib}, CPU: Stat{P95: 50, Max: 60},
		Requests: &protocol.Resources{CPUMilli: 100, MemoryBytes: 128 * mib}, Limits: &protocol.Resources{MemoryBytes: 256 * mib}}
	advise(&calm)
	if calm.Suggested.MemoryLimit != 256*mib {
		t.Errorf("a limit within twice the suggestion stays: %dMi", calm.Suggested.MemoryLimit/mib)
	}
	huge := calm
	huge.Limits = &protocol.Resources{MemoryBytes: 4096 * mib}
	huge.Issues, huge.Suggested = nil, nil
	advise(&huge)
	if huge.Suggested.MemoryLimit >= 1024*mib {
		t.Errorf("a limit far above any use comes down: %dMi", huge.Suggested.MemoryLimit/mib)
	}
	for _, want := range []string{"oom", "memory-near-limit", "cpu-over"} {
		if !slices.Contains(a.Issues, want) {
			t.Errorf("issues %v lack %s", a.Issues, want)
		}
	}
	if slices.Contains(a.Issues, "memory-over") || a.FreeCPU != (1000-sug.CPURequest)*2 {
		t.Errorf("1Gi against about 600Mi is not twice; cpu freed %d: %+v", a.FreeCPU, a.Issues)
	}
	if !Risky("oom") || !Risky("memory-near-limit") || Risky("cpu-over") || Risky("little-data") {
		t.Error("risky")
	}
}

func TestSaveOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sizing.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Record("prod", snapAt(pod("web-1", 100, 200*mib)), time.Now())
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := again.Usage("prod", Key("shop", "Deployment/web")); !ok || u.CPU.Max != 100 || u.Memory.Quantile(.5) < 200*mib {
		t.Errorf("after a restart: %+v %v", u, ok)
	}
	os.WriteFile(path, []byte("{broken"), 0o600)
	broken, err := Open(path)
	if err == nil || broken == nil || broken.Path() != path {
		t.Fatalf("a broken file: %v %v", broken, err)
	}
	if err := broken.Save(); err != nil {
		t.Errorf("a broken file is written over: %v", err)
	}
	if err := New().Save(); err != nil {
		t.Errorf("a store in memory has nothing to save: %v", err)
	}
}

// A memory limit only some containers have is no limit of the pod.
func TestPartialLimits(t *testing.T) {
	s := New()
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for m := 0; m < 90; m++ {
		s.Record("prod", snapAt(pod("web-1", 100, 590*mib)), at.Add(time.Duration(m)*time.Minute))
	}
	p := pod("web-1", 0, 0)
	p.Unlimited = []string{"memory"}
	a := s.Advise("prod", snapAt(p), nil, at.Add(2*time.Hour))[0]
	if slices.Contains(a.Issues, "memory-near-limit") || a.Limits.MemoryBytes != 0 || a.Limits.CPUMilli != 2000 {
		t.Errorf("partial memory limit: %+v %+v", a.Issues, a.Limits)
	}
	full := s.Advise("prod", snapAt(pod("web-1", 0, 0)), nil, at.Add(2*time.Hour))[0]
	if !slices.Contains(full.Issues, "memory-near-limit") {
		t.Errorf("a whole limit of 600Mi against 590Mi used: %+v", full.Issues)
	}
}
