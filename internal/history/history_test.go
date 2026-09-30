package history

import (
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func snap(cpu int64) *protocol.Snapshot {
	return &protocol.Snapshot{
		MetricsAvailable: true,
		Nodes:            []protocol.Node{{Name: "n1", Usage: &protocol.Resources{CPUMilli: cpu, MemoryBytes: 2 << 30}}},
		Pods:             []protocol.Pod{{Namespace: "a", Name: "p", Usage: &protocol.Resources{CPUMilli: cpu / 2, MemoryBytes: 64 << 20}}},
	}
}

func TestRecordAndQuery(t *testing.T) {
	s := New()
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 90; i++ {
		// Four reports a minute; the last one of each minute stays.
		for j := 0; j < 4; j++ {
			s.Record("c", snap(int64(100+i*10+j)), start.Add(time.Duration(i)*time.Minute+time.Duration(j)*15*time.Second))
		}
	}
	now := start.Add(89 * time.Minute)
	pts := s.Query("c", Key("node", "", "n1"), time.Hour, now)
	if len(pts) != 60 {
		t.Fatalf("an hour should give 60 points, got %d", len(pts))
	}
	last := pts[len(pts)-1]
	if last.CPUMilli != 100+89*10+3 || last.MemoryBytes != 2<<30 || last.Time != now.UnixMilli() {
		t.Errorf("last point: %+v", last)
	}
	if pts[0].Time >= last.Time {
		t.Error("points are not oldest first")
	}
	if pod := s.Query("c", Key("pod", "a", "p"), 6*time.Hour, now); len(pod) != 90 {
		t.Errorf("pod series: %d points", len(pod))
	}
	if total := s.Query("c", Key("cluster", "", ""), time.Hour, now); len(total) != 60 || total[59].CPUMilli != last.CPUMilli {
		t.Errorf("cluster series: %+v", total)
	}
	if none := s.Query("c", Key("pod", "a", "gone"), time.Hour, now); len(none) != 0 {
		t.Errorf("unknown series: %+v", none)
	}
}

func TestOldSeriesAreForgotten(t *testing.T) {
	s := New()
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	s.Record("c", snap(100), start)
	later := &protocol.Snapshot{MetricsAvailable: true}
	s.Record("c", later, start.Add(7*time.Hour))
	if pts := s.Query("c", Key("pod", "a", "p"), 6*time.Hour, start.Add(7*time.Hour)); len(pts) != 0 {
		t.Errorf("a pod gone for longer than the window is still kept: %+v", pts)
	}
	s.mu.Lock()
	n := len(s.clusters["c"])
	s.mu.Unlock()
	if n != 1 { // only the cluster total remains
		t.Errorf("%d series remain", n)
	}
}

// Filling in the past after a current sample keeps both.
func TestRecordingThePast(t *testing.T) {
	s := New()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	s.Record("c", snap(500), now)
	for m := Points - 1; m >= 1; m-- {
		s.Record("c", snap(int64(m)), now.Add(-time.Duration(m)*time.Minute))
	}
	pts := s.Query("c", Key("node", "", "n1"), 6*time.Hour, now)
	if len(pts) != Points || pts[len(pts)-1].CPUMilli != 500 || pts[0].CPUMilli != Points-1 {
		t.Fatalf("got %d points, first %+v, last %+v", len(pts), pts[0], pts[len(pts)-1])
	}
}
