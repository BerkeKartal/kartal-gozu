package rollout

import (
	"strings"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func web(image string, gen, observed int64, desired, updated, ready int32) protocol.Workload {
	return protocol.Workload{Kind: "Deployment", Namespace: "shop", Name: "web", Images: []string{image},
		Generation: gen, ObservedGeneration: observed, Desired: desired, Updated: updated, Ready: ready}
}

func snap(ws []protocol.Workload, pods ...protocol.Pod) *protocol.Snapshot {
	return &protocol.Snapshot{Workloads: ws, Pods: pods}
}

func TestRollout(t *testing.T) {
	tr := New()
	at := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	step := func(d time.Duration, s *protocol.Snapshot) { tr.Observe("prod", s, at.Add(d)) }

	step(0, snap([]protocol.Workload{web("web:1", 3, 3, 2, 2, 2)}))
	if got := tr.Recent(nil, 10); len(got) != 0 {
		t.Fatalf("the first snapshot is the baseline: %+v", got)
	}
	// New image, the controller has not seen it yet: the old status must not
	// count as rolled out.
	step(time.Minute, snap([]protocol.Workload{web("web:2", 4, 3, 2, 2, 2)}))
	r := tr.Recent(nil, 10)
	if len(r) != 1 || r[0].State != "progressing" || r[0].From != "web:1" || r[0].To != "web:2" || r[0].Cause != "image" {
		t.Fatalf("started: %+v", r)
	}
	step(2*time.Minute, snap([]protocol.Workload{web("web:2", 4, 4, 2, 1, 2)}))
	step(3*time.Minute, snap([]protocol.Workload{web("web:2", 4, 4, 2, 2, 2)}))
	r = tr.Recent(nil, 10)
	if r[0].State != "done" || r[0].Finished == nil || r[0].Finished.Sub(r[0].Started) != 2*time.Minute {
		t.Fatalf("done: %+v", r[0])
	}

	// Scaling bumps the generation too, but rolls nothing out.
	step(4*time.Minute, snap([]protocol.Workload{web("web:2", 5, 5, 4, 2, 2)}))
	if len(tr.Recent(nil, 10)) != 1 {
		t.Fatal("scaling is not a rollout")
	}
	// A restart: same images, a new generation, pods being replaced.
	step(5*time.Minute, snap([]protocol.Workload{web("web:2", 6, 6, 4, 1, 4)}))
	if r = tr.Recent(nil, 10); len(r) != 2 || r[0].Cause != "template" {
		t.Fatalf("restart: %+v", r)
	}

	// A version that does not pull gets stuck, and its problem is told.
	pull := protocol.Pod{Namespace: "shop", Name: "web-x", Owner: "Deployment/web", Phase: "Pending", Reason: "ImagePullBackOff"}
	step(6*time.Minute, snap([]protocol.Workload{web("web:3", 7, 7, 4, 1, 3)}, pull))
	if r = tr.Recent(nil, 10); r[1].State != "replaced" || r[0].State != "progressing" {
		t.Fatalf("a newer version replaces one under way: %+v", r)
	}
	step(6*time.Minute+StuckAfter, snap([]protocol.Workload{web("web:3", 7, 7, 4, 1, 3)}, pull))
	r = tr.Recent(nil, 10)
	if r[0].State != "stuck" || strings.Join(r[0].Problems, ",") != "ImagePullBackOff" || !r[0].WasStuck {
		t.Fatalf("stuck: %+v", r[0])
	}
	stuck := tr.Stuck("prod", at.Add(6*time.Minute+StuckAfter))
	if d := stuck["shop\x00Deployment/web"]; !strings.Contains(d, "3 of 4 ready after 10m0s: ImagePullBackOff") {
		t.Errorf("stuck alerts: %q", stuck)
	}
	// It may still get out, late.
	step(20*time.Minute, snap([]protocol.Workload{web("web:3", 7, 7, 4, 4, 4)}))
	if r = tr.Recent(nil, 10); r[0].State != "done" || !r[0].WasStuck || len(tr.Stuck("prod", at.Add(20*time.Minute))) != 0 {
		t.Fatalf("late: %+v", r[0])
	}

	// An OnDelete StatefulSet waits for its pods to be deleted: never stuck.
	db := protocol.Workload{Kind: "StatefulSet", Namespace: "shop", Name: "pg", Images: []string{"pg:15"}, Desired: 1, Updated: 1, Ready: 1, ManualRollout: true}
	step(20*time.Minute, snap([]protocol.Workload{web("web:3", 7, 7, 4, 4, 4), db}))
	db.Images, db.Updated = []string{"pg:16"}, 0
	step(21*time.Minute, snap([]protocol.Workload{web("web:3", 7, 7, 4, 4, 4), db}))
	step(21*time.Minute+2*StuckAfter, snap([]protocol.Workload{web("web:3", 7, 7, 4, 4, 4), db}))
	if r = tr.Recent(func(x Rollout) bool { return x.Name == "pg" }, 1); r[0].State != "progressing" || !r[0].Manual {
		t.Fatalf("OnDelete: %+v", r[0])
	}

	// A list that failed this time does not delete anything.
	failed := &protocol.Snapshot{Errors: []string{"deployments: forbidden"}}
	step(21*time.Minute, snap([]protocol.Workload{web("web:4", 8, 8, 4, 0, 4)}))
	step(22*time.Minute, failed)
	if r = tr.Recent(nil, 1); r[0].State != "progressing" {
		t.Fatalf("a failed list: %+v", r[0])
	}
	step(23*time.Minute, snap(nil))
	if r = tr.Recent(nil, 1); r[0].State != "deleted" {
		t.Fatalf("a deleted workload ends its rollout: %+v", r[0])
	}
	// A new workload rolls out its first version.
	step(24*time.Minute, snap([]protocol.Workload{{Kind: "StatefulSet", Namespace: "db", Name: "pg", Images: []string{"pg:16"}, Desired: 1}}))
	if r = tr.Recent(func(x Rollout) bool { return x.Namespace == "db" }, 5); len(r) != 1 || r[0].From != "" || r[0].To != "pg:16" {
		t.Fatalf("a new workload: %+v", r)
	}
	if got := tr.Recent(nil, 3); len(got) != 3 || got[0].ID < got[1].ID {
		t.Errorf("newest first, at most the limit: %+v", got)
	}
}
