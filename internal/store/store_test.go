package store

import (
	"context"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestLongPollWakesWhenACommandArrives(t *testing.T) {
	s := New("a")
	got := make(chan []protocol.Command, 1)
	go func() {
		cmds, _ := s.TakeCommands(context.Background(), "a", 5*time.Second)
		got <- cmds
	}()
	time.Sleep(20 * time.Millisecond)
	if _, _, err := s.Enqueue("a", protocol.Command{ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case cmds := <-got:
		if len(cmds) != 1 || cmds[0].ID != "c1" {
			t.Fatalf("cmds = %+v", cmds)
		}
	case <-time.After(time.Second):
		t.Fatal("long-poll was not woken up")
	}
}

func TestLongPollTimesOutEmpty(t *testing.T) {
	s := New("a")
	cmds, err := s.TakeCommands(context.Background(), "a", 20*time.Millisecond)
	if err != nil || cmds != nil {
		t.Fatalf("cmds=%v err=%v", cmds, err)
	}
}

func TestResultsOnlyAcceptedFromTheTargetCluster(t *testing.T) {
	s := New("a", "b")
	ch, cancel, err := s.Enqueue("a", protocol.Command{ID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if s.Deliver("b", protocol.Result{CommandID: "c1", OK: true}) {
		t.Fatal("cluster b answered a command sent to cluster a")
	}
	if !s.Deliver("a", protocol.Result{CommandID: "c1", OK: true, Output: "done"}) {
		t.Fatal("rightful result rejected")
	}
	if res := <-ch; res.Output != "done" {
		t.Fatalf("res = %+v", res)
	}
	if s.Deliver("a", protocol.Result{CommandID: "c1"}) {
		t.Fatal("a result was accepted twice")
	}
}

func TestCancelDropsAnUntakenCommand(t *testing.T) {
	s := New("a")
	_, cancel, _ := s.Enqueue("a", protocol.Command{ID: "c1"})
	cancel()
	if cmds, _ := s.TakeCommands(context.Background(), "a", 10*time.Millisecond); len(cmds) != 0 {
		t.Fatalf("cancelled command still queued: %+v", cmds)
	}
}

func TestUnknownClusterIsRejected(t *testing.T) {
	s := New("a")
	if err := s.PutSnapshot("x", &protocol.Snapshot{}, time.Now()); err != ErrUnknownCluster {
		t.Errorf("PutSnapshot err = %v", err)
	}
	if _, _, err := s.Enqueue("x", protocol.Command{ID: "1"}); err != ErrUnknownCluster {
		t.Errorf("Enqueue err = %v", err)
	}
	if _, err := s.TakeCommands(context.Background(), "x", time.Millisecond); err != ErrUnknownCluster {
		t.Errorf("TakeCommands err = %v", err)
	}
}
