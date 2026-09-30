// Package store keeps the latest state reported by each agent and the queue
// of commands waiting to be picked up. Everything lives in memory: agents
// resend a full snapshot every interval, so a restart heals itself quickly.
package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

var ErrUnknownCluster = errors.New("unknown cluster")

type ClusterInfo struct {
	Name     string
	LastSeen time.Time
	Snapshot *protocol.Snapshot
}

type cluster struct {
	snapshot *protocol.Snapshot
	lastSeen time.Time
	queue    []protocol.Command
	// wake is closed (and replaced) whenever a command is queued, releasing
	// every long-poll currently waiting on this cluster.
	wake chan struct{}
}

type waiter struct {
	cluster string
	ch      chan protocol.Result
}

type Store struct {
	mu       sync.Mutex
	clusters map[string]*cluster
	waiters  map[string]waiter
}

// New creates a store that accepts data only for the given cluster names.
func New(clusters ...string) *Store {
	s := &Store{clusters: map[string]*cluster{}, waiters: map[string]waiter{}}
	for _, name := range clusters {
		s.clusters[name] = &cluster{wake: make(chan struct{})}
	}
	return s
}

func (s *Store) PutSnapshot(name string, snap *protocol.Snapshot, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clusters[name]
	if !ok {
		return ErrUnknownCluster
	}
	c.snapshot = snap
	c.lastSeen = at
	return nil
}

// Touch records agent activity without a new snapshot (e.g. a command poll).
func (s *Store) Touch(name string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clusters[name]; ok && at.After(c.lastSeen) {
		c.lastSeen = at
	}
}

func (s *Store) Clusters() []ClusterInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ClusterInfo, 0, len(s.clusters))
	for name, c := range s.clusters {
		out = append(out, ClusterInfo{Name: name, LastSeen: c.lastSeen, Snapshot: c.snapshot})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Cluster(name string) (ClusterInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clusters[name]
	if !ok {
		return ClusterInfo{}, false
	}
	return ClusterInfo{Name: name, LastSeen: c.lastSeen, Snapshot: c.snapshot}, true
}

// Enqueue queues a command for a cluster. The returned channel receives the
// agent's result; cancel must be called once the caller stops waiting.
func (s *Store) Enqueue(name string, cmd protocol.Command) (<-chan protocol.Result, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clusters[name]
	if !ok {
		return nil, nil, ErrUnknownCluster
	}
	ch := make(chan protocol.Result, 1)
	s.waiters[cmd.ID] = waiter{cluster: name, ch: ch}
	c.queue = append(c.queue, cmd)
	close(c.wake)
	c.wake = make(chan struct{})

	cancel := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.waiters, cmd.ID)
		for i, q := range c.queue {
			if q.ID == cmd.ID {
				c.queue = append(c.queue[:i], c.queue[i+1:]...)
				break
			}
		}
	}
	return ch, cancel, nil
}

// TakeCommands returns queued commands immediately, or waits up to wait for
// one to arrive. It returns nil when nothing arrived in time.
func (s *Store) TakeCommands(ctx context.Context, name string, wait time.Duration) ([]protocol.Command, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		s.mu.Lock()
		c, ok := s.clusters[name]
		if !ok {
			s.mu.Unlock()
			return nil, ErrUnknownCluster
		}
		if len(c.queue) > 0 {
			cmds := c.queue
			c.queue = nil
			s.mu.Unlock()
			return cmds, nil
		}
		wake := c.wake
		s.mu.Unlock()

		select {
		case <-wake:
		case <-timer.C:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Deliver hands a result to whoever is waiting for it. Results are only
// accepted from the cluster the command was sent to.
func (s *Store) Deliver(name string, res protocol.Result) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.waiters[res.CommandID]
	if !ok || w.cluster != name {
		return false
	}
	delete(s.waiters, res.CommandID)
	w.ch <- res
	return true
}
