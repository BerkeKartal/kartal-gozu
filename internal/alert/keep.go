package alert

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// restoreHold is how long after a restart an alert read from the file is
// kept although nothing found it again: the address checks, the watches
// and the log rules each have to run once first, and until then nobody is
// told that their problems ended.
const restoreHold = 5 * time.Minute

// kept is what the alerts' file holds.
type kept struct {
	Active []Alert `json:"active"`
	Recent []Alert `json:"recent"`
}

// Restore reads the alerts kept in a file, and has Save keep them there
// from now on. A restart then neither forgets since when a problem has
// lasted nor tells people again of the ones they were told of; what ended
// while the server was away is resolved by the first snapshot. known says
// which clusters the server still has: the alerts of others are dropped,
// and so are the stuck rollouts, which are followed in memory and cannot
// be found again. Call it before anything is observed.
func (m *Manager) Restore(path string, known func(cluster string) bool, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = path
	m.holdUntil = now.Add(restoreHold)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var k kept
	if err := json.Unmarshal(b, &k); err != nil {
		return err
	}
	for _, a := range k.Active {
		if a.Kind == "" || a.Kind == RolloutStuck || (a.Cluster != "" && known != nil && !known(a.Cluster)) {
			m.changed = true
			continue
		}
		x := a
		x.Resolved, x.Silenced, x.restored = nil, false, true
		m.active[x.key()] = &x
	}
	if len(k.Recent) > keepRecent {
		k.Recent = k.Recent[len(k.Recent)-keepRecent:]
	}
	m.recent = k.Recent
	return nil
}

// Save writes the alerts to their file, whole or not at all, when they
// changed since it was last written. Without a file it does nothing.
func (m *Manager) Save() error {
	m.mu.Lock()
	if m.path == "" || !m.changed {
		m.mu.Unlock()
		return nil
	}
	k := kept{Active: make([]Alert, 0, len(m.active)), Recent: m.recent}
	for _, a := range m.active {
		k.Active = append(k.Active, *a)
	}
	sortAlerts(k.Active)
	b, err := json.Marshal(k)
	path := m.path
	m.changed = false
	m.mu.Unlock()
	if err == nil {
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, filepath.Clean(path))
		}
	}
	if err != nil {
		// Not written: the next Save tries again.
		m.mu.Lock()
		m.changed = true
		m.mu.Unlock()
	}
	return err
}
