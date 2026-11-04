// Package silence keeps the silences people set on alerts: maintenance
// windows, and problems someone is already on. They are kept with the
// other settings; the alert manager asks, for each problem due, whether
// one covers it, so they are also kept in memory.
package silence

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

var (
	// ErrNotFound is a silence that does not exist, or is over.
	ErrNotFound = errors.New("no such silence; it may be over already")
	// ErrNotAllowed is a silence the user may not end.
	ErrNotAllowed = errors.New("your role may not end this silence: it needs an operator of all it covers")
)

// Manager keeps the silences.
type Manager struct {
	keeper *settings.Keeper
	edit   sync.Mutex

	mu   sync.RWMutex
	list []settings.Silence
	// Now can be replaced in tests.
	Now func() time.Time
}

func New(keeper *settings.Keeper) *Manager {
	m := &Manager{keeper: keeper, Now: time.Now}
	m.Reload()
	return m
}

// Reload reads the silences from the settings again, as when they could
// not be read at the start.
func (m *Manager) Reload() { m.set(m.keeper.Get().Silences) }

func (m *Manager) set(list []settings.Silence) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.list = slices.Clone(list)
}

// List is the silences not over yet that keep accepts (nil: all), the
// soonest to end first.
func (m *Manager) List(keep func(settings.Silence) bool) []settings.Silence {
	now := m.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []settings.Silence{}
	for _, s := range m.list {
		if s.Ends.After(now) && (keep == nil || keep(s)) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ends.Before(out[j].Ends) })
	return out
}

// Covers tells whether a silence is on at now for an alert of a kind about
// an object in a namespace of a cluster.
func (m *Manager) Covers(cluster, kind, namespace, object string, now time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.list {
		if s.Covers(cluster, kind, namespace, object, now) {
			return true
		}
	}
	return false
}

// Where names the store they are kept in; empty is memory.
func (m *Manager) Where() string { return m.keeper.Where() }

// LoadError is why the saved settings could not be read, if they could not.
func (m *Manager) LoadError() string { return m.keeper.LoadError() }

// current is the silences not over at now.
func current(list []settings.Silence, now time.Time) []settings.Silence {
	return slices.DeleteFunc(slices.Clone(list), func(s settings.Silence) bool { return !s.Ends.After(now) })
}

// Add saves a new silence set by user, starting now unless it says when;
// the ones over by now are dropped.
func (m *Manager) Add(ctx context.Context, s settings.Silence, user string) (settings.Silence, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	now := m.Now().UTC()
	s.ID, s.By = settings.NewCheckID(), user
	s.Normalize()
	if s.Starts.IsZero() || s.Starts.Before(now) {
		s.Starts = now
	}
	s.Starts, s.Ends = s.Starts.UTC(), s.Ends.UTC()
	if err := s.Validate(now); err != nil {
		return s, &settings.InvalidError{Err: err}
	}
	saved, err := m.keeper.Update(ctx, func(all *settings.Settings) error {
		kept := current(all.Silences, now)
		if len(kept) >= settings.MaxSilences {
			return &settings.InvalidError{Err: fmt.Errorf("at most %d silences may be on or ahead; end some first", settings.MaxSilences)}
		}
		all.Silences = append(kept, s)
		return nil
	})
	if err == nil {
		m.set(saved.Silences)
	}
	return s, err
}

// Remove ends a silence at once, if may says the user may end it.
func (m *Manager) Remove(ctx context.Context, id string, may func(settings.Silence) bool) (settings.Silence, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	now := m.Now().UTC()
	var gone settings.Silence
	saved, err := m.keeper.Update(ctx, func(all *settings.Settings) error {
		kept := current(all.Silences, now)
		i := slices.IndexFunc(kept, func(s settings.Silence) bool { return s.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		gone = kept[i]
		if !may(gone) {
			return ErrNotAllowed
		}
		all.Silences = slices.Delete(kept, i, i+1)
		return nil
	})
	if err == nil {
		m.set(saved.Silences)
	}
	return gone, err
}
