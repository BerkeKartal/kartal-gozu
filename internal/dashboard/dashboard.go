// Package dashboard keeps the dashboards people save: pages of panels over
// the metric store and the data sources. They are kept with the other
// settings; what a panel shows is queried for whoever looks at it, with
// what that person may see.
package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

var (
	// ErrNotFound is a dashboard that does not exist (any more).
	ErrNotFound = errors.New("no such dashboard")
	// ErrNotYours is a change to a dashboard someone else made.
	ErrNotYours = errors.New("only the one who made this dashboard, or an admin, may change it")
)

// ConflictError is a save over a dashboard that changed since it was read.
type ConflictError struct {
	By      string
	Version int
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s saved this dashboard meanwhile (version %d); open it again and redo your change", e.By, e.Version)
}

// Manager keeps the dashboards.
type Manager struct {
	keeper *settings.Keeper
	edit   sync.Mutex
	// Now can be replaced in tests.
	Now func() time.Time
}

func New(keeper *settings.Keeper) *Manager { return &Manager{keeper: keeper, Now: time.Now} }

// Summary is a dashboard in a list.
type Summary struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Panels      int       `json:"panels"`
	Owner       string    `json:"owner"`
	Updated     time.Time `json:"updated"`
	UpdatedBy   string    `json:"updatedBy"`
}

// List describes the dashboards, by title.
func (m *Manager) List() []Summary {
	out := []Summary{}
	for _, d := range m.keeper.Get().Dashboards {
		out = append(out, Summary{ID: d.ID, Title: d.Title, Description: d.Description, Panels: len(d.Panels),
			Owner: d.Owner, Updated: d.Updated, UpdatedBy: d.UpdatedBy})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title) })
	return out
}

// Get finds a dashboard.
func (m *Manager) Get(id string) (settings.Dashboard, bool) {
	for _, d := range m.keeper.Get().Dashboards {
		if d.ID == id {
			return d, true
		}
	}
	return settings.Dashboard{}, false
}

// Where names the store the dashboards are kept in; empty is memory.
func (m *Manager) Where() string { return m.keeper.Where() }

func invalid(err error) error { return &settings.InvalidError{Err: err} }

// fits tells whether the dashboards take no more than they may.
func fits(all []settings.Dashboard) error {
	if len(all) > settings.MaxDashboards {
		return invalid(fmt.Errorf("at most %d dashboards", settings.MaxDashboards))
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	if len(b) > settings.MaxDashboardBytes {
		return invalid(fmt.Errorf("the dashboards would take %d KiB, more than the %d KiB they may; remove some panels or dashboards", len(b)>>10, settings.MaxDashboardBytes>>10))
	}
	return nil
}

// Add saves a new dashboard made by user.
func (m *Manager) Add(ctx context.Context, d settings.Dashboard, user string) (settings.Dashboard, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	d.ID, d.Owner, d.Version, d.Updated, d.UpdatedBy = settings.NewCheckID(), user, 1, m.Now().UTC(), user
	if err := d.Normalize(); err != nil {
		return d, invalid(err)
	}
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		all := append(slices.Clone(s.Dashboards), d)
		if err := fits(all); err != nil {
			return err
		}
		s.Dashboards = all
		return nil
	})
	return d, err
}

// Save replaces a dashboard with d, if mine says the user may change it and
// d is of the version saved: a save in between is not undone.
func (m *Manager) Save(ctx context.Context, id string, d settings.Dashboard, user string, mine func(settings.Dashboard) bool) (settings.Dashboard, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	if err := d.Normalize(); err != nil {
		return d, invalid(err)
	}
	var saved settings.Dashboard
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Dashboards, func(x settings.Dashboard) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		old := s.Dashboards[i]
		if !mine(old) {
			return ErrNotYours
		}
		if d.Version != old.Version {
			return &ConflictError{By: old.UpdatedBy, Version: old.Version}
		}
		d.ID, d.Owner, d.Version, d.Updated, d.UpdatedBy = id, old.Owner, old.Version+1, m.Now().UTC(), user
		all := slices.Clone(s.Dashboards)
		all[i] = d
		if err := fits(all); err != nil {
			return err
		}
		s.Dashboards, saved = all, d
		return nil
	})
	return saved, err
}

// Remove deletes a dashboard, if mine says the user may.
func (m *Manager) Remove(ctx context.Context, id string, mine func(settings.Dashboard) bool) (settings.Dashboard, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	var gone settings.Dashboard
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.Dashboards, func(x settings.Dashboard) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		if !mine(s.Dashboards[i]) {
			return ErrNotYours
		}
		gone = s.Dashboards[i]
		s.Dashboards = slices.Delete(slices.Clone(s.Dashboards), i, i+1)
		return nil
	})
	return gone, err
}
