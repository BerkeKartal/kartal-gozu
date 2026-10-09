package datasource

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// ErrNotFound is a source that does not exist (any more).
var ErrNotFound = errors.New("no such data source")

// Manager keeps the sources in the settings, and queries them.
type Manager struct {
	keeper *settings.Keeper
	Client *Client
	edit   sync.Mutex
}

func NewManager(keeper *settings.Keeper) *Manager {
	return &Manager{keeper: keeper, Client: New(nil)}
}

// Attach gives the manager a way to ask the clusters' agents, for the
// sources reached through one. It is called before the server serves.
func (m *Manager) Attach(ask func(context.Context, string, protocol.Command) (protocol.Result, error)) {
	m.Client.Ask = ask
}

// Get finds a source by its ID.
func (m *Manager) Get(id string) (settings.DataSource, bool) {
	for _, d := range m.keeper.Get().DataSources {
		if d.ID == id {
			return d, true
		}
	}
	return settings.DataSource{}, false
}

// List returns the sources.
func (m *Manager) List() []settings.DataSource { return m.keeper.Get().DataSources }

// View is a source for the UI: its password and token never leave the
// server, only whether it has them.
type View struct {
	settings.DataSource
	PasswordSet bool `json:"passwordSet"`
	TokenSet    bool `json:"tokenSet"`
}

func ViewOf(d settings.DataSource) View {
	v := View{DataSource: d, PasswordSet: d.Password != "", TokenSet: d.Token != ""}
	v.Password, v.Token = "", ""
	return v
}

// Where names the store the sources are kept in; LoadError says why they
// could not be read, if they could not.
func (m *Manager) Where() string     { return m.keeper.Where() }
func (m *Manager) LoadError() string { return m.keeper.LoadError() }

// Complete fills in a source's password or token from the saved source of
// that ID when the change leaves them empty: the UI never has them. A
// source whose authentication changed starts over. The saved ones are not
// sent to another address: one that moved must be given them again.
func (m *Manager) Complete(d *settings.DataSource) error {
	old, ok := m.Get(d.ID)
	if !ok || old.Auth != strings.TrimSpace(d.Auth) {
		return nil
	}
	password := d.Password == "" && old.Password != "" && old.Auth == "basic" && strings.TrimSpace(d.Username) == old.Username
	token := d.Token == "" && old.Token != "" && (old.Auth == "bearer" || old.Auth == "apikey")
	if !password && !token {
		return nil
	}
	if strings.TrimSuffix(strings.TrimSpace(d.URL), "/") != old.URL || strings.TrimSpace(d.Via) != old.Via {
		return errors.New("the address changed: give the password or token again, as the saved one is not sent to a new address")
	}
	if password {
		d.Password = old.Password
	}
	if token {
		d.Token = old.Token
	}
	return nil
}

func invalid(err error) error {
	if err == nil {
		return nil
	}
	return &settings.InvalidError{Err: err}
}

// Add saves a new source.
func (m *Manager) Add(ctx context.Context, d settings.DataSource) (settings.DataSource, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	d.ID = settings.NewCheckID()
	if err := d.Normalize(); err != nil {
		return d, invalid(err)
	}
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if len(s.DataSources) >= settings.MaxDataSources {
			return invalid(fmt.Errorf("at most %d data sources", settings.MaxDataSources))
		}
		s.DataSources = append(s.DataSources, d)
		return nil
	})
	return d, err
}

// Change saves a source's new settings; an empty password or token keeps
// the saved one.
func (m *Manager) Change(ctx context.Context, id string, d settings.DataSource) (settings.DataSource, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	d.ID = id
	if err := m.Complete(&d); err != nil {
		return d, invalid(err)
	}
	if err := d.Normalize(); err != nil {
		return d, invalid(err)
	}
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.DataSources, func(x settings.DataSource) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		s.DataSources[i] = d
		return nil
	})
	return d, err
}

// Remove deletes a source.
func (m *Manager) Remove(ctx context.Context, id string) (settings.DataSource, error) {
	m.edit.Lock()
	defer m.edit.Unlock()
	var gone settings.DataSource
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i := slices.IndexFunc(s.DataSources, func(x settings.DataSource) bool { return x.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		gone = s.DataSources[i]
		s.DataSources = slices.Delete(s.DataSources, i, i+1)
		return nil
	})
	return gone, err
}
