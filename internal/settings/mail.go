package settings

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
)

// Mail is the e-mail channel's settings. They are kept in a Store and put
// behind the alert manager's e-mail channel whenever they change. Settings
// from the server's environment (KARTAL_SMTP_*) win and are read-only here.
type Mail struct {
	store   Store
	channel *alert.Switchable
	fixed   bool

	mu        sync.Mutex
	all       Settings
	loadError string
}

// ErrFixed refuses changes to settings that come from the environment.
var ErrFixed = errors.New("e-mail is set by the server's environment (KARTAL_SMTP_*); change it there")

// InvalidError is a change that does not make sense, as opposed to one that
// could not be saved.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string { return e.Err.Error() }
func (e *InvalidError) Unwrap() error { return e.Err }

// NewMail loads the saved settings and turns the channel on if they say so.
// env, when not nil, comes from the environment and wins.
func NewMail(ctx context.Context, store Store, channel *alert.Switchable, env *Email, log *slog.Logger) *Mail {
	m := &Mail{store: store, channel: channel}
	if env != nil {
		m.fixed = true
		m.all.Email = *env
		m.apply()
		return m
	}
	all, err := store.Load(ctx)
	if err != nil {
		m.loadError = err.Error()
		if log != nil {
			log.Error("the saved settings could not be read", "store", store.Where(), "err", err)
		}
	}
	m.all = all
	m.apply()
	return m
}

func notifier(e Email) alert.Notifier {
	return alert.Email{Addr: e.Addr, From: e.From, To: e.To, Username: e.Username, Password: e.Password}
}

// apply puts the settings behind the channel, or turns it off.
func (m *Mail) apply() {
	if e := m.all.Email; e.Enabled && e.Check() == nil {
		m.channel.Set(notifier(e))
	} else {
		m.channel.Set(nil)
	}
}

// View is what the UI sees: everything but the password.
type View struct {
	Enabled     bool     `json:"enabled"`
	Addr        string   `json:"addr"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	Username    string   `json:"username"`
	PasswordSet bool     `json:"passwordSet"`
	// Fixed means the server's environment sets these; the UI only shows them.
	Fixed bool `json:"fixed"`
	// Where names the store; empty means changes last until a restart.
	Where     string `json:"where"`
	LoadError string `json:"loadError,omitempty"`
}

func (m *Mail) View() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view()
}

func (m *Mail) view() View {
	e := m.all.Email
	to := e.To
	if to == nil {
		to = []string{}
	}
	v := View{Enabled: e.Enabled, Addr: e.Addr, From: e.From, To: to, Username: e.Username, PasswordSet: e.Password != "",
		Fixed: m.fixed, LoadError: m.loadError}
	if !m.fixed {
		v.Where = m.store.Where()
	}
	return v
}

// Change is an edit from the UI. A nil Password keeps the saved one; an
// empty one removes it.
type Change struct {
	Enabled  bool     `json:"enabled"`
	Addr     string   `json:"addr"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	Username string   `json:"username"`
	Password *string  `json:"password"`
}

// merged is what a change would make of the current settings.
func (m *Mail) merged(c Change) Email {
	e := Email{Enabled: c.Enabled, Addr: strings.TrimSpace(c.Addr), From: strings.TrimSpace(c.From),
		Username: strings.TrimSpace(c.Username), Password: m.all.Email.Password}
	for _, to := range c.To {
		e.To = append(e.To, Recipients(to)...)
	}
	if c.Password != nil {
		e.Password = *c.Password
	}
	return e
}

// Update checks, saves and applies a change; nothing changes if the change
// cannot be saved.
func (m *Mail) Update(ctx context.Context, c Change) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fixed {
		return View{}, ErrFixed
	}
	e := m.merged(c)
	if err := e.Check(); err != nil {
		return View{}, &InvalidError{err}
	}
	next := m.all
	next.Email = e
	if err := m.store.Save(ctx, next); err != nil {
		return View{}, err
	}
	m.all, m.loadError = next, ""
	m.apply()
	return m.view(), nil
}

// Test sends a sample notification with the settings a change would give,
// without saving them, so they can be tried before they are kept.
func (m *Mail) Test(ctx context.Context, c Change, publicURL string) error {
	m.mu.Lock()
	e := m.all.Email
	if !m.fixed {
		e = m.merged(c)
	}
	m.mu.Unlock()
	e.Enabled = true // a test needs everything, whether or not it is on
	if err := e.Check(); err != nil {
		return &InvalidError{err}
	}
	return notifier(e).Send(ctx, alert.SampleNotification(publicURL))
}

// Summary describes the settings in a line for the audit log.
func (v View) Summary() string {
	if !v.Enabled {
		return "e-mail off"
	}
	return "e-mail on: " + v.Addr + " → " + strings.Join(v.To, ", ")
}
