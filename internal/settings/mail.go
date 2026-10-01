package settings

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
)

// Mail is the e-mail channel's settings. They are kept by a Keeper and put
// behind the alert manager's e-mail channel whenever they change. Settings
// from the server's environment (KARTAL_SMTP_*) win and are read-only here.
type Mail struct {
	keeper  *Keeper
	channel *alert.Switchable
	env     *Email // set: the environment's, fixed

	// mu keeps changes in order, so the channel gets the settings saved last.
	mu sync.Mutex
}

// ErrFixed refuses changes to settings that come from the environment.
var ErrFixed = errors.New("e-mail is set by the server's environment (KARTAL_SMTP_*); change it there")

// InvalidError is a change that does not make sense, as opposed to one that
// could not be saved.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string { return e.Err.Error() }
func (e *InvalidError) Unwrap() error { return e.Err }

// NewMail turns the channel on if the settings say so. env, when not nil,
// comes from the environment and wins.
func NewMail(keeper *Keeper, channel *alert.Switchable, env *Email) *Mail {
	m := &Mail{keeper: keeper, channel: channel, env: env}
	m.apply(m.current())
	return m
}

func (m *Mail) current() Email {
	if m.env != nil {
		return *m.env
	}
	return m.keeper.Get().Email
}

func notifier(e Email) alert.Notifier {
	return alert.Email{Addr: e.Addr, From: e.From, To: e.To, Username: e.Username, Password: e.Password}
}

// apply puts the settings behind the channel, or turns it off.
func (m *Mail) apply(e Email) {
	if e.Enabled && e.Check() == nil {
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
	e := m.current()
	to := e.To
	if to == nil {
		to = []string{}
	}
	v := View{Enabled: e.Enabled, Addr: e.Addr, From: e.From, To: to, Username: e.Username, PasswordSet: e.Password != "",
		Fixed: m.env != nil}
	if m.env == nil {
		v.Where, v.LoadError = m.keeper.Where(), m.keeper.LoadError()
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

// merged is what a change makes of saved settings.
func merged(c Change, saved Email) Email {
	e := Email{Enabled: c.Enabled, Addr: strings.TrimSpace(c.Addr), From: strings.TrimSpace(c.From),
		Username: strings.TrimSpace(c.Username), Password: saved.Password}
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
	if m.env != nil {
		return View{}, ErrFixed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.keeper.Update(ctx, func(s *Settings) error {
		e := merged(c, s.Email)
		if err := e.Check(); err != nil {
			return &InvalidError{err}
		}
		s.Email = e
		return nil
	})
	if err != nil {
		return View{}, err
	}
	m.apply(all.Email)
	return m.View(), nil
}

// Test sends a sample notification with the settings a change would give,
// without saving them, so they can be tried before they are kept.
func (m *Mail) Test(ctx context.Context, c Change, publicURL string) error {
	e := m.current()
	if m.env == nil {
		e = merged(c, e)
	}
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

// Reload puts the kept settings behind the channel again, for when they
// could be read only after the server started.
func (m *Mail) Reload() { m.apply(m.current()) }
