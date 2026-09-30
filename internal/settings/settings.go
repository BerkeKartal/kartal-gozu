// Package settings keeps what admins change in the UI, such as the e-mail
// server for notifications, so that it survives restarts: in a Kubernetes
// Secret next to the server, or in a file when it runs elsewhere.
package settings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
)

// Email is the e-mail channel for notifications.
type Email struct {
	Enabled  bool     `json:"enabled"`
	Addr     string   `json:"addr"` // host:port of the SMTP server
	From     string   `json:"from"`
	To       []string `json:"to"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
}

// Settings is everything kept.
type Settings struct {
	Email Email `json:"email"`
}

// maxRecipients keeps a mistake from mailing a whole address book.
const maxRecipients = 50

// Check validates the e-mail settings. Turned off, they may be incomplete.
func (e Email) Check() error {
	if !e.Enabled && e.Addr == "" && e.From == "" && len(e.To) == 0 {
		return nil
	}
	host, port, err := net.SplitHostPort(e.Addr)
	if err != nil || host == "" {
		return fmt.Errorf("the SMTP server must look like host:port, such as smtp.example.org:587")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("the SMTP port %q is not a port number", port)
	}
	if _, err := mail.ParseAddress(e.From); err != nil {
		return fmt.Errorf("the sender %q is not an e-mail address", e.From)
	}
	if len(e.To) == 0 {
		return errors.New("at least one recipient is needed")
	}
	if len(e.To) > maxRecipients {
		return fmt.Errorf("at most %d recipients", maxRecipients)
	}
	for _, to := range e.To {
		if _, err := mail.ParseAddress(to); err != nil {
			return fmt.Errorf("the recipient %q is not an e-mail address", to)
		}
	}
	if strings.ContainsAny(e.Username+e.Password, "\r\n") {
		return errors.New("the user name and password may not contain line breaks")
	}
	return nil
}

// Recipients splits a list of addresses separated by commas, semicolons or
// new lines.
func Recipients(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Store keeps the settings.
type Store interface {
	Load(ctx context.Context) (Settings, error)
	Save(ctx context.Context, s Settings) error
	// Where names the place, for the UI and the log; empty for memory.
	Where() string
}

// Memory keeps the settings until the server stops.
type Memory struct{}

func (Memory) Load(context.Context) (Settings, error) { return Settings{}, nil }
func (Memory) Save(context.Context, Settings) error   { return nil }
func (Memory) Where() string                          { return "" }

// File keeps the settings in a JSON file, readable by its owner only.
type File struct{ Path string }

func (f File) Where() string { return f.Path }

func (f File) Load(context.Context) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", f.Path, err)
	}
	return s, nil
}

func (f File) Save(_ context.Context, s Settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Written aside and renamed, so a crash never leaves half a file.
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

// secretKey is where the settings sit in the Secret.
const secretKey = "settings.json"

// Secret keeps the settings in a Kubernetes Secret, which must exist; the
// server only needs to get and patch that one Secret.
type Secret struct {
	Kube      *kube.Client
	Namespace string
	Name      string
}

func (s Secret) Where() string { return "Secret " + s.Namespace + "/" + s.Name }

func (s Secret) path() string {
	return "/api/v1/namespaces/" + kube.Seg(s.Namespace) + "/secrets/" + kube.Seg(s.Name)
}

func (s Secret) Load(ctx context.Context) (Settings, error) {
	var out Settings
	var sec struct {
		Data map[string]string `json:"data"`
	}
	if err := s.Kube.Get(ctx, s.path(), &sec); err != nil {
		if kube.IsNotFound(err) {
			return out, fmt.Errorf("%s does not exist; create it (deploy/server/settings-secret.yaml)", s.Where())
		}
		return out, err
	}
	raw, ok := sec.Data[secretKey]
	if !ok {
		return out, nil // nothing saved yet
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return out, fmt.Errorf("%s: %w", s.Where(), err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("%s: %w", s.Where(), err)
	}
	return out, nil
}

func (s Secret) Save(ctx context.Context, st Settings) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	patch, _ := json.Marshal(map[string]any{"data": map[string]string{secretKey: base64.StdEncoding.EncodeToString(b)}})
	if _, err := s.Kube.Send(ctx, http.MethodPatch, s.path(), "application/merge-patch+json", patch, 1<<20); err != nil {
		if kube.IsNotFound(err) {
			return fmt.Errorf("%s does not exist; create it (deploy/server/settings-secret.yaml)", s.Where())
		}
		return err
	}
	return nil
}
