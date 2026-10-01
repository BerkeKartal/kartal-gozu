package settings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/alert"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
)

func valid() Email {
	return Email{Enabled: true, Addr: "smtp.example.org:587", From: "Kartal <kartal@example.org>", To: []string{"ops@example.org"}}
}

func TestCheck(t *testing.T) {
	if err := (Email{}).Check(); err != nil {
		t.Errorf("empty and off should pass: %v", err)
	}
	if err := valid().Check(); err != nil {
		t.Errorf("valid: %v", err)
	}
	for name, change := range map[string]func(*Email){
		"no port":        func(e *Email) { e.Addr = "smtp.example.org" },
		"bad port":       func(e *Email) { e.Addr = "smtp.example.org:99999" },
		"bad sender":     func(e *Email) { e.From = "not an address" },
		"no recipient":   func(e *Email) { e.To = nil },
		"bad recipient":  func(e *Email) { e.To = []string{"ops@example.org", "nope"} },
		"too many":       func(e *Email) { e.To = strings.Split(strings.Repeat("a@example.org,", 51), ",")[:51] },
		"header in user": func(e *Email) { e.Username = "u\r\nBcc: x@example.org" },
	} {
		e := valid()
		change(&e)
		if e.Check() == nil {
			t.Errorf("%s: accepted %+v", name, e)
		}
	}
}

func TestRecipients(t *testing.T) {
	got := Recipients(" a@example.org, b@example.org;\nc@example.org ,, ")
	if !reflect.DeepEqual(got, []string{"a@example.org", "b@example.org", "c@example.org"}) {
		t.Errorf("got %q", got)
	}
}

func TestFileStore(t *testing.T) {
	f := File{Path: filepath.Join(t.TempDir(), "settings.json")}
	if s, err := f.Load(context.Background()); err != nil || !reflect.DeepEqual(s, Settings{}) {
		t.Fatalf("a missing file is empty settings: %+v %v", s, err)
	}
	want := Settings{Email: valid()}
	want.Email.Password = "secret"
	if err := f.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := f.Load(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("round trip: %+v %v", got, err)
	}
	if st, _ := os.Stat(f.Path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("the file holds a password; mode %v", st.Mode().Perm())
	}
}

// fakeSecret serves one Secret, or none, the way the API server does.
type fakeSecret struct {
	mu      sync.Mutex
	exists  bool
	data    map[string]string
	patches []string
}

func (f *fakeSecret) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/api/v1/namespaces/tools/secrets/kartal-server-settings" || !f.exists {
		http.Error(w, `{"kind":"Status","reason":"NotFound","message":"not found"}`, http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"data": f.data})
	case http.MethodPatch:
		b, _ := io.ReadAll(r.Body)
		f.patches = append(f.patches, r.Header.Get("Content-Type")+" "+string(b))
		var p struct{ Data map[string]string }
		json.Unmarshal(b, &p)
		for k, v := range p.Data {
			f.data[k] = v
		}
		w.Write([]byte("{}"))
	}
}

func TestSecretStore(t *testing.T) {
	fake := &fakeSecret{exists: true, data: map[string]string{"other": "a2VlcA=="}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s := Secret{Kube: kube.New(srv.URL, "", false), Namespace: "tools", Name: "kartal-server-settings"}
	ctx := context.Background()
	if got, err := s.Load(ctx); err != nil || !reflect.DeepEqual(got, Settings{}) {
		t.Fatalf("nothing saved yet: %+v %v", got, err)
	}
	want := Settings{Email: valid()}
	if err := s.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	if len(fake.patches) != 1 || !strings.HasPrefix(fake.patches[0], "application/merge-patch+json ") {
		t.Fatalf("patches: %q", fake.patches)
	}
	if fake.data["other"] != "a2VlcA==" {
		t.Error("other keys of the Secret must be left alone")
	}
	raw, _ := base64.StdEncoding.DecodeString(fake.data["settings.json"])
	if !strings.Contains(string(raw), "smtp.example.org:587") {
		t.Errorf("saved: %s", raw)
	}
	if got, err := s.Load(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("round trip: %+v %v", got, err)
	}
	fake.exists = false
	if _, err := s.Load(ctx); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing Secret: %v", err)
	}
	if err := s.Save(ctx, want); err == nil || !strings.Contains(err.Error(), "settings-secret.yaml") {
		t.Errorf("saving without the Secret: %v", err)
	}
}

type failingStore struct{ Memory }

func (failingStore) Save(context.Context, Settings) error { return errors.New("disk full") }

func TestMailFromTheEnvironmentIsFixed(t *testing.T) {
	ch := alert.NewSwitchable("email")
	env := valid()
	m := NewMail(NewKeeper(context.Background(), Memory{}, nil), ch, &env)
	if !ch.Enabled() || !m.View().Fixed {
		t.Fatalf("channel on=%v view=%+v", ch.Enabled(), m.View())
	}
	if _, err := m.Update(context.Background(), Change{Enabled: false}); !errors.Is(err, ErrFixed) {
		t.Errorf("changed settings from the environment: %v", err)
	}
}

func TestMailUpdate(t *testing.T) {
	ch := alert.NewSwitchable("email")
	m := NewMail(NewKeeper(context.Background(), Memory{}, nil), ch, nil)
	if ch.Enabled() {
		t.Fatal("nothing set, yet the channel is on")
	}
	secret := "s3cret"
	c := Change{Enabled: true, Addr: "smtp.example.org:587", From: "kartal@example.org", To: []string{"a@example.org, b@example.org"},
		Username: "kartal", Password: &secret}
	v, err := m.Update(context.Background(), c)
	if err != nil || !ch.Enabled() || !v.PasswordSet || len(v.To) != 2 {
		t.Fatalf("update: %+v %v (on=%v)", v, err, ch.Enabled())
	}
	b, _ := json.Marshal(m.View())
	if strings.Contains(string(b), secret) {
		t.Errorf("the view shows the password: %s", b)
	}
	// Without a password in the change, the saved one stays; "" removes it.
	c.Password = nil
	if v, _ := m.Update(context.Background(), c); !v.PasswordSet || m.keeper.Get().Email.Password != secret {
		t.Error("the saved password was lost")
	}
	empty := ""
	c.Password = &empty
	if v, _ := m.Update(context.Background(), c); v.PasswordSet {
		t.Error("the password was not removed")
	}
	// Turning it off keeps the values but stops the channel.
	c.Enabled = false
	if v, err := m.Update(context.Background(), c); err != nil || ch.Enabled() || v.Addr != "smtp.example.org:587" {
		t.Errorf("off: %+v %v", v, err)
	}
	// A bad change, or one that cannot be saved, changes nothing.
	var invalid *InvalidError
	if _, err := m.Update(context.Background(), Change{Enabled: true, Addr: "x"}); !errors.As(err, &invalid) {
		t.Errorf("bad change: %v", err)
	}
	m.keeper.store = failingStore{}
	c.Enabled = true
	if _, err := m.Update(context.Background(), c); err == nil || ch.Enabled() {
		t.Errorf("an unsaved change was applied: %v (on=%v)", err, ch.Enabled())
	}
}

func TestKeeperKeepsEveryPart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	k := NewKeeper(context.Background(), File{Path: path}, nil)
	m := NewMail(k, alert.NewSwitchable("email"), nil)
	if _, err := m.Update(context.Background(), Change{Enabled: true, Addr: "smtp.example.org:25", From: "k@example.org", To: []string{"o@example.org"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Update(context.Background(), func(s *Settings) error {
		s.Checks = append(s.Checks, Check{ID: "1", Name: "web", URL: "https://example.org", Interval: 60, Timeout: 10})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A failed change leaves everything as it was.
	if _, err := k.Update(context.Background(), func(s *Settings) error {
		s.Checks[0].Name = "changed"
		return errors.New("no")
	}); err == nil || k.Get().Checks[0].Name != "web" {
		t.Errorf("a failed change stuck: %v %+v", err, k.Get().Checks)
	}
	again := NewKeeper(context.Background(), File{Path: path}, nil).Get()
	if again.Email.Addr != "smtp.example.org:25" || len(again.Checks) != 1 {
		t.Errorf("after a restart: %+v", again)
	}
}

func TestCheckNormalize(t *testing.T) {
	c := Check{URL: " https://example.org/health "}
	if err := c.Normalize(); err != nil || c.Name != "https://example.org/health" || c.Interval != 60 || c.Timeout != 10 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, bad := range []Check{
		{URL: "ftp://example.org"},
		{URL: "  "},
		{URL: "https://"},
		{URL: "https://user:pass@example.org"},
		{URL: "https://example.org", Interval: 10},
		{URL: "https://example.org", Interval: 30, Timeout: 30},
		{URL: "https://example.org", Status: 42},
		{URL: "https://example.org", Name: "two\nlines"},
		{URL: "https://example.org", Contains: strings.Repeat("x", 201)},
	} {
		if err := bad.Normalize(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestCheckWithoutScheme(t *testing.T) {
	c := Check{URL: "portal.example.org:8443/healthz"}
	if err := c.Normalize(); err != nil || c.URL != "https://portal.example.org:8443/healthz" {
		t.Errorf("%+v %v", c, err)
	}
}

// flakyStore cannot be read until it is fixed, and keeps what is saved.
type flakyStore struct {
	mu     sync.Mutex
	broken bool
	saved  Settings
}

func (f *flakyStore) Load(context.Context) (Settings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.broken {
		return Settings{}, errors.New("the API server is away")
	}
	return f.saved, nil
}

func (f *flakyStore) Save(_ context.Context, s Settings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = s
	return nil
}

func (f *flakyStore) Where() string { return "flaky" }

func (f *flakyStore) fix() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.broken = false
}

func TestSettingsReadLate(t *testing.T) {
	store := &flakyStore{broken: true, saved: Settings{Email: valid()}}
	k := NewKeeper(context.Background(), store, nil)
	ch := alert.NewSwitchable("email")
	m := NewMail(k, ch, nil)
	if ch.Enabled() || k.LoadError() == "" {
		t.Fatal("nothing could be read, yet e-mail is on")
	}
	// Saving now would replace the e-mail settings that could not be read.
	if _, err := k.Update(context.Background(), func(s *Settings) error {
		s.Checks = append(s.Checks, Check{ID: "1"})
		return nil
	}); err == nil || store.saved.Email.Addr == "" {
		t.Fatalf("saved over unread settings: %v %+v", err, store.saved)
	}
	loaded := make(chan bool, 1)
	k.OnLoad(m.Reload)
	k.OnLoad(func() { loaded <- true })
	store.fix()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go k.Retry(ctx, 10*time.Millisecond)
	select {
	case <-loaded:
	case <-time.After(5 * time.Second):
		t.Fatal("the settings were not read again")
	}
	if !ch.Enabled() || k.LoadError() != "" || k.Get().Email.Addr != valid().Addr {
		t.Errorf("after reading late: on=%v error=%q", ch.Enabled(), k.LoadError())
	}
}
