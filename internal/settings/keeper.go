package settings

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// Keeper holds the saved settings for every part of the server that changes
// them (e-mail, URL checks), so that one part's save never undoes another's.
type Keeper struct {
	store Store

	mu        sync.Mutex
	all       Settings
	loadError string
	onLoad    []func()
}

// NewKeeper loads what the store has. When that fails, the server still
// starts, with nothing set, and the error is shown in the UI; Retry and
// the next Update read them again.
func NewKeeper(ctx context.Context, store Store, log *slog.Logger) *Keeper {
	k := &Keeper{store: store}
	if err := k.load(ctx); err != nil && log != nil {
		log.Error("the saved settings could not be read", "store", store.Where(), "err", err)
	}
	return k
}

// load reads the settings, with mu held or before anyone else can see k.
func (k *Keeper) load(ctx context.Context) error {
	all, err := k.store.Load(ctx)
	if err != nil {
		k.loadError = err.Error()
		return err
	}
	k.all, k.loadError = all, ""
	return nil
}

// OnLoad adds what to do when settings that could not be read at first
// are read after all, such as turning the e-mail channel on.
func (k *Keeper) OnLoad(f func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onLoad = append(k.onLoad, f)
}

func (k *Keeper) loaded() {
	k.mu.Lock()
	fs := slices.Clone(k.onLoad)
	k.mu.Unlock()
	for _, f := range fs {
		f()
	}
}

// Retry reads settings that could not be read again, every so often, until
// that works or ctx ends.
func (k *Keeper) Retry(ctx context.Context, every time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		k.mu.Lock()
		if k.loadError == "" {
			k.mu.Unlock()
			return
		}
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := k.load(lctx)
		cancel()
		k.mu.Unlock()
		if err == nil {
			k.loaded()
			return
		}
	}
}

// Get returns a copy of the settings.
func (k *Keeper) Get() Settings {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.all.clone()
}

// Update applies change to a copy of the settings and saves it. Nothing
// changes when change fails or the save does. Settings that could not be
// read are read again first: saving without them would replace them.
func (k *Keeper) Update(ctx context.Context, change func(*Settings) error) (Settings, error) {
	recovered := false
	defer func() {
		// After the lock is let go: what is done on loading reads them.
		if recovered {
			k.loaded()
		}
	}()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.loadError != "" {
		if err := k.load(ctx); err != nil {
			return Settings{}, fmt.Errorf("the saved settings still cannot be read, and saving now would replace them: %w", err)
		}
		recovered = true
	}
	next := k.all.clone()
	if err := change(&next); err != nil {
		return Settings{}, err
	}
	if err := k.store.Save(ctx, next); err != nil {
		return Settings{}, err
	}
	k.all = next
	return next.clone(), nil
}

// Where names the store; empty means changes last until a restart.
func (k *Keeper) Where() string { return k.store.Where() }

// LoadError is why the saved settings could not be read, if they could not.
func (k *Keeper) LoadError() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.loadError
}

func (s Settings) clone() Settings {
	s.Email.To = slices.Clone(s.Email.To)
	s.Checks = slices.Clone(s.Checks)
	s.Watches = slices.Clone(s.Watches)
	for i, w := range s.Watches {
		s.Watches[i] = w.clone()
	}
	s.Collect.Targets = slices.Clone(s.Collect.Targets)
	s.DataSources = slices.Clone(s.DataSources)
	s.Dashboards = slices.Clone(s.Dashboards)
	for i, d := range s.Dashboards {
		s.Dashboards[i].Variables = slices.Clone(d.Variables)
		s.Dashboards[i].Panels = slices.Clone(d.Panels)
	}
	return s
}
