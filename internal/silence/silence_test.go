package silence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

func TestSilences(t *testing.T) {
	ctx := context.Background()
	keeper := settings.NewKeeper(ctx, settings.Memory{}, nil)
	m := New(keeper)
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }

	// No start: it starts now; a start in the past is now too.
	s, err := m.Add(ctx, settings.Silence{Cluster: "prod", Namespace: "shop", Ends: now.Add(time.Hour), Comment: " deploy "}, "ayse")
	if err != nil || s.ID == "" || s.By != "ayse" || !s.Starts.Equal(now) || s.Comment != "deploy" {
		t.Fatalf("add: %+v %v", s, err)
	}
	if _, err := m.Add(ctx, settings.Silence{Ends: now.Add(-time.Minute)}, "ayse"); err == nil {
		t.Error("a silence over already was saved")
	}
	ahead, _ := m.Add(ctx, settings.Silence{Cluster: "prod", Starts: now.Add(24 * time.Hour), Ends: now.Add(26 * time.Hour)}, "ali")

	if !m.Covers("prod", "PodFailing", "shop", "web-1", now) || m.Covers("prod", "PodFailing", "other", "web-1", now) {
		t.Error("covers now")
	}
	if !m.Covers("prod", "NodeNotReady", "", "n1", now.Add(25*time.Hour)) || m.Covers("prod", "NodeNotReady", "", "n1", now) {
		t.Error("a maintenance window ahead covers only its time")
	}
	if list := m.List(nil); len(list) != 2 || list[0].ID != s.ID {
		t.Errorf("list, soonest to end first: %+v", list)
	}
	// Kept with the settings, read again after a restart.
	again := New(keeper)
	again.Now = m.Now
	if len(again.List(nil)) != 2 {
		t.Error("not kept")
	}

	// One that is over is no longer listed, and dropped at the next save.
	now = now.Add(2 * time.Hour)
	if list := m.List(nil); len(list) != 1 || list[0].ID != ahead.ID {
		t.Errorf("after the first ended: %+v", list)
	}
	if _, err := m.Remove(ctx, s.ID, func(settings.Silence) bool { return true }); !errors.Is(err, ErrNotFound) {
		t.Errorf("ending one over already: %v", err)
	}
	if _, err := m.Remove(ctx, ahead.ID, func(settings.Silence) bool { return false }); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("ending one not allowed: %v", err)
	}
	gone, err := m.Remove(ctx, ahead.ID, func(settings.Silence) bool { return true })
	if err != nil || gone.By != "ali" || len(m.List(nil)) != 0 || len(keeper.Get().Silences) != 0 {
		t.Errorf("remove: %+v %v, kept %+v", gone, err, keeper.Get().Silences)
	}
}
