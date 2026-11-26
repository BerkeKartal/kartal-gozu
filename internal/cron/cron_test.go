package cron

import (
	"testing"
	"time"
)

func TestNext(t *testing.T) {
	ist, err := Zone("")
	if err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, ist)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct{ expr, from, want string }{
		{"0 3 * * *", "2026-11-26 02:59", "2026-11-26 03:00"},
		{"0 3 * * *", "2026-11-26 03:00", "2026-11-27 03:00"},
		{"*/15 * * * *", "2026-11-26 10:07", "2026-11-26 10:15"},
		{"30 8-18/2 * * mon-fri", "2026-11-27 19:00", "2026-11-30 08:30"}, // Friday evening: Monday
		{"0 4 * * 0", "2026-11-26 12:00", "2026-11-29 04:00"},             // Sunday
		{"0 4 * * 7", "2026-11-26 12:00", "2026-11-29 04:00"},
		{"0 0 1 * *", "2026-11-26 12:00", "2026-12-01 00:00"},
		{"0 0 29 2 *", "2026-03-01 00:00", "2028-02-29 00:00"},
		{"0 12 1 * mon", "2026-11-26 12:00", "2026-11-30 12:00"}, // either day field
		{"@daily", "2026-12-31 23:59", "2027-01-01 00:00"},
		{"15 10 * jan,jul *", "2026-11-26 12:00", "2027-01-01 10:15"},
		{"0,30 1 * * *", "2026-11-26 01:10", "2026-11-26 01:30"},
	} {
		s, err := Parse(c.expr)
		if err != nil {
			t.Errorf("%s: %v", c.expr, err)
			continue
		}
		if got := s.Next(at(c.from), ist); !got.Equal(at(c.want)) {
			t.Errorf("%s after %s: %s, want %s", c.expr, c.from, got.In(ist).Format("2006-01-02 15:04 Mon"), c.want)
		}
	}
	// In a zone that changes its clocks, the hour skipped is skipped and
	// the hour repeated runs once.
	berlin, _ := time.LoadLocation("Europe/Berlin")
	s, _ := Parse("30 2 * * *")
	from := time.Date(2026, 3, 29, 0, 0, 0, 0, berlin)
	if got := s.Next(from, berlin); got.Day() != 30 || got.Hour() != 2 {
		t.Errorf("over the spring change: %s", got)
	}
	from = time.Date(2026, 10, 25, 2, 31, 0, 0, berlin)
	if got := s.Next(from, berlin); !got.After(from) || got.Day() != 26 {
		t.Errorf("over the autumn change: %s", got)
	}
	if never, _ := Parse("0 0 30 2 *"); !never.Next(at("2026-01-01 00:00"), ist).IsZero() {
		t.Error("30 February came")
	}
}

func TestParseRefuses(t *testing.T) {
	for _, expr := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8",
		"*/0 * * * *", "5-1 * * * *", "a * * * *", "* * * * * *"} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("%q was taken", expr)
		}
	}
}
