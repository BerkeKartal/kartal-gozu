// Package cron reads schedules as cron writes them, five fields: minute,
// hour, day of the month, month and day of the week, in a time zone of
// their own. The time zone database is built in, so a schedule reads the
// same in a container without one.
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	// Containers often have no zoneinfo; the schedules' zone must load.
	_ "time/tzdata"
)

// DefaultZone is the time zone schedules are read in, unless told.
const DefaultZone = "Europe/Istanbul"

// Schedule is a parsed cron expression.
type Schedule struct {
	text                     string
	minute, hour, dom, month uint64
	dow                      uint64
	// domAll and dowAll tell whether the day fields were left open, which
	// decides how they combine: when both are restricted, either matches.
	domAll, dowAll bool
}

// String is the expression as it was written.
func (s Schedule) String() string { return s.text }

var macros = map[string]string{
	"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
	"@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *",
}

var monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
var dayNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// Parse reads "m h dom mon dow", or a macro such as @daily. Fields take *,
// numbers, ranges (1-5), lists (1,15), steps (*/15, 8-18/2), and names
// for months and days (jan, mon); 7 is Sunday too.
func Parse(text string) (Schedule, error) {
	text = strings.TrimSpace(text)
	expr := text
	if m, ok := macros[strings.ToLower(expr)]; ok {
		expr = m
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return Schedule{}, fmt.Errorf("%q: a schedule has five fields, minute hour day month weekday, such as 0 3 * * *", text)
	}
	s := Schedule{text: text}
	var err error
	if s.minute, _, err = field(f[0], 0, 59, nil); err != nil {
		return Schedule{}, fmt.Errorf("%q, the minute: %w", text, err)
	}
	if s.hour, _, err = field(f[1], 0, 23, nil); err != nil {
		return Schedule{}, fmt.Errorf("%q, the hour: %w", text, err)
	}
	if s.dom, s.domAll, err = field(f[2], 1, 31, nil); err != nil {
		return Schedule{}, fmt.Errorf("%q, the day of the month: %w", text, err)
	}
	if s.month, _, err = field(f[3], 1, 12, monthNames); err != nil {
		return Schedule{}, fmt.Errorf("%q, the month: %w", text, err)
	}
	if s.dow, s.dowAll, err = field(f[4], 0, 7, dayNames); err != nil {
		return Schedule{}, fmt.Errorf("%q, the day of the week: %w", text, err)
	}
	if s.dow&(1<<7) != 0 {
		s.dow |= 1
	}
	return s, nil
}

// field reads one field into a set of bits, and tells whether it was *.
func field(text string, lo, hi int, names map[string]int) (uint64, bool, error) {
	var bits uint64
	all := text == "*"
	for _, part := range strings.Split(text, ",") {
		step := 1
		if i := strings.IndexByte(part, '/'); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 {
				return 0, false, fmt.Errorf("%q is not a step", part[i+1:])
			}
			step, part = n, part[:i]
		}
		from, to := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			var err error
			if from, err = value(a, lo, hi, names); err != nil {
				return 0, false, err
			}
			if to, err = value(b, lo, hi, names); err != nil {
				return 0, false, err
			}
			if from > to {
				return 0, false, fmt.Errorf("%q runs backwards", part)
			}
		default:
			v, err := value(part, lo, hi, names)
			if err != nil {
				return 0, false, err
			}
			from, to = v, v
			if step > 1 {
				to = hi
			}
		}
		for v := from; v <= to; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, all, nil
}

func value(text string, lo, hi int, names map[string]int) (int, error) {
	if v, ok := names[strings.ToLower(text)]; ok {
		return v, nil
	}
	v, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", text)
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("%d is not between %d and %d", v, lo, hi)
	}
	return v, nil
}

// Next is the first time after t that the schedule matches, in loc, or the
// zero time when there is none within five years (30 February).
func (s Schedule) Next(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc).Truncate(time.Minute).Add(time.Minute)
	end := t.AddDate(5, 0, 0)
	for t.Before(end) {
		if s.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc)
			continue
		}
		if !s.day(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			next := time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, loc)
			// A day whose clock goes back repeats an hour; never go back.
			if !next.After(t) {
				next = t.Add(time.Hour).Truncate(time.Hour)
			}
			t = next
			continue
		}
		if s.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

func (s Schedule) day(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	if s.domAll || s.dowAll {
		return dom && dow
	}
	return dom || dow
}

// Zone loads a time zone by its name, DefaultZone when empty.
func Zone(name string) (*time.Location, error) {
	if name == "" {
		name = DefaultZone
	}
	return time.LoadLocation(name)
}
