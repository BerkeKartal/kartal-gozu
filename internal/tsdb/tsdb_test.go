package tsdb

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func same(a, b float64) bool {
	return a == b || (math.IsNaN(a) && math.IsNaN(b))
}

func TestChunkRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	cases := map[string]func(i int) (int64, float64){
		"steady counter": func(i int) (int64, float64) { return 1_700_000_000_000 + int64(i)*30_000, float64(i * 7) },
		"jittery gauge": func(i int) (int64, float64) {
			return 1_700_000_000_000 + int64(i)*30_000 + r.Int63n(2000) - 1000, r.Float64() * 100
		},
		"constant": func(i int) (int64, float64) { return int64(i) * 15_000, 42 },
		"special values": func(i int) (int64, float64) {
			return int64(i) * 1000, []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, -0.5}[i%5]
		},
		"big gaps":         func(i int) (int64, float64) { return int64(i*i) * 3_600_000, float64(i) * 1e300 },
		"ragged intervals": func(i int) (int64, float64) { return int64(i)*10_000 + int64(i%3)*70_000, float64(-i) },
	}
	for name, gen := range cases {
		var e encoder
		var want []Point
		last := int64(math.MinInt64)
		for i := 0; i < maxChunkSamples; i++ {
			ts, v := gen(i)
			if ts <= last {
				ts = last + 1
			}
			last = ts
			e.add(ts, v)
			want = append(want, Point{ts, v})
		}
		got, err := decode(e.bytes(), e.n, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %d points, want %d", name, len(got), len(want))
		}
		for i := range want {
			if got[i].T != want[i].T || !same(got[i].V, want[i].V) {
				t.Fatalf("%s: point %d = %v, want %v", name, i, got[i], want[i])
			}
		}
	}
	// A counter that grows every sample takes a few bytes per sample, not 16.
	var e encoder
	for i := 0; i < maxChunkSamples; i++ {
		e.add(int64(i)*30_000, float64(i*7))
	}
	if n := len(e.bytes()); n > 4*maxChunkSamples+16 {
		t.Errorf("steady counter takes %d bytes for %d samples", n, maxChunkSamples)
	}
}

func day(d int, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }

func samples(v float64, pods ...string) []Sample {
	var out []Sample
	for _, p := range pods {
		out = append(out, Sample{Labels: FromMap("http_requests_total", map[string]string{"pod": p, "code": "200"}), Type: "counter", Value: v})
	}
	return out
}

func mustMatch(t *testing.T, mt MatchType, name, value string) *Matcher {
	t.Helper()
	m, err := NewMatcher(mt, name, value)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func values(s Series) []float64 {
	out := make([]float64, len(s.Points))
	for i, p := range s.Points {
		out[i] = p.V
	}
	return out
}

func TestAppendSelectAcrossDaysAndRestart(t *testing.T) {
	dir := t.TempDir()
	db, err := openAt(dir, day(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Three days, every hour, two pods; more samples than one chunk holds.
	n := 0
	for d := 1; d <= 3; d++ {
		for h := 0; h < 24; h++ {
			for m := 0; m < 60; m += 5 {
				at := day(d, h).Add(time.Duration(m) * time.Minute)
				if err := db.Append(at, samples(float64(n), "web-1", "web-2")); err != nil {
					t.Fatal(err)
				}
				n++
			}
		}
	}
	// The same moment again is ignored, an older one too.
	db.Append(day(3, 23).Add(55*time.Minute), samples(-1, "web-1"))
	db.Append(day(3, 1), samples(-1, "web-1"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = openAt(dir, day(3, 23))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sel, err := db.Select(day(1, 0).UnixMilli(), day(4, 0).UnixMilli(), Match(mustMatch(t, MatchEqual, "pod", "web-1")))
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 1 || len(sel[0].Points) != n || sel[0].Type != "counter" {
		t.Fatalf("got %d series, %d points; want 1 series of %d", len(sel), len(sel[0].Points), n)
	}
	for i, v := range values(sel[0]) {
		if v != float64(i) {
			t.Fatalf("point %d = %v", i, v)
		}
	}
	// A window inside the second day.
	sel, _ = db.Select(day(2, 10).UnixMilli(), day(2, 11).UnixMilli(), Match(mustMatch(t, MatchRegexp, "pod", "web-.*")))
	if len(sel) != 2 || len(sel[0].Points) != 13 {
		t.Fatalf("window: %d series, %d points", len(sel), len(sel[0].Points))
	}
	names, _ := db.Metrics(day(1, 0).UnixMilli(), day(4, 0).UnixMilli(), Selector{})
	if !reflect.DeepEqual(names, []MetricInfo{{Name: "http_requests_total", Type: "counter", Series: 2}}) {
		t.Errorf("metrics: %+v", names)
	}
	pods, _ := db.LabelValues("pod", day(2, 0).UnixMilli(), day(2, 1).UnixMilli(), Selector{})
	if !reflect.DeepEqual(pods, []string{"web-1", "web-2"}) {
		t.Errorf("pods: %v", pods)
	}
	// Keep hides series, as from a user who may not see them.
	notWeb2 := Selector{Keep: func(ls Labels) bool { return ls.Get("pod") != "web-2" }}
	pods, _ = db.LabelValues("pod", day(2, 0).UnixMilli(), day(2, 1).UnixMilli(), notWeb2)
	names, _ = db.Metrics(day(1, 0).UnixMilli(), day(4, 0).UnixMilli(), notWeb2)
	if !reflect.DeepEqual(pods, []string{"web-1"}) || names[0].Series != 1 {
		t.Errorf("kept: pods %v, metrics %+v", pods, names)
	}
	if ln, _ := db.LabelNames(day(2, 0).UnixMilli(), day(2, 1).UnixMilli(), Selector{}); !reflect.DeepEqual(ln, []string{"code", "pod"}) {
		t.Errorf("label names: %v", ln)
	}
	if days := db.Days(); len(days) != 3 || days[0].Day != "2026-10-01" || days[0].Bytes == 0 {
		t.Errorf("days: %+v", days)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	db, err := openAt(dir, day(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for d := 1; d <= 4; d++ {
		for h := 0; h < 24; h++ {
			db.Append(day(d, h), samples(float64(d*100+h), "a"))
		}
	}
	all := func() []float64 {
		sel, err := db.Select(0, farFuture, Selector{})
		if err != nil {
			t.Fatal(err)
		}
		if len(sel) == 0 {
			return nil
		}
		return values(sel[0])
	}
	// The second day from noon to the end of the third: day 3 goes whole,
	// day 2 is rewritten.
	res, err := db.Delete(day(2, 12).UnixMilli(), day(4, 0).UnixMilli()-1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Removed, []string{"2026-10-03"}) || !reflect.DeepEqual(res.Rewritten, []string{"2026-10-02"}) || res.Freed <= 0 {
		t.Errorf("result: %+v", res)
	}
	got := all()
	if len(got) != 24+12+24 || got[24+11] != 211 || got[24+12] != 400 {
		t.Fatalf("after delete: %d points %v", len(got), got)
	}
	// Today (the head) can be cut too, and still takes samples afterwards.
	if _, err := db.Delete(day(4, 0).UnixMilli(), day(4, 5).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := db.Append(day(4, 23).Add(30*time.Minute), samples(999, "a")); err != nil {
		t.Fatal(err)
	}
	got = all()
	if got[len(got)-1] != 999 || got[24+12] != 406 {
		t.Fatalf("after cutting today: %v", got[24+12:])
	}
	// Everything.
	if _, err := db.Delete(0, farFuture); err != nil {
		t.Fatal(err)
	}
	if got := all(); len(got) != 0 {
		t.Fatalf("after deleting all: %v", got)
	}
	if err := db.Append(day(4, 23).Add(40*time.Minute), samples(1, "a")); err != nil {
		t.Fatal(err)
	}
	if got := all(); len(got) != 1 {
		t.Fatalf("today after deleting all: %v", got)
	}
}

func TestCrashLeftovers(t *testing.T) {
	dir := t.TempDir()
	db, _ := openAt(dir, day(5, 0))
	for h := 0; h < 10; h++ {
		db.Append(day(5, h), samples(float64(h), "a"))
	}
	db.Close()
	d := filepath.Join(dir, "2026-10-05")
	// A crash mid-write: half a record and half a series line.
	f, _ := os.OpenFile(filepath.Join(d, chunksFile), os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{0x4b, 0x47, 1, 2, 3})
	f.Close()
	f, _ = os.OpenFile(filepath.Join(d, seriesFile), os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("1\tgauge\t[[\"__name"))
	f.Close()
	// And an interrupted rewrite of another day.
	os.MkdirAll(filepath.Join(dir, "2026-10-04.tmp"), 0o755)

	db, err := openAt(dir, day(5, 12))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Append(day(5, 12), append(samples(12, "a"), samples(5, "b")...)); err != nil {
		t.Fatal(err)
	}
	sel, err := db.Select(0, farFuture, Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 2 || len(sel[0].Points) != 11 || sel[1].Labels.Get("pod") != "b" {
		t.Fatalf("after crash: %+v", sel)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-10-04.tmp")); !os.IsNotExist(err) {
		t.Error("leftover .tmp kept")
	}
}

func TestMatchers(t *testing.T) {
	ls := FromMap("up", map[string]string{"pod": "web-1"})
	for _, c := range []struct {
		t    MatchType
		n, v string
		want bool
	}{
		{MatchEqual, "pod", "web-1", true},
		{MatchNotEqual, "pod", "web-1", false},
		{MatchRegexp, "pod", "web-.", true},
		{MatchRegexp, "pod", "web", false}, // anchored
		{MatchNotRegexp, "pod", "api-.*", true},
		{MatchEqual, "missing", "", true},
		{MatchNotEqual, "missing", "x", true},
	} {
		m := mustMatch(t, c.t, c.n, c.v)
		if got := matchAll(ls, []*Matcher{m}); got != c.want {
			t.Errorf("%s%s%q = %v", c.n, c.t, c.v, got)
		}
	}
	if _, err := NewMatcher(MatchRegexp, "pod", "("); err == nil {
		t.Error("a bad regexp was accepted")
	}
	if got := ls.String(); got != `up{pod="web-1"}` {
		t.Errorf("String() = %s", got)
	}
}

func TestEachAcrossDays(t *testing.T) {
	dir := t.TempDir()
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }
	db, err := openAt(dir, day(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for d := 1; d <= 3; d++ {
		for h := 0; h < 24; h += 6 {
			s := []Sample{
				{Labels: FromMap("m", map[string]string{"pod": "b"}), Value: float64(d*100 + h)},
				{Labels: FromMap("m", map[string]string{"pod": "a"}), Value: float64(d*100 + h)},
			}
			if err := db.Append(day(d, h), s); err != nil {
				t.Fatal(err)
			}
		}
	}
	var pods []string
	var counts []int
	err = db.Each(day(1, 12).UnixMilli(), day(3, 6).UnixMilli(), Selector{}, func(s Series) error {
		pods = append(pods, s.Labels.Get("pod"))
		counts = append(counts, len(s.Points))
		for i := 1; i < len(s.Points); i++ {
			if s.Points[i].T <= s.Points[i-1].T {
				t.Errorf("points out of order: %v", s.Points)
			}
		}
		return nil
	})
	// From day 1 12:00 to day 3 06:00: 2 + 4 + 2 samples each.
	if err != nil || !reflect.DeepEqual(pods, []string{"a", "b"}) || !reflect.DeepEqual(counts, []int{8, 8}) {
		t.Errorf("each: %v %v %v", err, pods, counts)
	}
}

func TestDaySeriesLimit(t *testing.T) {
	daySeries = 3
	defer func() { daySeries = MaxDaySeries }()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var s []Sample
	for i := 0; i < 5; i++ {
		s = append(s, Sample{Labels: FromMap("m", map[string]string{"i": string(rune('a' + i))}), Value: 1})
	}
	now := time.Now()
	if err := db.Append(now, s); !errors.Is(err, ErrDaySeries) {
		t.Errorf("five series past a limit of three: %v", err)
	}
	// The series already there still take samples.
	if err := db.Append(now.Add(time.Second), s[:3]); err != nil {
		t.Errorf("known series: %v", err)
	}
	if n := db.HeadSeries(); n != 3 {
		t.Errorf("%d series stored, want 3", n)
	}
}

func TestLongLabelsAndOddTypes(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("<", MaxLabelBytes)
	now := time.Now()
	err = db.Append(now, []Sample{
		{Labels: FromMap("m", map[string]string{"v": long}), Value: 1},
		{Labels: FromMap("m", map[string]string{"v": "short"}), Type: "gauge\nbroken\tline", Value: 2},
	})
	if !errors.Is(err, ErrLabelsTooLong) {
		t.Errorf("labels of %d bytes: %v", len(long), err)
	}
	db.Close()
	// The store opens again, with the series that fit, and a type that
	// cannot break its line.
	db, err = Open(dir)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer db.Close()
	got, err := db.Select(0, now.Add(time.Hour).UnixMilli(), Selector{})
	if err != nil || len(got) != 1 || got[0].Labels.Get("v") != "short" || got[0].Type != "untyped" {
		t.Errorf("after reopening: %+v %v", got, err)
	}
}

// A day that is over gets an index; one that does not fit any more, or is
// damaged, is made again from the chunks.
func TestIndexOfClosedDays(t *testing.T) {
	dir := t.TempDir()
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }
	db, err := openAt(dir, day(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	for d := 1; d <= 2; d++ {
		for m := 0; m < 400; m++ { // more than one chunk a series
			at := day(d, 0).Add(time.Duration(m) * time.Minute)
			if err := db.Append(at, []Sample{{Labels: FromMap("m", map[string]string{"pod": "a"}), Value: float64(m)}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	db.Close()
	index := filepath.Join(dir, "2026-10-01", indexFile)
	if _, err := os.Stat(index); err != nil {
		t.Fatalf("the first day has no index: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-10-02", indexFile)); err == nil {
		t.Error("today has an index")
	}
	count := func() int {
		db, err := openAt(dir, day(2, 12))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		got, err := db.Select(day(1, 0).UnixMilli(), day(3, 0).UnixMilli(), Selector{})
		if err != nil || len(got) != 1 {
			t.Fatalf("select: %v %v", got, err)
		}
		return len(got[0].Points)
	}
	if n := count(); n != 800 {
		t.Errorf("%d points through the index, want 800", n)
	}
	b, _ := os.ReadFile(index)
	b[indexHeader+3] ^= 0xff // an offset
	os.WriteFile(index, b, 0o644)
	if n := count(); n != 800 {
		t.Errorf("%d points after the index was damaged, want 800", n)
	}
	if fixed, _ := os.ReadFile(index); bytes.Equal(fixed, b) {
		t.Error("the damaged index was not made again")
	}
}
