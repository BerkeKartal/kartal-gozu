package query

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// fakeDB answers from series held in memory.
type fakeDB []tsdb.Series

func (f fakeDB) Each(from, to int64, sel tsdb.Selector, fn func(tsdb.Series) error) error {
	got, _ := f.selectSeries(from, to, sel)
	sort.Slice(got, func(i, j int) bool { return got[i].Labels.String() < got[j].Labels.String() })
	for _, s := range got {
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}

func (f fakeDB) selectSeries(from, to int64, sel tsdb.Selector) ([]tsdb.Series, error) {
	var out []tsdb.Series
	for _, s := range f {
		ok := true
		for _, m := range sel.Matchers {
			if !m.Matches(s.Labels.Get(m.Name)) {
				ok = false
			}
		}
		if !ok || (sel.Keep != nil && !sel.Keep(s.Labels)) {
			continue
		}
		var pts []tsdb.Point
		for _, p := range s.Points {
			if p.T >= from && p.T <= to {
				pts = append(pts, p)
			}
		}
		if len(pts) > 0 {
			out = append(out, tsdb.Series{Labels: s.Labels, Type: s.Type, Points: pts})
		}
	}
	return out, nil
}

const sec = int64(1000)

// series makes a series sampled every 15 seconds from 0 to last seconds.
func series(name string, labels map[string]string, last int64, v func(k int64) float64) tsdb.Series {
	s := tsdb.Series{Labels: tsdb.FromMap(name, labels)}
	for k := int64(0); k*15 <= last; k++ {
		s.Points = append(s.Points, tsdb.Point{T: k * 15 * sec, V: v(k)})
	}
	return s
}

func testDB() fakeDB {
	lin := func(a float64) func(int64) float64 { return func(k int64) float64 { return a * float64(k) } }
	flat := func(a float64) func(int64) float64 { return func(int64) float64 { return a } }
	return fakeDB{
		series("http_requests_total", map[string]string{"pod": "a", "code": "200"}, 600, lin(10)),
		series("http_requests_total", map[string]string{"pod": "b", "code": "200"}, 600, lin(5)),
		series("http_requests_total", map[string]string{"pod": "a", "code": "500"}, 600, lin(1)),
		series("mem", map[string]string{"pod": "a"}, 600, flat(100)),
		series("mem", map[string]string{"pod": "b"}, 600, flat(300)),
		series("lat_bucket", map[string]string{"pod": "a", "le": "0.1"}, 600, lin(50)),
		series("lat_bucket", map[string]string{"pod": "a", "le": "0.5"}, 600, lin(90)),
		series("lat_bucket", map[string]string{"pod": "a", "le": "+Inf"}, 600, lin(100)),
		series("gone", map[string]string{"pod": "a"}, 300, flat(1)),
		// A counter that restarts from zero at 300 seconds.
		series("restarts_total", map[string]string{"pod": "a"}, 600, func(k int64) float64 {
			if k*15 < 300 {
				return 1000 + 10*float64(k)
			}
			return 10 * float64(k-20)
		}),
	}
}

// at evaluates q at one moment and returns the values by their labels.
func at(t *testing.T, q string, ms int64) map[string]float64 {
	t.Helper()
	res, err := NewEngine(testDB()).Range(context.Background(), q, ms, ms, 1, nil)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	out := map[string]float64{}
	for _, s := range res.Series {
		out[labelText(s.Labels)] = s.Values.V[0]
	}
	return out
}

func labelText(m map[string]string) string {
	k := labelKey(m)
	return strings.ReplaceAll(k, "\xff", ",")
}

func near(a, b float64) bool {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.IsNaN(a) && math.IsNaN(b)
	}
	return math.Abs(a-b) < 1e-9*math.Max(1, math.Abs(b))
}

func TestQueries(t *testing.T) {
	const now = 600 * sec
	for _, c := range []struct {
		q    string
		want map[string]float64
	}{
		{`rate(http_requests_total{pod="a",code="200"}[1m])`, map[string]float64{",code,200,pod,a": 10.0 / 15}},
		{`increase(http_requests_total{pod="a",code="200"}[1m])`, map[string]float64{",code,200,pod,a": 40}},
		{`irate(http_requests_total{pod="b",code="200"}[1m])`, map[string]float64{",code,200,pod,b": 5.0 / 15}},
		{`deriv(http_requests_total{pod="a",code="200"}[2m])`, map[string]float64{",code,200,pod,a": 10.0 / 15}},
		{`sum by (code) (rate(http_requests_total[1m]))`, map[string]float64{",code,200": 15.0 / 15, ",code,500": 1.0 / 15}},
		{`sum(rate(http_requests_total[1m])) by (code)`, map[string]float64{",code,200": 15.0 / 15, ",code,500": 1.0 / 15}},
		{`sum without (pod) (rate(http_requests_total[1m]))`, map[string]float64{",code,200": 15.0 / 15, ",code,500": 1.0 / 15}},
		{`sum(mem)`, map[string]float64{"": 400}},
		{`avg(mem)`, map[string]float64{"": 200}},
		{`max(mem)`, map[string]float64{"": 300}},
		{`count(mem)`, map[string]float64{"": 2}},
		{`quantile(0.5, mem)`, map[string]float64{"": 200}},
		{`stddev(mem)`, map[string]float64{"": 100}},
		{`topk(1, mem)`, map[string]float64{"mem,pod,b": 300}},
		{`bottomk(1, mem)`, map[string]float64{"mem,pod,a": 100}},
		{`mem * 2`, map[string]float64{",pod,a": 200, ",pod,b": 600}},
		{`2 * mem`, map[string]float64{",pod,a": 200, ",pod,b": 600}},
		{`mem > 150`, map[string]float64{"mem,pod,b": 300}},
		{`150 < mem`, map[string]float64{"mem,pod,b": 300}},
		{`mem > bool 150`, map[string]float64{",pod,a": 0, ",pod,b": 1}},
		{`mem - mem`, map[string]float64{",pod,a": 0, ",pod,b": 0}},
		{`mem / on (pod) group_left mem`, map[string]float64{",pod,a": 1, ",pod,b": 1}},
		{`rate(http_requests_total{code="200"}[1m]) / ignoring (code) group_left mem`,
			map[string]float64{",code,200,pod,a": 10.0 / 15 / 100, ",code,200,pod,b": 5.0 / 15 / 300}},
		{`mem / on (pod) group_right sum by (pod) (rate(http_requests_total[1m]))`, nil}, // checked below
		{`mem and on (pod) http_requests_total{code="500"}`, map[string]float64{"mem,pod,a": 100}},
		{`mem unless on (pod) http_requests_total{code="500"}`, map[string]float64{"mem,pod,b": 300}},
		{`mem{pod="a"} or mem`, map[string]float64{"mem,pod,a": 100, "mem,pod,b": 300}},
		{`histogram_quantile(0.5, rate(lat_bucket[1m]))`, map[string]float64{",pod,a": 0.1}},
		{`histogram_quantile(0.9, sum by (le) (rate(lat_bucket[1m])))`, map[string]float64{"": 0.5}},
		{`histogram_quantile(0.95, rate(lat_bucket[1m]))`, map[string]float64{",pod,a": 0.5}},
		{`absent(nope{job="x"})`, map[string]float64{",job,x": 1}},
		{`absent(mem)`, map[string]float64{}},
		{`label_replace(mem{pod="a"}, "host", "node-$1", "pod", "(.*)")`, map[string]float64{"mem,host,node-a,pod,a": 100}},
		{`label_join(mem{pod="a"}, "x", "-", "pod", "pod")`, map[string]float64{"mem,pod,a,x,a-a": 100}},
		{`1 + 2 * 3`, map[string]float64{"": 7}},
		{`2 ^ 3 ^ 2`, map[string]float64{"": 512}},
		{`-2 ^ 2`, map[string]float64{"": -4}},
		{`(1 + 2) * 3`, map[string]float64{"": 9}},
		{`10 % 4`, map[string]float64{"": 2}},
		{`2 > bool 1`, map[string]float64{"": 1}},
		{`time()`, map[string]float64{"": 600}},
		{`vector(3)`, map[string]float64{"": 3}},
		{`scalar(mem{pod="b"}) + 1`, map[string]float64{"": 301}},
		{`clamp_max(mem, 200)`, map[string]float64{",pod,a": 100, ",pod,b": 200}},
		{`round(rate(http_requests_total{pod="a",code="200"}[1m]), 0.1)`, map[string]float64{",code,200,pod,a": 0.7}},
		{`avg_over_time(mem[5m])`, map[string]float64{",pod,a": 100, ",pod,b": 300}},
		{`max_over_time(http_requests_total{pod="a",code="500"}[1m])`, map[string]float64{",code,500,pod,a": 40}},
		{`count_over_time(mem{pod="a"}[1m])`, map[string]float64{",pod,a": 4}},
		{`last_over_time(mem{pod="a"}[1m])`, map[string]float64{"mem,pod,a": 100}},
		{`resets(restarts_total[10m])`, map[string]float64{",pod,a": 1}},
		{`increase(restarts_total[2m])`, map[string]float64{",pod,a": 80}},
		{`gone`, map[string]float64{}}, // its last sample is 5 minutes old
		{`mem offset 1m`, map[string]float64{"mem,pod,a": 100, "mem,pod,b": 300}},
		{`sum by (pod) (http_requests_total offset 5m)`, map[string]float64{",pod,a": 200 + 20, ",pod,b": 100}},
		{`hour()`, map[string]float64{"": 0}},
	} {
		got := at(t, c.q, now)
		if c.want == nil {
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s = %v, want %v", c.q, got, c.want)
			continue
		}
		for k, v := range c.want {
			if g, ok := got[k]; !ok || !near(g, v) {
				t.Errorf("%s = %v, want %v", c.q, got, c.want)
				break
			}
		}
	}
	// group_right keeps the right side's labels.
	got := at(t, `mem / on (pod) group_right sum by (pod) (rate(http_requests_total[1m]))`, now)
	if !near(got[",pod,a"], 100/(11.0/15)) || !near(got[",pod,b"], 300/(5.0/15)) {
		t.Errorf("group_right: %v", got)
	}
	// Just before its last sample turns 5 minutes old, gone is there.
	if got := at(t, `gone`, 599*sec); got["gone,pod,a"] != 1 {
		t.Errorf("gone at 599s: %v", got)
	}
}

func TestRangeAndJSON(t *testing.T) {
	e := NewEngine(testDB())
	res, err := e.Range(context.Background(), `sum by (code) (rate(http_requests_total[1m])) / 0`, 60*sec, 600*sec, 60*sec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) != 2 || len(res.Series[0].Values.V) != 10 || res.End != 600*sec {
		t.Fatalf("result %+v", res)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"+Inf"`) {
		t.Errorf("JSON %s", b)
	}
	// Before the first sample a series is missing, which is null.
	res, _ = e.Range(context.Background(), `rate(mem[1m])`, 0, 60*sec, 30*sec, nil)
	b, _ = json.Marshal(res.Series[0].Values)
	if string(b) != `[null,0,0]` {
		t.Errorf("values %s", b)
	}
}

func TestKeepHidesSeries(t *testing.T) {
	keep := func(ls tsdb.Labels) bool { return ls.Get("pod") != "b" }
	res, err := NewEngine(testDB()).Range(context.Background(), `sum(mem)`, 600*sec, 600*sec, 1, keep)
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Series[0].Values.V[0]; v != 100 {
		t.Errorf("sum without pod b = %v, want 100", v)
	}
}

func TestLimits(t *testing.T) {
	e := NewEngine(testDB())
	e.MaxPoints = 50
	if _, err := e.Range(context.Background(), `mem`, 0, 600*sec, sec, nil); err != ErrTooMuch {
		t.Errorf("too many values: %v", err)
	}
	e = NewEngine(testDB())
	if _, err := e.Range(context.Background(), `mem`, 0, 600*sec*100, 1, nil); err == nil || !strings.Contains(err.Error(), "steps") {
		t.Errorf("too many steps: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, q := range []string{
		`rate(mem)`, `sum(`, `mem[5m]`, `1 > 2`, `{}`, `{pod=~".*"}`, `mem{pod="a"`, `nope(mem)`, `topk(mem)`,
		`mem[5m:1m]`, `mem @ 100`, `rate(mem[5x])`, `sum by (pod) mem`, `mem and 1`, `"x"`, `mem +`, `5m`,
		`label_replace(mem, "1x", "", "pod", "")`, `histogram_quantile(mem, mem)`,
	} {
		if _, err := NewEngine(testDB()).Range(context.Background(), q, 0, 0, 1, nil); err == nil {
			t.Errorf("%s: no error", q)
		}
	}
	for _, q := range []string{
		`sum(rate(http_requests_total{code=~"5.."}[5m])) by (pod) / sum(rate(http_requests_total[5m])) by (pod)`,
		`max without (le) (lat_bucket) # a comment`,
		`http_requests_total{code!="200", pod!~"b|c"}`,
		`{__name__=~"mem|gone"}`,
		`'single' == bool "x"`, // strings parse; the comparison fails later
	} {
		if _, err := Parse(q); err != nil && !strings.Contains(q, "single") {
			t.Errorf("%s: %v", q, err)
		}
	}
}

func TestDurations(t *testing.T) {
	for s, want := range map[string]int64{"5m": 300, "1h30m": 5400, "2d": 172800, "500ms": 0, "1w": 604800} {
		d, err := ParseDuration(s)
		if err != nil || int64(d.Seconds()) != want {
			t.Errorf("%s = %v, %v", s, d, err)
		}
	}
	for _, s := range []string{"300y", "99y2y", "9999999999999999999s", "5"} {
		if d, err := ParseDuration(s); err == nil {
			t.Errorf("%s = %v, want an error", s, d)
		}
	}
}

// A counter that starts within the window is extended half a step before
// its first sample, but not past its zero point, as in Prometheus 3.
func TestIncreaseOfAStartingCounter(t *testing.T) {
	s := tsdb.Series{Labels: tsdb.FromMap("c", nil), Points: []tsdb.Point{{T: 20 * sec, V: 10}, {T: 30 * sec, V: 20}, {T: 40 * sec, V: 30}}}
	res, err := NewEngine(fakeDB{s}).Range(context.Background(), `increase(c[40s])`, 40*sec, 40*sec, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Series[0].Values.V[0]; !near(v, 25) {
		t.Errorf("increase = %v, want 25", v)
	}
}

func TestStringEscapes(t *testing.T) {
	for q, want := range map[string]string{
		`{job="a\xc3\xa7b"}`:   "a\U000000e7b", // UTF-8 bytes make a letter
		`{job="a\U000000e7b"}`: "a\U000000e7b",
		`{job="tab\there"}`:    "tab\there",
		`{job="\x41\101"}`:     "AA",
		`{job=~"a\.b"}`:        `a\.b`, // a regular expression's escape stays
		`{job='it\'s'}`:        "it's",
		"{job=`raw\\n`}":       `raw\n`,
		`{job="say \"hi\""}`:   `say "hi"`,
		`{job="back\\slash"}`:  `back\slash`,
		`{job="\U0001F600"}`:   "\U0001F600",
		`{job="nul\x00end"}`:   "nul\x00end",
		`{job="bad\u12"}`:      `bad\u12`, // not an escape after all
	} {
		vs, err := ParseSelector(q)
		if err != nil {
			t.Errorf("%s: %v", q, err)
			continue
		}
		if got := vs.Matchers[0].Value; got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
		again, err := ParseSelector(vs.String())
		if err != nil || again.Matchers[0].Value != want {
			t.Errorf("%s prints as %s, which reads back as %v %v", q, vs.String(), again, err)
		}
	}
}
