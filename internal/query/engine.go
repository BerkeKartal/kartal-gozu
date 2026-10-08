package query

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// Querier is where the samples come from: the metric store, which hands
// them over one series at a time.
type Querier interface {
	Each(from, to int64, sel tsdb.Selector, f func(tsdb.Series) error) error
}

// Engine evaluates queries.
type Engine struct {
	DB Querier
	// Lookback is how far back a selector looks for a series' latest
	// sample at each moment (5 minutes, as in Prometheus).
	Lookback time.Duration
	// MaxSteps bounds the moments of one query; MaxPoints the values it may
	// hold at once.
	MaxSteps  int
	MaxPoints int
}

// NewEngine returns an engine with the usual bounds.
func NewEngine(db Querier) *Engine {
	return &Engine{DB: db, Lookback: 5 * time.Minute, MaxSteps: 11000, MaxPoints: 10_000_000}
}

// ErrTooMuch is a query that would hold too many values.
var ErrTooMuch = errors.New("the query works on too many values; narrow it down with label filters, a shorter time range or a longer step")

// Values are a series' values at each step; a missing one is null in JSON,
// and NaN and infinities are strings, as JSON numbers cannot be.
type Values struct {
	V  []float64
	OK []bool
}

func (v Values) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(v.V)*8+2)
	b = append(b, '[')
	for i, f := range v.V {
		if i > 0 {
			b = append(b, ',')
		}
		switch {
		case !v.OK[i]:
			b = append(b, "null"...)
		case math.IsNaN(f):
			b = append(b, `"NaN"`...)
		case math.IsInf(f, 1):
			b = append(b, `"+Inf"`...)
		case math.IsInf(f, -1):
			b = append(b, `"-Inf"`...)
		default:
			b = strconv.AppendFloat(b, f, 'g', -1, 64)
		}
	}
	return append(b, ']'), nil
}

// Series is a series of a result.
type Series struct {
	Labels map[string]string `json:"labels"`
	Values Values            `json:"values"`
}

// Result is what a query gave at each step from Start to End.
type Result struct {
	Start    int64    `json:"start"` // Unix milliseconds
	End      int64    `json:"end"`
	Step     int64    `json:"step"` // milliseconds
	Series   []Series `json:"series"`
	Warnings []string `json:"warnings,omitempty"`
}

// stepSeries holds a series' value at each step.
type stepSeries struct {
	labels tsdb.Labels
	v      []float64
	ok     []bool
}

type vector []*stepSeries
type scalar []float64

type evaluator struct {
	ctx      context.Context
	e        *Engine
	keep     func(tsdb.Labels) bool
	ts       []int64
	points   int
	warnings map[string]bool
}

// Range evaluates q at every step from start to end (Unix milliseconds).
// keep, when set, hides the series it does not keep, such as the ones a
// user may not see.
func (e *Engine) Range(ctx context.Context, q string, start, end, step int64, keep func(tsdb.Labels) bool) (*Result, error) {
	expr, err := Parse(q)
	if err != nil {
		return nil, err
	}
	return e.RangeExpr(ctx, expr, start, end, step, keep)
}

// RangeExpr is Range for a parsed query.
func (e *Engine) RangeExpr(ctx context.Context, expr Expr, start, end, step int64, keep func(tsdb.Labels) bool) (*Result, error) {
	if step <= 0 {
		return nil, errors.New("the step must be above zero")
	}
	span := end - start
	if end < start || span < 0 {
		return nil, errors.New("the range ends before it starts")
	}
	// Counted without adding one first, which could overflow.
	if span/step >= int64(e.MaxSteps) {
		return nil, fmt.Errorf("the range holds more than %d steps; make the step longer", e.MaxSteps)
	}
	n := span/step + 1
	switch expr.Type() {
	case typeMatrix:
		return nil, errors.New("a range vector cannot be drawn; wrap it in a function such as rate()")
	case typeString:
		return nil, errors.New("a string cannot be drawn")
	}
	ev := &evaluator{ctx: ctx, e: e, keep: keep, warnings: map[string]bool{}}
	ev.ts = make([]int64, n)
	for i := range ev.ts {
		ev.ts[i] = start + int64(i)*step
	}
	v, err := ev.eval(expr)
	if err != nil {
		return nil, err
	}
	res := &Result{Start: start, End: ev.ts[n-1], Step: step, Series: []Series{}}
	switch x := v.(type) {
	case scalar:
		ok := make([]bool, len(x))
		for i := range ok {
			ok[i] = true
		}
		res.Series = append(res.Series, Series{Labels: map[string]string{}, Values: Values{x, ok}})
	case vector:
		for _, s := range x {
			if anyOK(s.ok) {
				res.Series = append(res.Series, Series{Labels: toMap(s.labels), Values: Values{s.v, s.ok}})
			}
		}
		order(res.Series, expr, n == 1)
	}
	for w := range ev.warnings {
		res.Warnings = append(res.Warnings, w)
	}
	sort.Strings(res.Warnings)
	return res, nil
}

func anyOK(ok []bool) bool {
	for _, b := range ok {
		if b {
			return true
		}
	}
	return false
}

// order sorts the series by their labels, or for an instant sort() and
// sort_desc() by value.
func order(ss []Series, expr Expr, instant bool) {
	for {
		p, ok := expr.(*Paren)
		if !ok {
			break
		}
		expr = p.Expr
	}
	if c, ok := expr.(*Call); ok && instant && (c.Func.name == "sort" || c.Func.name == "sort_desc") {
		desc := c.Func.name == "sort_desc"
		sort.SliceStable(ss, func(i, j int) bool {
			a, b := ss[i].Values.V[0], ss[j].Values.V[0]
			if desc {
				return a > b || (!math.IsNaN(a) && math.IsNaN(b))
			}
			return a < b || (!math.IsNaN(a) && math.IsNaN(b))
		})
		return
	}
	keys := make([]string, len(ss))
	for i, s := range ss {
		keys[i] = labelKey(s.Labels)
	}
	sort.Sort(byKey{ss, keys})
}

type byKey struct {
	ss   []Series
	keys []string
}

func (b byKey) Len() int           { return len(b.ss) }
func (b byKey) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b byKey) Swap(i, j int) {
	b.ss[i], b.ss[j] = b.ss[j], b.ss[i]
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
}

func labelKey(m map[string]string) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(m[tsdb.MetricName])
	for _, k := range names {
		if k != tsdb.MetricName {
			b.WriteString("\xff" + k + "\xff" + m[k])
		}
	}
	return b.String()
}

func (ev *evaluator) warn(format string, args ...any) {
	ev.warnings[fmt.Sprintf(format, args...)] = true
}

// charge counts values held, failing past the engine's bound.
func (ev *evaluator) charge(n int) error {
	ev.points += n
	if ev.points > ev.e.MaxPoints {
		return ErrTooMuch
	}
	return nil
}

func (ev *evaluator) newSeries(ls tsdb.Labels) (*stepSeries, error) {
	if err := ev.charge(len(ev.ts)); err != nil {
		return nil, err
	}
	return &stepSeries{labels: ls, v: make([]float64, len(ev.ts)), ok: make([]bool, len(ev.ts))}, nil
}

func (ev *evaluator) newScalar() (scalar, error) {
	if err := ev.charge(len(ev.ts)); err != nil {
		return nil, err
	}
	return make(scalar, len(ev.ts)), nil
}

func (ev *evaluator) eval(expr Expr) (any, error) {
	if err := ev.ctx.Err(); err != nil {
		return nil, err
	}
	switch x := expr.(type) {
	case NumberLit:
		s, err := ev.newScalar()
		if err != nil {
			return nil, err
		}
		for i := range s {
			s[i] = x.V
		}
		return s, nil
	case StringLit:
		return x.V, nil
	case *Paren:
		return ev.eval(x.Expr)
	case *Unary:
		v, err := ev.eval(x.Expr)
		if err != nil {
			return nil, err
		}
		switch y := v.(type) {
		case scalar:
			for i := range y {
				y[i] = -y[i]
			}
			return y, nil
		case vector:
			for _, s := range y {
				s.labels = dropName(s.labels)
				for i := range s.v {
					s.v[i] = -s.v[i]
				}
			}
			return ev.dedupe(y), nil
		}
	case *VectorSelector:
		return ev.selectVector(x)
	case *MatrixSelector:
		return nil, errors.New("a range vector goes only into a function such as rate()")
	case *Call:
		return ev.call(x)
	case *Aggregate:
		return ev.aggregate(x)
	case *Binary:
		return ev.binary(x)
	}
	return nil, fmt.Errorf("cannot evaluate %s", expr)
}

func (ev *evaluator) scalarArg(e Expr) (scalar, error) {
	v, err := ev.eval(e)
	if err != nil {
		return nil, err
	}
	return v.(scalar), nil
}

func (ev *evaluator) vectorArg(e Expr) (vector, error) {
	v, err := ev.eval(e)
	if err != nil {
		return nil, err
	}
	return v.(vector), nil
}

// each calls f with each series a selector picks, with the samples it
// needs for a window that long before each step.
func (ev *evaluator) each(vs *VectorSelector, window int64, f func(tsdb.Series) error) error {
	off := vs.Offset.Milliseconds()
	from, to := ev.ts[0]-off-window+1, ev.ts[len(ev.ts)-1]-off
	if to < 0 {
		return nil
	}
	n := 0
	err := ev.e.DB.Each(max(from, 0), to, tsdb.Selector{Matchers: vs.Matchers, Keep: ev.keep}, func(s tsdb.Series) error {
		if n++; n%256 == 0 {
			if err := ev.ctx.Err(); err != nil {
				return err
			}
		}
		return f(s)
	})
	if errors.Is(err, tsdb.ErrTooMuch) {
		return ErrTooMuch
	}
	return err
}

// keepSeries adds a series to a vector if it has a value at some step, and
// otherwise gives back what it held.
func (ev *evaluator) keepSeries(out vector, ss *stepSeries) vector {
	if anyOK(ss.ok) {
		return append(out, ss)
	}
	ev.points -= len(ss.v)
	return out
}

// selectVector is each series' latest sample at each step, if not older
// than the lookback.
func (ev *evaluator) selectVector(vs *VectorSelector) (vector, error) {
	lb := ev.e.Lookback.Milliseconds()
	off := vs.Offset.Milliseconds()
	var out vector
	err := ev.each(vs, lb, func(s tsdb.Series) error {
		ss, err := ev.newSeries(s.Labels)
		if err != nil {
			return err
		}
		pts, j := s.Points, 0
		for i, t := range ev.ts {
			t -= off
			for j < len(pts) && pts[j].T <= t {
				j++
			}
			if j > 0 && pts[j-1].T > t-lb {
				ss.v[i], ss.ok[i] = pts[j-1].V, true
			}
		}
		out = ev.keepSeries(out, ss)
		return nil
	})
	return out, err
}

// windows applies f to the samples of each series within the range before
// each step.
func (ev *evaluator) windows(ms *MatrixSelector, keepName bool, f windowFunc) (vector, error) {
	r := ms.Range.Milliseconds()
	off := ms.VS.Offset.Milliseconds()
	var out vector
	err := ev.each(ms.VS, r, func(s tsdb.Series) error {
		ls := s.Labels
		if !keepName {
			ls = dropName(ls)
		}
		ss, err := ev.newSeries(ls)
		if err != nil {
			return err
		}
		pts, lo, hi := s.Points, 0, 0
		for i, t := range ev.ts {
			end := t - off
			start := end - r
			for hi < len(pts) && pts[hi].T <= end {
				hi++
			}
			for lo < hi && pts[lo].T <= start {
				lo++
			}
			if v, ok := f(pts[lo:hi], start, end, i); ok {
				ss.v[i], ss.ok[i] = v, true
			}
		}
		out = ev.keepSeries(out, ss)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ev.dedupe(out), nil
}

func dropName(ls tsdb.Labels) tsdb.Labels {
	for i, l := range ls {
		if l.Name == tsdb.MetricName {
			out := make(tsdb.Labels, 0, len(ls)-1)
			return append(append(out, ls[:i]...), ls[i+1:]...)
		}
	}
	return ls
}

func seriesKey(ls tsdb.Labels) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Name + "\xff" + l.Value + "\xff")
	}
	return b.String()
}

// dedupe joins series that came to have the same labels, such as two
// metrics whose names a function dropped. Where both have a value, the
// first one's is kept, and a warning says so.
func (ev *evaluator) dedupe(v vector) vector {
	if len(v) < 2 {
		return v
	}
	seen := make(map[string]*stepSeries, len(v))
	out := v[:0]
	for _, s := range v {
		k := seriesKey(s.labels)
		d := seen[k]
		if d == nil {
			seen[k] = s
			out = append(out, s)
			continue
		}
		for i := range s.v {
			if s.ok[i] {
				if d.ok[i] {
					ev.warn("several series have the labels %s at the same moment; one of them is shown", s.labels)
					continue
				}
				d.v[i], d.ok[i] = s.v[i], true
			}
		}
	}
	return out
}

func (ev *evaluator) call(c *Call) (any, error) {
	name := c.Func.name
	if len(c.Args) > 0 && c.Args[0].Type() == typeMatrix || name == "quantile_over_time" {
		return ev.rangeFunction(c)
	}
	switch name {
	case "time":
		s, err := ev.newScalar()
		if err != nil {
			return nil, err
		}
		for i, t := range ev.ts {
			s[i] = float64(t) / 1000
		}
		return s, nil
	case "vector":
		x, err := ev.scalarArg(c.Args[0])
		if err != nil {
			return nil, err
		}
		ss, err := ev.newSeries(tsdb.Labels{})
		if err != nil {
			return nil, err
		}
		for i := range x {
			ss.v[i], ss.ok[i] = x[i], true
		}
		return vector{ss}, nil
	case "scalar":
		v, err := ev.vectorArg(c.Args[0])
		if err != nil {
			return nil, err
		}
		out, err := ev.newScalar()
		if err != nil {
			return nil, err
		}
		for i := range out {
			n := 0
			for _, s := range v {
				if s.ok[i] {
					n++
					out[i] = s.v[i]
				}
			}
			if n != 1 {
				out[i] = math.NaN()
			}
		}
		return out, nil
	case "absent":
		return ev.absent(c.Args[0], func() (vector, error) { return ev.vectorArg(c.Args[0]) })
	case "histogram_quantile":
		return ev.histogramQuantile(c)
	case "label_replace", "label_join":
		return ev.labelFunction(c)
	case "minute", "hour", "day_of_week", "day_of_month", "days_in_month", "month", "year":
		return ev.dateFunction(c)
	}
	v, err := ev.vectorArg(c.Args[0])
	if err != nil {
		return nil, err
	}
	var params []scalar
	for _, a := range c.Args[1:] {
		p, err := ev.scalarArg(a)
		if err != nil {
			return nil, err
		}
		params = append(params, p)
	}
	if name == "sort" || name == "sort_desc" {
		return v, nil
	}
	var f func(x float64, i int) (float64, bool)
	switch name {
	case "abs":
		f = func(x float64, _ int) (float64, bool) { return math.Abs(x), true }
	case "ceil":
		f = func(x float64, _ int) (float64, bool) { return math.Ceil(x), true }
	case "floor":
		f = func(x float64, _ int) (float64, bool) { return math.Floor(x), true }
	case "exp":
		f = func(x float64, _ int) (float64, bool) { return math.Exp(x), true }
	case "ln":
		f = func(x float64, _ int) (float64, bool) { return math.Log(x), true }
	case "log2":
		f = func(x float64, _ int) (float64, bool) { return math.Log2(x), true }
	case "log10":
		f = func(x float64, _ int) (float64, bool) { return math.Log10(x), true }
	case "sqrt":
		f = func(x float64, _ int) (float64, bool) { return math.Sqrt(x), true }
	case "sgn":
		f = func(x float64, _ int) (float64, bool) {
			switch {
			case x > 0:
				return 1, true
			case x < 0:
				return -1, true
			}
			return x, true
		}
	case "round":
		f = func(x float64, i int) (float64, bool) {
			to := 1.0
			if len(params) > 0 {
				to = params[0][i]
			}
			return math.Floor(x/to+0.5) * to, true
		}
	case "clamp":
		f = func(x float64, i int) (float64, bool) {
			lo, hi := params[0][i], params[1][i]
			if lo > hi {
				return 0, false
			}
			return math.Max(lo, math.Min(hi, x)), true
		}
	case "clamp_min":
		f = func(x float64, i int) (float64, bool) { return math.Max(params[0][i], x), true }
	case "clamp_max":
		f = func(x float64, i int) (float64, bool) { return math.Min(params[0][i], x), true }
	default:
		return nil, fmt.Errorf("%s is not implemented", name)
	}
	for _, s := range v {
		s.labels = dropName(s.labels)
		for i := range s.v {
			if s.ok[i] {
				s.v[i], s.ok[i] = f(s.v[i], i)
			}
		}
	}
	return ev.dedupe(v), nil
}

// absent is 1 at the steps where the vector has no series, with the labels
// that the argument's selector asks for exactly.
func (ev *evaluator) absent(arg Expr, get func() (vector, error)) (vector, error) {
	v, err := get()
	if err != nil {
		return nil, err
	}
	ls := tsdb.Labels{}
	var vs *VectorSelector
	switch x := arg.(type) {
	case *VectorSelector:
		vs = x
	case *MatrixSelector:
		vs = x.VS
	}
	if vs != nil {
		count := map[string]int{}
		for _, m := range vs.Matchers {
			count[m.Name]++
		}
		m := map[string]string{}
		for _, x := range vs.Matchers {
			if x.Type == tsdb.MatchEqual && x.Name != tsdb.MetricName && count[x.Name] == 1 {
				m[x.Name] = x.Value
			}
		}
		ls = fromMap(m)
	}
	ss, err := ev.newSeries(ls)
	if err != nil {
		return nil, err
	}
	for i := range ev.ts {
		present := false
		for _, s := range v {
			if s.ok[i] {
				present = true
				break
			}
		}
		if !present {
			ss.v[i], ss.ok[i] = 1, true
		}
	}
	return vector{ss}, nil
}

func (ev *evaluator) histogramQuantile(c *Call) (vector, error) {
	q, err := ev.scalarArg(c.Args[0])
	if err != nil {
		return nil, err
	}
	v, err := ev.vectorArg(c.Args[1])
	if err != nil {
		return nil, err
	}
	type member struct {
		le float64
		s  *stepSeries
	}
	type group struct {
		labels  tsdb.Labels
		members []member
	}
	groups := map[string]*group{}
	var keys []string
	for _, s := range v {
		raw := s.labels.Get("le")
		le, err := strconv.ParseFloat(raw, 64)
		if raw == "" || err != nil {
			ev.warn("histogram_quantile skipped series without a valid le label")
			continue
		}
		ls := make(tsdb.Labels, 0, len(s.labels))
		for _, l := range s.labels {
			if l.Name != "le" && l.Name != tsdb.MetricName {
				ls = append(ls, l)
			}
		}
		k := seriesKey(ls)
		g := groups[k]
		if g == nil {
			g = &group{labels: ls}
			groups[k] = g
			keys = append(keys, k)
		}
		g.members = append(g.members, member{le, s})
	}
	out := make(vector, 0, len(groups))
	buf := make([]bucket, 0, 32)
	for _, k := range keys {
		g := groups[k]
		ss, err := ev.newSeries(g.labels)
		if err != nil {
			return nil, err
		}
		for i := range ev.ts {
			buf = buf[:0]
			for _, m := range g.members {
				if m.s.ok[i] {
					buf = append(buf, bucket{m.le, m.s.v[i]})
				}
			}
			if len(buf) > 0 {
				ss.v[i], ss.ok[i] = bucketQuantile(q[i], buf), true
			}
		}
		out = append(out, ss)
	}
	return out, nil
}

var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (ev *evaluator) labelFunction(c *Call) (vector, error) {
	v, err := ev.vectorArg(c.Args[0])
	if err != nil {
		return nil, err
	}
	strs := make([]string, len(c.Args)-1)
	for i, a := range c.Args[1:] {
		strs[i] = a.(StringLit).V
	}
	dst := strs[0]
	if !labelName.MatchString(dst) {
		return nil, fmt.Errorf("%q is not a label name", dst)
	}
	var set func(ls tsdb.Labels) (string, bool)
	if c.Func.name == "label_replace" {
		repl, src := strs[1], strs[2]
		re, err := regexp.Compile("^(?:" + strs[3] + ")$")
		if err != nil {
			return nil, fmt.Errorf("label_replace: %v", err)
		}
		set = func(ls tsdb.Labels) (string, bool) {
			val := ls.Get(src)
			m := re.FindStringSubmatchIndex(val)
			if m == nil {
				return "", false
			}
			return string(re.ExpandString(nil, repl, val, m)), true
		}
	} else {
		sep, srcs := strs[1], strs[2:]
		set = func(ls tsdb.Labels) (string, bool) {
			vals := make([]string, len(srcs))
			for i, s := range srcs {
				vals[i] = ls.Get(s)
			}
			return strings.Join(vals, sep), true
		}
	}
	for _, s := range v {
		val, ok := set(s.labels)
		if !ok {
			continue
		}
		m := toMap(s.labels)
		if val == "" {
			delete(m, dst)
		} else {
			m[dst] = val
		}
		s.labels = fromMap(m)
	}
	return ev.dedupe(v), nil
}

func (ev *evaluator) dateFunction(c *Call) (vector, error) {
	var v vector
	if len(c.Args) == 0 {
		ss, err := ev.newSeries(tsdb.Labels{})
		if err != nil {
			return nil, err
		}
		for i, t := range ev.ts {
			ss.v[i], ss.ok[i] = float64(t)/1000, true
		}
		v = vector{ss}
	} else {
		var err error
		if v, err = ev.vectorArg(c.Args[0]); err != nil {
			return nil, err
		}
	}
	for _, s := range v {
		s.labels = dropName(s.labels)
		for i := range s.v {
			if !s.ok[i] {
				continue
			}
			t := time.Unix(int64(s.v[i]), 0).UTC()
			switch c.Func.name {
			case "minute":
				s.v[i] = float64(t.Minute())
			case "hour":
				s.v[i] = float64(t.Hour())
			case "day_of_week":
				s.v[i] = float64(t.Weekday())
			case "day_of_month":
				s.v[i] = float64(t.Day())
			case "days_in_month":
				s.v[i] = float64(time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day())
			case "month":
				s.v[i] = float64(t.Month())
			case "year":
				s.v[i] = float64(t.Year())
			}
		}
	}
	return ev.dedupe(v), nil
}

// groupLabels are the labels an aggregation keeps of a series.
func groupLabels(ls tsdb.Labels, grouping []string, without bool) tsdb.Labels {
	out := make(tsdb.Labels, 0, len(ls))
	for _, l := range ls {
		listed := false
		for _, g := range grouping {
			if g == l.Name {
				listed = true
				break
			}
		}
		if without {
			if !listed && l.Name != tsdb.MetricName {
				out = append(out, l)
			}
		} else if listed {
			out = append(out, l)
		}
	}
	return out
}

func (ev *evaluator) aggregate(a *Aggregate) (vector, error) {
	v, err := ev.vectorArg(a.Expr)
	if err != nil {
		return nil, err
	}
	var param scalar
	if a.Param != nil {
		if param, err = ev.scalarArg(a.Param); err != nil {
			return nil, err
		}
	}
	groups := map[string]*aggGroup{}
	var keys []string
	for _, s := range v {
		ls := groupLabels(s.labels, a.Grouping, a.Without)
		k := seriesKey(ls)
		g := groups[k]
		if g == nil {
			g = &aggGroup{labels: ls}
			groups[k] = g
			keys = append(keys, k)
		}
		g.members = append(g.members, s)
	}
	if a.Op == "topk" || a.Op == "bottomk" {
		return ev.topk(a.Op == "topk", param, groups, keys)
	}
	out := make(vector, 0, len(groups))
	vals := make([]float64, 0, 64)
	for _, k := range keys {
		g := groups[k]
		ss, err := ev.newSeries(g.labels)
		if err != nil {
			return nil, err
		}
		for i := range ev.ts {
			vals = vals[:0]
			for _, m := range g.members {
				if m.ok[i] {
					vals = append(vals, m.v[i])
				}
			}
			if len(vals) == 0 {
				continue
			}
			ss.ok[i] = true
			switch a.Op {
			case "sum", "avg":
				s := 0.0
				for _, x := range vals {
					s += x
				}
				if a.Op == "avg" {
					s /= float64(len(vals))
				}
				ss.v[i] = s
			case "min", "max":
				r := vals[0]
				for _, x := range vals[1:] {
					if (a.Op == "max" && (x > r || math.IsNaN(r))) || (a.Op == "min" && (x < r || math.IsNaN(r))) {
						r = x
					}
				}
				ss.v[i] = r
			case "count":
				ss.v[i] = float64(len(vals))
			case "group":
				ss.v[i] = 1
			case "stddev":
				ss.v[i] = math.Sqrt(variance(vals))
			case "stdvar":
				ss.v[i] = variance(vals)
			case "quantile":
				ss.v[i] = quantile(param[i], vals)
			}
		}
		out = append(out, ss)
	}
	return out, nil
}

type aggGroup struct {
	labels  tsdb.Labels
	members vector
}

// topk keeps, at each step, the k largest (or smallest) series of each
// group, with all their labels.
func (ev *evaluator) topk(top bool, param scalar, groups map[string]*aggGroup, keys []string) (vector, error) {
	type pick struct {
		s   *stepSeries
		out *stepSeries
	}
	var out vector
	for _, k := range keys {
		g := groups[k]
		picks := make([]pick, len(g.members))
		for j, m := range g.members {
			picks[j].s = m
		}
		order := make([]int, 0, len(picks))
		for i := range ev.ts {
			n := int(param[i])
			if n < 1 {
				continue
			}
			order = order[:0]
			for j, p := range picks {
				if p.s.ok[i] {
					order = append(order, j)
				}
			}
			sort.SliceStable(order, func(a, b int) bool {
				x, y := picks[order[a]].s.v[i], picks[order[b]].s.v[i]
				if math.IsNaN(y) {
					return !math.IsNaN(x)
				}
				if top {
					return x > y
				}
				return x < y
			})
			for _, j := range order[:min(n, len(order))] {
				p := &picks[j]
				if p.out == nil {
					s, err := ev.newSeries(p.s.labels)
					if err != nil {
						return nil, err
					}
					p.out = s
					out = append(out, s)
				}
				p.out.v[i], p.out.ok[i] = p.s.v[i], true
			}
		}
	}
	return out, nil
}
