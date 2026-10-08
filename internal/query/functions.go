package query

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

type function struct {
	name string
	args []valueType
	// optional trailing arguments may be left out; a variadic function
	// repeats its last.
	optional int
	variadic bool
	ret      valueType
}

func (f *function) usage() string {
	names := make([]string, len(f.args))
	for i, a := range f.args {
		names[i] = a.String()
	}
	s := strings.Join(names, ", ")
	if f.optional > 0 {
		s += fmt.Sprintf(" (the last %d optional)", f.optional)
	}
	if f.variadic {
		s += ", ..."
	}
	if s == "" {
		return "no arguments"
	}
	return s
}

var functions = map[string]*function{}

func def(name string, ret valueType, optional int, variadic bool, args ...valueType) {
	functions[name] = &function{name: name, args: args, optional: optional, variadic: variadic, ret: ret}
}

func init() {
	for _, n := range []string{"rate", "irate", "increase", "delta", "idelta", "deriv", "resets", "changes",
		"avg_over_time", "min_over_time", "max_over_time", "sum_over_time", "count_over_time", "last_over_time",
		"stddev_over_time", "stdvar_over_time", "present_over_time", "absent_over_time"} {
		def(n, typeVector, 0, false, typeMatrix)
	}
	def("quantile_over_time", typeVector, 0, false, typeScalar, typeMatrix)
	def("predict_linear", typeVector, 0, false, typeMatrix, typeScalar)
	for _, n := range []string{"abs", "ceil", "floor", "exp", "ln", "log2", "log10", "sqrt", "sgn", "sort", "sort_desc", "absent"} {
		def(n, typeVector, 0, false, typeVector)
	}
	def("round", typeVector, 1, false, typeVector, typeScalar)
	def("clamp", typeVector, 0, false, typeVector, typeScalar, typeScalar)
	def("clamp_min", typeVector, 0, false, typeVector, typeScalar)
	def("clamp_max", typeVector, 0, false, typeVector, typeScalar)
	def("histogram_quantile", typeVector, 0, false, typeScalar, typeVector)
	def("label_replace", typeVector, 0, false, typeVector, typeString, typeString, typeString, typeString)
	def("label_join", typeVector, 0, true, typeVector, typeString, typeString, typeString)
	def("scalar", typeScalar, 0, false, typeVector)
	def("vector", typeVector, 0, false, typeScalar)
	def("time", typeScalar, 0, false)
	for _, n := range []string{"minute", "hour", "day_of_week", "day_of_month", "days_in_month", "month", "year"} {
		def(n, typeVector, 1, false, typeVector)
	}
}

// FunctionNames lists the functions, for completion in the UI.
func FunctionNames() []string {
	out := make([]string, 0, len(functions)+len(aggregations))
	for n := range functions {
		out = append(out, n)
	}
	for n := range aggregations {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// windowFunc computes a range function over the samples of one window,
// (start, end], at step i.
type windowFunc func(pts []tsdb.Point, start, end int64, i int) (float64, bool)

func (ev *evaluator) rangeFunction(c *Call) (vector, error) {
	name := c.Func.name
	var ms *MatrixSelector
	var param scalar
	switch name {
	case "quantile_over_time":
		p, err := ev.scalarArg(c.Args[0])
		if err != nil {
			return nil, err
		}
		param, ms = p, c.Args[1].(*MatrixSelector)
	case "predict_linear":
		p, err := ev.scalarArg(c.Args[1])
		if err != nil {
			return nil, err
		}
		param, ms = p, c.Args[0].(*MatrixSelector)
	default:
		var ok bool
		if ms, ok = c.Args[0].(*MatrixSelector); !ok {
			return nil, fmt.Errorf("%s needs a series selector with a range, such as %s(x[5m])", name, name)
		}
	}
	rangeSec := ms.Range.Seconds()
	var f windowFunc
	switch name {
	case "rate", "increase", "delta":
		counter, isRate := name != "delta", name == "rate"
		f = func(p []tsdb.Point, start, end int64, _ int) (float64, bool) {
			return extrapolated(p, start, end, counter, isRate, rangeSec)
		}
	case "irate", "idelta":
		f = func(p []tsdb.Point, _, _ int64, _ int) (float64, bool) {
			if len(p) < 2 {
				return 0, false
			}
			last, prev := p[len(p)-1], p[len(p)-2]
			d := last.V - prev.V
			if name == "idelta" {
				return d, true
			}
			if last.V < prev.V {
				d = last.V // a counter reset
			}
			dt := float64(last.T-prev.T) / 1000
			if dt == 0 {
				return 0, false
			}
			return d / dt, true
		}
	case "deriv", "predict_linear":
		f = func(p []tsdb.Point, _, end int64, i int) (float64, bool) {
			if len(p) < 2 {
				return 0, false
			}
			slope, intercept := regression(p, end)
			if name == "deriv" {
				return slope, true
			}
			return intercept + slope*param[i], true
		}
	case "resets", "changes":
		f = func(p []tsdb.Point, _, _ int64, _ int) (float64, bool) {
			if len(p) == 0 {
				return 0, false
			}
			n := 0
			for k := 1; k < len(p); k++ {
				if (name == "resets" && p[k].V < p[k-1].V) || (name == "changes" && p[k].V != p[k-1].V && !(math.IsNaN(p[k].V) && math.IsNaN(p[k-1].V))) {
					n++
				}
			}
			return float64(n), true
		}
	default:
		f = overTime(name, param)
	}
	if name == "absent_over_time" {
		return ev.absent(c.Args[0], func() (vector, error) {
			return ev.windows(ms, true, func(p []tsdb.Point, _, _ int64, _ int) (float64, bool) { return 1, len(p) > 0 })
		})
	}
	return ev.windows(ms, name == "last_over_time", f)
}

// overTime is the *_over_time function of that name.
func overTime(name string, param scalar) windowFunc {
	return func(p []tsdb.Point, _, _ int64, i int) (float64, bool) {
		if len(p) == 0 {
			return 0, false
		}
		switch name {
		case "avg_over_time", "sum_over_time":
			s := 0.0
			for _, x := range p {
				s += x.V
			}
			if name == "avg_over_time" {
				s /= float64(len(p))
			}
			return s, true
		case "min_over_time", "max_over_time":
			v := p[0].V
			for _, x := range p[1:] {
				if (name == "min_over_time" && (x.V < v || math.IsNaN(v))) || (name == "max_over_time" && (x.V > v || math.IsNaN(v))) {
					v = x.V
				}
			}
			return v, true
		case "count_over_time":
			return float64(len(p)), true
		case "last_over_time":
			return p[len(p)-1].V, true
		case "present_over_time":
			return 1, true
		case "stddev_over_time", "stdvar_over_time":
			vs := make([]float64, len(p))
			for k, x := range p {
				vs[k] = x.V
			}
			v := variance(vs)
			if name == "stddev_over_time" {
				v = math.Sqrt(v)
			}
			return v, true
		case "quantile_over_time":
			vs := make([]float64, len(p))
			for k, x := range p {
				vs[k] = x.V
			}
			return quantile(param[i], vs), true
		}
		return 0, false
	}
}

// extrapolated is Prometheus's rate, increase and delta: the change over
// the samples in the window, corrected for counter resets and extended to
// the window's edges where the samples suggest the series went on.
func extrapolated(p []tsdb.Point, start, end int64, counter, isRate bool, rangeSec float64) (float64, bool) {
	if len(p) < 2 {
		return 0, false
	}
	first, last := p[0], p[len(p)-1]
	result := last.V - first.V
	if counter {
		prev := first.V
		for _, x := range p[1:] {
			if x.V < prev {
				result += prev
			}
			prev = x.V
		}
	}
	toStart := float64(first.T-start) / 1000
	toEnd := float64(end-last.T) / 1000
	sampled := float64(last.T-first.T) / 1000
	if sampled <= 0 {
		return 0, false
	}
	avgStep := sampled / float64(len(p)-1)
	// Samples close to an edge (within 10% more than the usual step) are
	// taken to go on to it; farther, the series started or ended within
	// the window, half a step beyond its samples. As in Prometheus 3.
	threshold := avgStep * 1.1
	if toStart >= threshold {
		toStart = avgStep / 2
	}
	if counter && result > 0 && first.V >= 0 {
		// A counter does not go below zero: it is not extended past where
		// it would have been zero.
		if toZero := sampled * (first.V / result); toZero < toStart {
			toStart = toZero
		}
	}
	if toEnd >= threshold {
		toEnd = avgStep / 2
	}
	result *= (sampled + toStart + toEnd) / sampled
	if isRate {
		result /= rangeSec
	}
	return result, true
}

// regression fits a line through the samples, with times in seconds
// relative to at; it returns the slope and the value at at.
func regression(p []tsdb.Point, at int64) (slope, intercept float64) {
	var n, sumX, sumY, sumXY, sumX2 float64
	for _, x := range p {
		t := float64(x.T-at) / 1000
		n++
		sumX += t
		sumY += x.V
		sumXY += t * x.V
		sumX2 += t * t
	}
	cov := sumXY - sumX*sumY/n
	varX := sumX2 - sumX*sumX/n
	if varX == 0 {
		return 0, sumY / n
	}
	slope = cov / varX
	return slope, sumY/n - slope*sumX/n
}

func variance(vs []float64) float64 {
	var mean float64
	for _, v := range vs {
		mean += v
	}
	mean /= float64(len(vs))
	var s float64
	for _, v := range vs {
		s += (v - mean) * (v - mean)
	}
	return s / float64(len(vs))
}

// quantile is the φ-quantile of the values, interpolated between the two
// nearest, as Prometheus does.
func quantile(q float64, vs []float64) float64 {
	switch {
	case len(vs) == 0 || math.IsNaN(q):
		return math.NaN()
	case q < 0:
		return math.Inf(-1)
	case q > 1:
		return math.Inf(1)
	}
	sort.Float64s(vs)
	n := float64(len(vs))
	rank := q * (n - 1)
	lo := math.Max(0, math.Floor(rank))
	hi := math.Min(n-1, lo+1)
	w := rank - math.Floor(rank)
	return vs[int(lo)]*(1-w) + vs[int(hi)]*w
}

type bucket struct {
	upper, count float64
}

// bucketQuantile is the φ-quantile of a classic histogram's buckets, as
// Prometheus's histogram_quantile computes it.
func bucketQuantile(q float64, buckets []bucket) float64 {
	switch {
	case math.IsNaN(q):
		return math.NaN()
	case q < 0:
		return math.Inf(-1)
	case q > 1:
		return math.Inf(1)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].upper < buckets[j].upper })
	if len(buckets) < 2 || !math.IsInf(buckets[len(buckets)-1].upper, 1) {
		return math.NaN()
	}
	// Buckets of the same bound are added up; counts that go down, which
	// a scrape between two updates can show, are evened out.
	merged := buckets[:1]
	for _, b := range buckets[1:] {
		if b.upper == merged[len(merged)-1].upper {
			merged[len(merged)-1].count += b.count
		} else {
			merged = append(merged, b)
		}
	}
	buckets = merged
	for i := 1; i < len(buckets); i++ {
		buckets[i].count = math.Max(buckets[i].count, buckets[i-1].count)
	}
	if len(buckets) < 2 {
		return math.NaN()
	}
	total := buckets[len(buckets)-1].count
	if total == 0 {
		return math.NaN()
	}
	rank := q * total
	b := sort.Search(len(buckets)-1, func(i int) bool { return buckets[i].count >= rank })
	if b == len(buckets)-1 {
		return buckets[len(buckets)-2].upper
	}
	if b == 0 && buckets[0].upper <= 0 {
		return buckets[0].upper
	}
	start, end, count := 0.0, buckets[b].upper, buckets[b].count
	if b > 0 {
		start = buckets[b-1].upper
		count -= buckets[b-1].count
		rank -= buckets[b-1].count
	}
	if count == 0 {
		return end
	}
	return start + (end-start)*(rank/count)
}
