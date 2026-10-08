package query

import (
	"math"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// toMap is all of a series' labels, its name included.
func toMap(ls tsdb.Labels) map[string]string {
	m := make(map[string]string, len(ls))
	for _, l := range ls {
		m[l.Name] = l.Value
	}
	return m
}

// fromMap makes labels of a map that may name the metric.
func fromMap(m map[string]string) tsdb.Labels {
	name := m[tsdb.MetricName]
	ls := tsdb.FromMap(name, m)
	if name == "" {
		ls = dropName(ls)
	}
	return ls
}

// binop applies an arithmetic or comparison operator; a comparison gives
// the left value and whether it holds.
func binop(op string, l, r float64) (float64, bool) {
	switch op {
	case "+":
		return l + r, true
	case "-":
		return l - r, true
	case "*":
		return l * r, true
	case "/":
		return l / r, true
	case "%":
		return math.Mod(l, r), true
	case "^":
		return math.Pow(l, r), true
	case "atan2":
		return math.Atan2(l, r), true
	case "==":
		return l, l == r
	case "!=":
		return l, l != r
	case ">":
		return l, l > r
	case "<":
		return l, l < r
	case ">=":
		return l, l >= r
	case "<=":
		return l, l <= r
	}
	panic("unknown operator " + op)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (ev *evaluator) binary(b *Binary) (any, error) {
	l, err := ev.eval(b.LHS)
	if err != nil {
		return nil, err
	}
	r, err := ev.eval(b.RHS)
	if err != nil {
		return nil, err
	}
	ls, lScalar := l.(scalar)
	rs, rScalar := r.(scalar)
	switch {
	case lScalar && rScalar:
		for i := range ls {
			v, keep := binop(b.Op, ls[i], rs[i])
			if isComparison(b.Op) {
				v = boolValue(keep)
			}
			ls[i] = v
		}
		return ls, nil
	case lScalar:
		return ev.vectorScalar(b, r.(vector), ls, true), nil
	case rScalar:
		return ev.vectorScalar(b, l.(vector), rs, false), nil
	}
	return ev.vectorVector(b, l.(vector), r.(vector))
}

// vectorScalar applies an operator between each series and a number. A
// comparison keeps the series' value, whichever side it is on.
func (ev *evaluator) vectorScalar(b *Binary, v vector, s scalar, scalarLeft bool) vector {
	cmp := isComparison(b.Op)
	for _, x := range v {
		if !cmp || b.ReturnBool {
			x.labels = dropName(x.labels)
		}
		for i := range x.v {
			if !x.ok[i] {
				continue
			}
			lv, rv := x.v[i], s[i]
			if scalarLeft {
				lv, rv = rv, lv
			}
			val, keep := binop(b.Op, lv, rv)
			switch {
			case cmp && b.ReturnBool:
				val = boolValue(keep)
			case cmp && !keep:
				x.ok[i] = false
				continue
			case cmp:
				val = x.v[i]
			}
			x.v[i] = val
		}
	}
	return ev.dedupe(keepPresent(v))
}

func keepPresent(v vector) vector {
	out := v[:0]
	for _, s := range v {
		if anyOK(s.ok) {
			out = append(out, s)
		}
	}
	return out
}

// signature is what pairs series of the two sides: the labels named by on,
// or all but those named by ignoring and the metric's name.
func signature(ls tsdb.Labels, m *Matching) string {
	var b strings.Builder
	for _, l := range ls {
		listed := false
		for _, n := range m.Labels {
			if n == l.Name {
				listed = true
				break
			}
		}
		if (m.On && listed) || (!m.On && !listed && l.Name != tsdb.MetricName) {
			b.WriteString(l.Name + "\xff" + l.Value + "\xff")
		}
	}
	return b.String()
}

func (ev *evaluator) vectorVector(b *Binary, lhs, rhs vector) (vector, error) {
	m := b.Matching
	if m == nil {
		m = &Matching{Card: "one-to-one"}
	}
	switch b.Op {
	case "and", "unless":
		present := presence(rhs, m, len(ev.ts))
		for _, s := range lhs {
			p := present[signature(s.labels, m)]
			for i := range s.ok {
				has := p != nil && p[i]
				if s.ok[i] && has == (b.Op == "unless") {
					s.ok[i] = false
				}
			}
		}
		return keepPresent(lhs), nil
	case "or":
		present := presence(lhs, m, len(ev.ts))
		out := lhs
		for _, s := range rhs {
			p := present[signature(s.labels, m)]
			for i := range s.ok {
				if s.ok[i] && p != nil && p[i] {
					s.ok[i] = false
				}
			}
			if anyOK(s.ok) {
				out = append(out, s)
			}
		}
		return ev.dedupe(out), nil
	}

	// The "many" side is walked; group_right swaps the sides for that.
	many, one, swapped := lhs, rhs, false
	if m.Card == "one-to-many" {
		many, one, swapped = rhs, lhs, true
	}
	index := map[string]vector{}
	for _, s := range one {
		k := signature(s.labels, m)
		index[k] = append(index[k], s)
	}
	cmp := isComparison(b.Op)
	dropNames := !cmp || b.ReturnBool
	var out vector
	for k, ms := range many {
		if k%256 == 0 && ev.ctx.Err() != nil {
			return nil, ev.ctx.Err()
		}
		for _, os := range index[signature(ms.labels, m)] {
			overlap := false
			for i := range ms.ok {
				if ms.ok[i] && os.ok[i] {
					overlap = true
					break
				}
			}
			if !overlap {
				continue
			}
			res, err := ev.newSeries(resultLabels(ms.labels, os.labels, m, dropNames))
			if err != nil {
				return nil, err
			}
			for i := range ms.ok {
				if !ms.ok[i] || !os.ok[i] {
					continue
				}
				lv, rv := ms.v[i], os.v[i]
				if swapped {
					lv, rv = rv, lv
				}
				val, keep := binop(b.Op, lv, rv)
				switch {
				case cmp && b.ReturnBool:
					val = boolValue(keep)
				case cmp && !keep:
					continue
				}
				res.v[i], res.ok[i] = val, true
			}
			if anyOK(res.ok) {
				out = append(out, res)
			}
		}
	}
	return ev.dedupe(out), nil
}

// presence says, by signature, at which steps a vector has a series.
func presence(v vector, m *Matching, n int) map[string][]bool {
	out := map[string][]bool{}
	for _, s := range v {
		k := signature(s.labels, m)
		p := out[k]
		if p == nil {
			p = make([]bool, n)
			out[k] = p
		}
		for i, ok := range s.ok {
			p[i] = p[i] || ok
		}
	}
	return out
}

// resultLabels are the labels of a pair's result: the "many" side's, less
// the metric's name for arithmetic, narrowed to the on labels (or without
// the ignoring ones) one to one, with the group_left or group_right labels
// of the other side added.
func resultLabels(many, one tsdb.Labels, m *Matching, dropName bool) tsdb.Labels {
	lb := toMap(many)
	if dropName {
		delete(lb, tsdb.MetricName)
	}
	if m.Card == "one-to-one" {
		if m.On {
			keep := map[string]string{}
			for _, n := range m.Labels {
				if v, ok := lb[n]; ok {
					keep[n] = v
				}
			}
			lb = keep
		} else {
			for _, n := range m.Labels {
				delete(lb, n)
			}
		}
	} else {
		for _, n := range m.Include {
			if v := one.Get(n); v != "" {
				lb[n] = v
			} else {
				delete(lb, n)
			}
		}
	}
	return fromMap(lb)
}
