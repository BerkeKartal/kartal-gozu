package query

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// valueType is what an expression gives.
type valueType int

const (
	typeScalar valueType = iota
	typeVector
	typeMatrix
	typeString
)

func (t valueType) String() string {
	return [...]string{"a number", "an instant vector", "a range vector", "a string"}[t]
}

// Expr is a parsed query, or a part of one.
type Expr interface {
	Type() valueType
	String() string
}

type NumberLit struct{ V float64 }

type StringLit struct{ V string }

// VectorSelector picks series by their labels; the metric name is one of
// its matchers.
type VectorSelector struct {
	Name     string
	Matchers []*tsdb.Matcher
	Offset   time.Duration
}

// MatrixSelector is a vector selector with a range: the samples of the
// last Range at each moment.
type MatrixSelector struct {
	VS    *VectorSelector
	Range time.Duration
}

type Call struct {
	Func *function
	Args []Expr
}

type Aggregate struct {
	Op       string
	Expr     Expr
	Param    Expr // topk, bottomk and quantile
	Grouping []string
	Without  bool
}

// Matching says how the series of two vectors are paired.
type Matching struct {
	Card    string // "one-to-one", "many-to-one" (group_left) or "one-to-many" (group_right)
	On      bool
	Labels  []string
	Include []string
}

type Binary struct {
	Op         string
	LHS, RHS   Expr
	ReturnBool bool
	Matching   *Matching
}

type Unary struct {
	Op   string
	Expr Expr
}

type Paren struct{ Expr Expr }

func (NumberLit) Type() valueType       { return typeScalar }
func (StringLit) Type() valueType       { return typeString }
func (*VectorSelector) Type() valueType { return typeVector }
func (*MatrixSelector) Type() valueType { return typeMatrix }
func (c *Call) Type() valueType         { return c.Func.ret }
func (*Aggregate) Type() valueType      { return typeVector }
func (u *Unary) Type() valueType        { return u.Expr.Type() }
func (p *Paren) Type() valueType        { return p.Expr.Type() }
func (b *Binary) Type() valueType {
	if b.LHS.Type() == typeScalar && b.RHS.Type() == typeScalar {
		return typeScalar
	}
	return typeVector
}

func (n NumberLit) String() string { return strconv.FormatFloat(n.V, 'g', -1, 64) }
func (s StringLit) String() string { return strconv.Quote(s.V) }
func (v *VectorSelector) String() string {
	var ms []string
	for _, m := range v.Matchers {
		if m.Name == tsdb.MetricName && m.Type == tsdb.MatchEqual && v.Name != "" {
			continue
		}
		ms = append(ms, m.Name+string(m.Type)+strconv.Quote(m.Value))
	}
	s := v.Name
	if len(ms) > 0 || s == "" {
		s += "{" + strings.Join(ms, ", ") + "}"
	}
	if v.Offset != 0 {
		s += " offset " + formatDuration(v.Offset)
	}
	return s
}
func (m *MatrixSelector) String() string {
	vs := *m.VS
	vs.Offset = 0
	s := vs.String() + "[" + formatDuration(m.Range) + "]"
	if m.VS.Offset != 0 {
		s += " offset " + formatDuration(m.VS.Offset)
	}
	return s
}
func (c *Call) String() string {
	args := make([]string, len(c.Args))
	for i, a := range c.Args {
		args[i] = a.String()
	}
	return c.Func.name + "(" + strings.Join(args, ", ") + ")"
}
func (a *Aggregate) String() string {
	s := a.Op
	if a.Without {
		s += " without (" + strings.Join(a.Grouping, ", ") + ")"
	} else if len(a.Grouping) > 0 {
		s += " by (" + strings.Join(a.Grouping, ", ") + ")"
	}
	s += " ("
	if a.Param != nil {
		s += a.Param.String() + ", "
	}
	return s + a.Expr.String() + ")"
}
func (b *Binary) String() string {
	s := b.LHS.String() + " " + b.Op
	if b.ReturnBool {
		s += " bool"
	}
	if m := b.Matching; m != nil {
		if m.On || len(m.Labels) > 0 {
			kw := "ignoring"
			if m.On {
				kw = "on"
			}
			s += " " + kw + " (" + strings.Join(m.Labels, ", ") + ")"
		}
		switch m.Card {
		case "many-to-one":
			s += " group_left (" + strings.Join(m.Include, ", ") + ")"
		case "one-to-many":
			s += " group_right (" + strings.Join(m.Include, ", ") + ")"
		}
	}
	return s + " " + b.RHS.String()
}
func (u *Unary) String() string { return u.Op + u.Expr.String() }
func (p *Paren) String() string { return "(" + p.Expr.String() + ")" }

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	var b strings.Builder
	if d < 0 {
		// A negative offset looks ahead.
		b.WriteByte('-')
		d = -d
	}
	for _, u := range []struct {
		name string
		d    time.Duration
	}{{"y", unitOf["y"]}, {"w", unitOf["w"]}, {"d", unitOf["d"]}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}, {"ms", time.Millisecond}} {
		if n := d / u.d; n > 0 {
			fmt.Fprintf(&b, "%d%s", n, u.name)
			d -= n * u.d
		}
	}
	return b.String()
}

var aggregations = map[string]bool{
	"sum": true, "avg": true, "min": true, "max": true, "count": true, "group": true,
	"stddev": true, "stdvar": true, "topk": true, "bottomk": true, "quantile": true,
}

// precedence of the binary operators, lowest first.
var precedence = map[string]int{
	"or": 1, "and": 2, "unless": 2,
	"==": 3, "!=": 3, "<=": 3, "<": 3, ">=": 3, ">": 3,
	"+": 4, "-": 4, "*": 5, "/": 5, "%": 5, "atan2": 5, "^": 6,
}

func isComparison(op string) bool {
	switch op {
	case "==", "!=", "<=", "<", ">=", ">":
		return true
	}
	return false
}

func isSetOp(op string) bool { return op == "and" || op == "or" || op == "unless" }

type parser struct {
	toks []token
	i    int
}

// Parse reads a query.
func Parse(q string) (Expr, error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	e, err := p.expr(0)
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, p.errorf(t, "unexpected %s", t)
	}
	return e, nil
}

// ParseSelector reads a vector selector alone, such as {namespace="shop"}.
func ParseSelector(q string) (*VectorSelector, error) {
	e, err := Parse(q)
	if err != nil {
		return nil, err
	}
	vs, ok := e.(*VectorSelector)
	if !ok {
		return nil, fmt.Errorf("%s is not a series selector", q)
	}
	return vs, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) errorf(t token, format string, args ...any) error {
	return &ParseError{t.pos, fmt.Sprintf(format, args...)}
}

func (p *parser) isOp(val string) bool {
	t := p.peek()
	return t.kind == tOp && t.val == val
}

func (p *parser) expect(val string) error {
	t := p.next()
	if t.kind != tOp || t.val != val {
		return p.errorf(t, "expected %q, found %s", val, t)
	}
	return nil
}

// binaryOp is the operator at the parser, if one is.
func (p *parser) binaryOp() (string, bool) {
	t := p.peek()
	switch t.kind {
	case tOp:
		_, ok := precedence[t.val]
		return t.val, ok && t.val != "atan2"
	case tIdent:
		switch v := strings.ToLower(t.val); v {
		case "and", "or", "unless", "atan2":
			return v, true
		}
	}
	return "", false
}

func (p *parser) expr(min int) (Expr, error) {
	lhs, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		op, ok := p.binaryOp()
		if !ok || precedence[op] < min {
			return lhs, nil
		}
		optok := p.next()
		b := &Binary{Op: op, LHS: lhs}
		if p.peek().kind == tIdent && strings.EqualFold(p.peek().val, "bool") {
			if !isComparison(op) {
				return nil, p.errorf(p.peek(), "bool goes only after a comparison")
			}
			p.next()
			b.ReturnBool = true
		}
		if err := p.matching(b); err != nil {
			return nil, err
		}
		next := precedence[op] + 1
		if op == "^" {
			next = precedence[op] // right-associative
		}
		if b.RHS, err = p.expr(next); err != nil {
			return nil, err
		}
		if err := checkBinary(b); err != nil {
			return nil, p.errorf(optok, "%v", err)
		}
		lhs = b
	}
}

// matching reads on/ignoring and group_left/group_right after an operator.
func (p *parser) matching(b *Binary) error {
	t := p.peek()
	if t.kind != tIdent {
		return nil
	}
	kw := strings.ToLower(t.val)
	if kw != "on" && kw != "ignoring" {
		return nil
	}
	p.next()
	labels, err := p.labelList()
	if err != nil {
		return err
	}
	b.Matching = &Matching{Card: "one-to-one", On: kw == "on", Labels: labels}
	if t := p.peek(); t.kind == tIdent {
		switch strings.ToLower(t.val) {
		case "group_left", "group_right":
			p.next()
			b.Matching.Card = "many-to-one"
			if strings.EqualFold(t.val, "group_right") {
				b.Matching.Card = "one-to-many"
			}
			if p.isOp("(") {
				if b.Matching.Include, err = p.labelList(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkBinary(b *Binary) error {
	l, r := b.LHS.Type(), b.RHS.Type()
	for _, t := range []valueType{l, r} {
		if t != typeScalar && t != typeVector {
			return fmt.Errorf("%s cannot be an operand of %s; wrap a range vector in a function such as rate()", t, b.Op)
		}
	}
	if isSetOp(b.Op) && (l != typeVector || r != typeVector) {
		return fmt.Errorf("%s works only between instant vectors", b.Op)
	}
	if b.Matching != nil && (l != typeVector || r != typeVector) {
		return fmt.Errorf("on and ignoring work only between instant vectors")
	}
	if isComparison(b.Op) && l == typeScalar && r == typeScalar && !b.ReturnBool {
		return fmt.Errorf("a comparison between numbers needs bool")
	}
	if b.Matching != nil && b.Matching.Card != "one-to-one" && isSetOp(b.Op) {
		return fmt.Errorf("group_left and group_right do not go with %s", b.Op)
	}
	return nil
}

func (p *parser) unary() (Expr, error) {
	if p.isOp("-") || p.isOp("+") {
		op := p.next().val
		e, err := p.expr(precedence["^"])
		if err != nil {
			return nil, err
		}
		if t := e.Type(); t != typeScalar && t != typeVector {
			return nil, fmt.Errorf("%s cannot have a sign", t)
		}
		if n, ok := e.(NumberLit); ok {
			if op == "-" {
				n.V = -n.V
			}
			return n, nil
		}
		if op == "+" {
			return e, nil
		}
		return &Unary{Op: "-", Expr: e}, nil
	}
	e, err := p.primary()
	if err != nil {
		return nil, err
	}
	return p.postfix(e)
}

// postfix reads a range, an offset, or both after a selector.
func (p *parser) postfix(e Expr) (Expr, error) {
	for {
		t := p.peek()
		switch {
		case t.kind == tOp && t.val == "[":
			vs, ok := e.(*VectorSelector)
			if !ok {
				return nil, p.errorf(t, "a range goes only after a series selector; subqueries are not supported")
			}
			p.next()
			d := p.next()
			if d.kind != tDuration {
				return nil, p.errorf(d, "expected a duration such as 5m, found %s", d)
			}
			if p.isOp(":") {
				return nil, p.errorf(p.peek(), "subqueries are not supported")
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			r, err := ParseDuration(d.val)
			if err != nil || r <= 0 {
				return nil, p.errorf(d, "bad range %q", d.val)
			}
			e = &MatrixSelector{VS: vs, Range: r}
		case t.kind == tIdent && strings.EqualFold(t.val, "offset"):
			p.next()
			neg := false
			if p.isOp("-") {
				p.next()
				neg = true
			}
			d := p.next()
			if d.kind != tDuration {
				return nil, p.errorf(d, "expected a duration after offset, found %s", d)
			}
			off, err := ParseDuration(d.val)
			if err != nil {
				return nil, p.errorf(d, "%v", err)
			}
			if neg {
				off = -off
			}
			switch x := e.(type) {
			case *VectorSelector:
				x.Offset = off
			case *MatrixSelector:
				x.VS.Offset = off
			default:
				return nil, p.errorf(t, "offset goes only after a series selector")
			}
		case t.kind == tOp && t.val == "@":
			return nil, p.errorf(t, "the @ modifier is not supported")
		default:
			return e, nil
		}
	}
}

func (p *parser) primary() (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tNumber:
		p.next()
		v, err := parseNumber(t.val)
		if err != nil {
			return nil, p.errorf(t, "bad number %q", t.val)
		}
		return NumberLit{v}, nil
	case tString:
		p.next()
		return StringLit{t.val}, nil
	case tDuration:
		return nil, p.errorf(t, "a duration such as %s goes only in a range [..] or after offset", t.val)
	case tOp:
		switch t.val {
		case "(":
			p.next()
			e, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			return &Paren{e}, nil
		case "{":
			return p.selector("", t)
		}
		return nil, p.errorf(t, "unexpected %s", t)
	case tIdent:
		lower := strings.ToLower(t.val)
		if aggregations[lower] && p.aggregationAhead() {
			return p.aggregate()
		}
		if p.toks[p.i+1].kind == tOp && p.toks[p.i+1].val == "(" {
			return p.call()
		}
		if lower == "inf" || lower == "nan" {
			p.next()
			if lower == "nan" {
				return NumberLit{math.NaN()}, nil
			}
			return NumberLit{math.Inf(1)}, nil
		}
		p.next()
		return p.selector(t.val, t)
	}
	return nil, p.errorf(t, "unexpected %s", t)
}

// aggregationAhead tells an aggregation (sum(...), sum by (x) (...)) from
// a metric that happens to be named sum.
func (p *parser) aggregationAhead() bool {
	n := p.toks[p.i+1]
	return (n.kind == tOp && n.val == "(") || (n.kind == tIdent && (strings.EqualFold(n.val, "by") || strings.EqualFold(n.val, "without")))
}

func parseNumber(s string) (float64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseInt(s[2:], 16, 64)
		return float64(n), err
	}
	return strconv.ParseFloat(s, 64)
}

func (p *parser) selector(name string, at token) (Expr, error) {
	vs := &VectorSelector{Name: name}
	if name != "" {
		m, _ := tsdb.NewMatcher(tsdb.MatchEqual, tsdb.MetricName, name)
		vs.Matchers = append(vs.Matchers, m)
	}
	if p.isOp("{") {
		p.next()
		for !p.isOp("}") {
			lt := p.next()
			if lt.kind != tIdent {
				return nil, p.errorf(lt, "expected a label name, found %s", lt)
			}
			op := p.next()
			if op.kind != tOp || (op.val != "=" && op.val != "!=" && op.val != "=~" && op.val != "!~") {
				return nil, p.errorf(op, "expected =, !=, =~ or !~ after %s, found %s", lt.val, op)
			}
			vt := p.next()
			if vt.kind != tString {
				return nil, p.errorf(vt, "expected a quoted value for %s, found %s", lt.val, vt)
			}
			m, err := tsdb.NewMatcher(tsdb.MatchType(op.val), lt.val, vt.val)
			if err != nil {
				return nil, p.errorf(vt, "%v", err)
			}
			if lt.val == tsdb.MetricName && name != "" {
				return nil, p.errorf(lt, "the metric is named twice")
			}
			vs.Matchers = append(vs.Matchers, m)
			if p.isOp(",") {
				p.next()
				continue
			}
			if !p.isOp("}") {
				return nil, p.errorf(p.peek(), "expected , or } in the label matchers, found %s", p.peek())
			}
		}
		p.next()
	}
	// Like Prometheus: something must rule out matching every series.
	empty := true
	for _, m := range vs.Matchers {
		if !m.Matches("") {
			empty = false
		}
	}
	if empty {
		return nil, p.errorf(at, "a selector needs a metric name or a matcher that does not match the empty value, such as {job=\"x\"}")
	}
	return vs, nil
}

// labelList reads (a, b, c).
func (p *parser) labelList() ([]string, error) {
	if err := p.expect("("); err != nil {
		return nil, err
	}
	var out []string
	for !p.isOp(")") {
		t := p.next()
		if t.kind != tIdent {
			return nil, p.errorf(t, "expected a label name, found %s", t)
		}
		out = append(out, t.val)
		if p.isOp(",") {
			p.next()
		} else if !p.isOp(")") {
			return nil, p.errorf(p.peek(), "expected , or ), found %s", p.peek())
		}
	}
	p.next()
	return out, nil
}

func (p *parser) grouping(a *Aggregate) (bool, error) {
	t := p.peek()
	if t.kind != tIdent {
		return false, nil
	}
	kw := strings.ToLower(t.val)
	if kw != "by" && kw != "without" {
		return false, nil
	}
	p.next()
	labels, err := p.labelList()
	if err != nil {
		return false, err
	}
	a.Grouping, a.Without = labels, kw == "without"
	return true, nil
}

func (p *parser) aggregate() (Expr, error) {
	t := p.next()
	a := &Aggregate{Op: strings.ToLower(t.val)}
	before, err := p.grouping(a)
	if err != nil {
		return nil, err
	}
	if err := p.expect("("); err != nil {
		return nil, err
	}
	var args []Expr
	for !p.isOp(")") {
		e, err := p.expr(0)
		if err != nil {
			return nil, err
		}
		args = append(args, e)
		if p.isOp(",") {
			p.next()
		} else if !p.isOp(")") {
			return nil, p.errorf(p.peek(), "expected , or ), found %s", p.peek())
		}
	}
	p.next()
	if !before {
		if _, err := p.grouping(a); err != nil {
			return nil, err
		}
	}
	want := 1
	if a.Op == "topk" || a.Op == "bottomk" || a.Op == "quantile" {
		want = 2
	}
	if len(args) != want {
		return nil, p.errorf(t, "%s takes %d arguments, not %d", a.Op, want, len(args))
	}
	if want == 2 {
		a.Param = args[0]
		if a.Param.Type() != typeScalar {
			return nil, p.errorf(t, "the first argument of %s must be a number", a.Op)
		}
	}
	a.Expr = args[want-1]
	if a.Expr.Type() != typeVector {
		return nil, p.errorf(t, "%s needs an instant vector, not %s", a.Op, a.Expr.Type())
	}
	return a, nil
}

func (p *parser) call() (Expr, error) {
	t := p.next()
	f := functions[t.val]
	if f == nil {
		return nil, p.errorf(t, "unknown function %s", t.val)
	}
	p.next() // (
	var args []Expr
	for !p.isOp(")") {
		e, err := p.expr(0)
		if err != nil {
			return nil, err
		}
		args = append(args, e)
		if p.isOp(",") {
			p.next()
		} else if !p.isOp(")") {
			return nil, p.errorf(p.peek(), "expected , or ), found %s", p.peek())
		}
	}
	p.next()
	if len(args) < len(f.args)-f.optional || (!f.variadic && len(args) > len(f.args)) {
		return nil, p.errorf(t, "%s takes %s", f.name, f.usage())
	}
	for i, a := range args {
		want := f.args[min(i, len(f.args)-1)]
		if a.Type() != want {
			return nil, p.errorf(t, "argument %d of %s must be %s, not %s", i+1, f.name, want, a.Type())
		}
	}
	return &Call{Func: f, Args: args}, nil
}
