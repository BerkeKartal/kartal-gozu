// Package query evaluates queries over the metric store in a subset of
// PromQL, the language of Prometheus: selectors with label matchers, range
// selectors and offsets, the usual functions (rate, increase, the
// *_over_time family, histogram_quantile, label_replace...), aggregations
// with by and without, and arithmetic, comparison and set operators with
// vector matching. Subqueries and the @ modifier are not supported.
package query

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tNumber
	tDuration
	tString
	tOp
)

type token struct {
	kind tokKind
	val  string
	pos  int
}

func (t token) String() string {
	switch t.kind {
	case tEOF:
		return "the end of the query"
	case tString:
		return strconv.Quote(t.val)
	}
	return fmt.Sprintf("%q", t.val)
}

// ParseError is a query that does not parse, with where.
type ParseError struct {
	Pos int
	Msg string
}

func (e *ParseError) Error() string { return fmt.Sprintf("at character %d: %s", e.Pos+1, e.Msg) }

func isIdentStart(c byte) bool {
	return c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

var operators = []string{"==", "!=", "<=", ">=", "=~", "!~", "<", ">", "=", "+", "-", "*", "/", "%", "^", "(", ")", "{", "}", "[", "]", ",", ":", "@"}

func lex(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case isIdentStart(c):
			j := i
			for j < len(s) && isIdentChar(s[j]) {
				j++
			}
			out = append(out, token{tIdent, s[i:j], i})
			i = j
		case isDigit(c) || (c == '.' && i+1 < len(s) && isDigit(s[i+1])):
			t, n, err := lexNumber(s, i)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
			i += n
		case c == '"' || c == '\'' || c == '`':
			v, n, err := lexString(s, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{tString, v, i})
			i += n
		default:
			op := ""
			for _, o := range operators {
				if strings.HasPrefix(s[i:], o) {
					op = o
					break
				}
			}
			if op == "" {
				return nil, &ParseError{i, fmt.Sprintf("unexpected character %q", c)}
			}
			out = append(out, token{tOp, op, i})
			i += len(op)
		}
	}
	return append(out, token{tEOF, "", len(s)}), nil
}

var durationRE = regexp.MustCompile(`^(?:[0-9]+(?:ms|s|m|h|d|w|y))+`)

// lexNumber reads a number, or a duration such as 1h30m.
func lexNumber(s string, i int) (token, int, error) {
	if m := durationRE.FindString(s[i:]); m != "" && (i+len(m) == len(s) || !isIdentChar(s[i+len(m)])) {
		return token{tDuration, m, i}, len(m), nil
	}
	j := i
	if strings.HasPrefix(s[i:], "0x") || strings.HasPrefix(s[i:], "0X") {
		j += 2
		for j < len(s) && strings.ContainsRune("0123456789abcdefABCDEF", rune(s[j])) {
			j++
		}
	} else {
		for j < len(s) && (isDigit(s[j]) || s[j] == '.') {
			j++
		}
		if j < len(s) && (s[j] == 'e' || s[j] == 'E') {
			k := j + 1
			if k < len(s) && (s[k] == '+' || s[k] == '-') {
				k++
			}
			if k < len(s) && isDigit(s[k]) {
				j = k
				for j < len(s) && isDigit(s[j]) {
					j++
				}
			}
		}
	}
	if j < len(s) && isIdentChar(s[j]) {
		return token{}, 0, &ParseError{i, fmt.Sprintf("bad number or duration %q", s[i:j+1])}
	}
	return token{tNumber, s[i:j], i}, j - i, nil
}

// lexString reads a quoted string, with the escapes of Go and PromQL (\n,
// \x41, \U0001F600...). Escapes that mean nothing there, such as \. in a
// regular expression, keep their backslash.
func lexString(s string, i int) (string, int, error) {
	q := s[i]
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == q:
			return b.String(), j - i + 1, nil
		case c == '\\' && q != '`' && j+1 < len(s):
			if e := s[j+1]; e == '\\' || e == '"' || e == '\'' {
				b.WriteByte(e)
				j++
				continue
			}
			r, multibyte, tail, err := strconv.UnquoteChar(s[j:], q)
			switch {
			case err != nil:
				b.WriteByte('\\')
				b.WriteByte(s[j+1])
				j++
			case multibyte:
				b.WriteRune(r)
				j = len(s) - len(tail) - 1
			default:
				b.WriteByte(byte(r))
				j = len(s) - len(tail) - 1
			}
		case c == '\n' && q != '`':
			return "", 0, &ParseError{i, "a string ends at the end of the line"}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, &ParseError{i, "a string is not closed"}
}

var unitOf = map[string]time.Duration{
	"ms": time.Millisecond, "s": time.Second, "m": time.Minute, "h": time.Hour,
	"d": 24 * time.Hour, "w": 7 * 24 * time.Hour, "y": 365 * 24 * time.Hour,
}

const maxDuration = 100 * 365 * 24 * time.Hour

var durationPart = regexp.MustCompile(`([0-9]+)(ms|s|m|h|d|w|y)`)

// ParseDuration reads a duration as queries write it: 5m, 1h30m, 2d.
func ParseDuration(s string) (time.Duration, error) {
	if durationRE.FindString(s) != s || s == "" {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	var d time.Duration
	for _, m := range durationPart.FindAllStringSubmatch(s, -1) {
		n, err := strconv.ParseInt(m[1], 10, 64)
		unit := unitOf[m[2]]
		// A hundred years is far more than any store holds, and far from
		// overflowing.
		if err != nil || n > int64(maxDuration/unit) || d+time.Duration(n)*unit > maxDuration {
			return 0, fmt.Errorf("the duration %q is longer than 100 years", s)
		}
		d += time.Duration(n) * unit
	}
	return d, nil
}
