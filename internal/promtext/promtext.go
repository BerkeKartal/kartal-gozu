// Package promtext reads the Prometheus text exposition format, which most
// applications use to expose their metrics at /metrics. OpenMetrics, its
// successor, reads the same way for what is kept here; exemplars and
// timestamps are dropped.
package promtext

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const maxLine = 1 << 20

var (
	metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelName  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// ValidName tells whether s can be a metric's name.
func ValidName(s string) bool { return len(s) <= 200 && metricName.MatchString(s) }

// ValidLabel tells whether s can be a label's name.
func ValidLabel(s string) bool { return len(s) <= 100 && labelName.MatchString(s) }

// suffixes are what a family's samples add to its name, by its type.
var suffixes = map[string][]string{
	"counter":        {"_total", "_created"},
	"histogram":      {"_bucket", "_sum", "_count", "_created"},
	"gaugehistogram": {"_bucket", "_gsum", "_gcount"},
	"summary":        {"_sum", "_count", "_created"},
	"info":           {"_info"},
}

var types = map[string]bool{
	"counter": true, "gauge": true, "histogram": true, "gaugehistogram": true, "summary": true,
	"untyped": true, "unknown": true, "info": true, "stateset": true,
}

// ErrFormat is a page that is not in the text format. It never repeats
// what the page said: the page may be anything that answered at that path.
var ErrFormat = errors.New("not in the Prometheus text format")

type parser struct {
	families []protocol.MetricFamily
	byName   map[string]int
	typeOf   map[string]string
}

// family finds the family a sample belongs to: the one of its own name,
// or one whose type adds the sample's suffix. Without either, the sample
// is a family of its own, untyped.
func (p *parser) family(sample string) int {
	if i, ok := p.byName[sample]; ok {
		return i
	}
	for _, list := range suffixes {
		for _, suf := range list {
			base, ok := strings.CutSuffix(sample, suf)
			if !ok || base == "" {
				continue
			}
			if i, ok := p.byName[base]; ok && hasSuffix(p.typeOf[base], suf) {
				return i
			}
		}
	}
	return p.add(sample)
}

func hasSuffix(typ, suf string) bool {
	for _, s := range suffixes[typ] {
		if s == suf {
			return true
		}
	}
	return false
}

func (p *parser) add(name string) int {
	if i, ok := p.byName[name]; ok {
		return i
	}
	typ := p.typeOf[name]
	if typ == "" || typ == "unknown" {
		typ = "untyped"
	}
	p.families = append(p.families, protocol.MetricFamily{Name: name, Type: typ, Samples: []protocol.Sample{}})
	p.byName[name] = len(p.families) - 1
	return len(p.families) - 1
}

// Parse reads the metrics in r, keeping at most maxSamples samples; it
// says when there were more. A line it cannot read fails the whole page.
func Parse(r io.Reader, maxSamples int) ([]protocol.MetricFamily, bool, error) {
	p := &parser{byName: map[string]int{}, typeOf: map[string]string{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	n, kept, truncated := 0, 0, false
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			stop, err := p.comment(line)
			if err != nil {
				return nil, false, fmt.Errorf("line %d: %w", n, err)
			}
			if stop {
				break
			}
			continue
		}
		s, err := parseSample(line)
		if err != nil {
			return nil, false, fmt.Errorf("line %d: %w", n, err)
		}
		if kept >= maxSamples {
			truncated = true
			continue
		}
		f := &p.families[p.family(s.Name)]
		f.Samples = append(f.Samples, s)
		kept++
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, false, fmt.Errorf("line %d is longer than %d bytes: %w", n+1, maxLine, ErrFormat)
		}
		return nil, false, err
	}
	return p.families, truncated, nil
}

// comment reads "# HELP name text" and "# TYPE name type"; it says to stop
// at OpenMetrics' "# EOF". Other comments are skipped.
func (p *parser) comment(line string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 2 && fields[1] == "EOF" {
		return true, nil
	}
	if len(fields) < 3 || (fields[1] != "HELP" && fields[1] != "TYPE") {
		return false, nil
	}
	name := fields[2]
	if !metricName.MatchString(name) {
		return false, ErrFormat
	}
	if fields[1] == "TYPE" {
		if len(fields) != 4 || !types[fields[3]] {
			return false, ErrFormat
		}
		p.typeOf[name] = fields[3]
		i := p.add(name)
		if t := fields[3]; t != "unknown" {
			p.families[i].Type = t
		}
		return false, nil
	}
	// The help text is everything after the name, with \\ and \n escaped.
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	rest = strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(rest, "HELP")), name)
	i := p.add(name)
	p.families[i].Help = unescape(strings.TrimSpace(rest), false)
	return false, nil
}

// parseSample reads `name{label="value",...} value [timestamp]`.
func parseSample(line string) (protocol.Sample, error) {
	var s protocol.Sample
	end := strings.IndexAny(line, "{ \t")
	if end < 0 {
		return s, ErrFormat
	}
	s.Name = line[:end]
	if !metricName.MatchString(s.Name) {
		return s, ErrFormat
	}
	rest := line[end:]
	if rest[0] == '{' {
		labels, after, err := parseLabels(rest[1:])
		if err != nil {
			return s, err
		}
		if len(labels) > 0 {
			s.Labels = labels
		}
		rest = after
	}
	// An OpenMetrics exemplar follows " # ".
	if i := strings.Index(rest, " # "); i >= 0 {
		rest = rest[:i]
	}
	fields := strings.Fields(rest)
	if len(fields) < 1 || len(fields) > 2 {
		return s, ErrFormat
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s, ErrFormat
	}
	if len(fields) == 2 {
		if _, err := strconv.ParseFloat(fields[1], 64); err != nil {
			return s, ErrFormat
		}
	}
	s.Value = protocol.Number(v)
	return s, nil
}

// parseLabels reads `label="value",...}` and returns what follows.
func parseLabels(in string) (map[string]string, string, error) {
	labels := map[string]string{}
	for {
		in = strings.TrimLeft(in, " \t")
		if strings.HasPrefix(in, "}") {
			return labels, in[1:], nil
		}
		eq := strings.IndexByte(in, '=')
		if eq < 0 {
			return nil, "", ErrFormat
		}
		name := strings.TrimSpace(in[:eq])
		if !labelName.MatchString(name) {
			return nil, "", ErrFormat
		}
		in = strings.TrimLeft(in[eq+1:], " \t")
		if !strings.HasPrefix(in, `"`) {
			return nil, "", ErrFormat
		}
		// The value runs to the first quote that is not escaped.
		i, escaped := 1, false
		for ; i < len(in); i++ {
			if escaped {
				escaped = false
				continue
			}
			if in[i] == '\\' {
				escaped = true
			} else if in[i] == '"' {
				break
			}
		}
		if i >= len(in) {
			return nil, "", ErrFormat
		}
		labels[name] = unescape(in[1:i], true)
		in = strings.TrimLeft(in[i+1:], " \t")
		if strings.HasPrefix(in, ",") {
			in = in[1:]
		} else if !strings.HasPrefix(in, "}") {
			return nil, "", ErrFormat
		}
	}
}

// unescape undoes \\ and \n, and in label values \".
func unescape(s string, quotes bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case '"':
				if quotes {
					b.WriteByte('"')
					i++
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
