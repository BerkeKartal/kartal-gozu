package tsdb

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MetricName is the label that holds a series' metric name.
const MetricName = "__name__"

// Label is one name and value of a series.
type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Labels identify a series; they are kept sorted by name.
type Labels []Label

// FromMap makes the labels of metric name with the given labels.
func FromMap(name string, m map[string]string) Labels {
	ls := make(Labels, 0, len(m)+1)
	ls = append(ls, Label{MetricName, name})
	for k, v := range m {
		if k != MetricName && v != "" {
			ls = append(ls, Label{k, v})
		}
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Name < ls[j].Name })
	return ls
}

// Get returns a label's value, empty when the series does not have it.
func (ls Labels) Get(name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}

// Map returns the labels other than the metric name.
func (ls Labels) Map() map[string]string {
	m := make(map[string]string, len(ls))
	for _, l := range ls {
		if l.Name != MetricName {
			m[l.Name] = l.Value
		}
	}
	return m
}

// key is a series' identity; \xff never appears in UTF-8 text.
func (ls Labels) key() string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Name)
		b.WriteByte(0xff)
		b.WriteString(l.Value)
		b.WriteByte(0xff)
	}
	return b.String()
}

// String formats the labels the way Prometheus does: name{a="b"}.
func (ls Labels) String() string {
	var b strings.Builder
	b.WriteString(ls.Get(MetricName))
	b.WriteByte('{')
	first := true
	for _, l := range ls {
		if l.Name == MetricName {
			continue
		}
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString(l.Name)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(l.Value))
	}
	b.WriteByte('}')
	return b.String()
}

func (ls Labels) marshal() []byte {
	pairs := make([][2]string, len(ls))
	for i, l := range ls {
		pairs[i] = [2]string{l.Name, l.Value}
	}
	b, _ := json.Marshal(pairs)
	return b
}

func unmarshalLabels(b []byte) (Labels, error) {
	var pairs [][2]string
	if err := json.Unmarshal(b, &pairs); err != nil {
		return nil, err
	}
	ls := make(Labels, len(pairs))
	for i, p := range pairs {
		ls[i] = Label{p[0], p[1]}
	}
	return ls, nil
}

// MatchType is how a matcher compares a label's value.
type MatchType string

const (
	MatchEqual     MatchType = "="
	MatchNotEqual  MatchType = "!="
	MatchRegexp    MatchType = "=~"
	MatchNotRegexp MatchType = "!~"
)

// Matcher selects series by one label. A label a series does not have
// counts as empty, as in Prometheus: {pod!="x"} matches series without pod.
type Matcher struct {
	Name  string    `json:"name"`
	Type  MatchType `json:"type"`
	Value string    `json:"value"`
	re    *regexp.Regexp
}

// NewMatcher validates a matcher; regular expressions match the whole value.
func NewMatcher(t MatchType, name, value string) (*Matcher, error) {
	m := &Matcher{Name: name, Type: t, Value: value}
	switch t {
	case MatchEqual, MatchNotEqual:
	case MatchRegexp, MatchNotRegexp:
		re, err := regexp.Compile("^(?:" + value + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression %q: %w", value, err)
		}
		m.re = re
	default:
		return nil, fmt.Errorf("unknown match type %q", t)
	}
	return m, nil
}

// Matches tells whether a value passes the matcher.
func (m *Matcher) Matches(v string) bool {
	switch m.Type {
	case MatchEqual:
		return v == m.Value
	case MatchNotEqual:
		return v != m.Value
	case MatchRegexp:
		return m.re.MatchString(v)
	default:
		return !m.re.MatchString(v)
	}
}

func matchAll(ls Labels, ms []*Matcher) bool {
	for _, m := range ms {
		if !m.Matches(ls.Get(m.Name)) {
			return false
		}
	}
	return true
}

// Selector picks series: those all of Matchers select, and that Keep, when
// set, keeps, such as the ones a user may see.
type Selector struct {
	Matchers []*Matcher
	Keep     func(Labels) bool
}

// Match is a selector of matchers alone.
func Match(ms ...*Matcher) Selector { return Selector{Matchers: ms} }

func (s Selector) match(ls Labels) bool {
	return matchAll(ls, s.Matchers) && (s.Keep == nil || s.Keep(ls))
}
