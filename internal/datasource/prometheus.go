package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/query"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// MaxSteps bounds the moments of one query, as the metric store's do.
const MaxSteps = 11000

// promAnswer is the envelope of Prometheus's API.
type promAnswer struct {
	Status   string          `json:"status"`
	Data     json.RawMessage `json:"data"`
	Error    string          `json:"error"`
	Warnings []string        `json:"warnings"`
}

func (c *Client) prom(ctx context.Context, src settings.DataSource, method, path string, params url.Values) (json.RawMessage, []string, error) {
	r := request{method: method, path: path}
	if method == http.MethodPost {
		r.body, r.contentType = []byte(params.Encode()), "application/x-www-form-urlencoded"
	} else {
		r.query = params
	}
	body, err := c.do(ctx, src, r)
	if err != nil {
		return nil, nil, err
	}
	var a promAnswer
	if err := json.Unmarshal(body, &a); err != nil || a.Status == "" {
		return nil, nil, errors.New("the source does not answer as Prometheus does; check its address")
	}
	if a.Status != "success" {
		return nil, nil, errors.New(a.Error)
	}
	return a.Data, a.Warnings, nil
}

// seconds writes milliseconds as Prometheus takes times and steps.
func seconds(ms int64) string { return strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64) }

// PromRange evaluates a query at each step from start to end (Unix
// milliseconds), as the metric store's queries are.
func (c *Client) PromRange(ctx context.Context, src settings.DataSource, q string, start, end, step int64) (*query.Result, error) {
	n, err := steps(start, end, step)
	if err != nil {
		return nil, err
	}
	data, warnings, err := c.prom(ctx, src, http.MethodPost, "/api/v1/query_range", url.Values{
		"query": {q}, "start": {seconds(start)}, "end": {seconds(end)}, "step": {seconds(step)},
	})
	if err != nil {
		return nil, err
	}
	var m struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string    `json:"metric"`
			Values [][2]json.RawMessage `json:"values"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("the source's answer: %w", err)
	}
	res := &query.Result{Start: start, End: start + (n-1)*step, Step: step, Series: []query.Series{}, Warnings: warnings}
	for _, r := range m.Result {
		s := query.Series{Labels: r.Metric, Values: query.Values{V: make([]float64, n), OK: make([]bool, n)}}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		for _, p := range r.Values {
			ts, err := strconv.ParseFloat(string(p[0]), 64)
			if err != nil {
				continue
			}
			var text string
			if json.Unmarshal(p[1], &text) != nil {
				continue
			}
			v, err := strconv.ParseFloat(text, 64)
			if err != nil {
				continue
			}
			i := int64(math.Round((ts*1000 - float64(start)) / float64(step)))
			if i >= 0 && i < n {
				s.Values.V[i], s.Values.OK[i] = v, true
			}
		}
		res.Series = append(res.Series, s)
	}
	return res, nil
}

// steps counts the moments from start to end.
func steps(start, end, step int64) (int64, error) {
	if step <= 0 || end < start || end-start < 0 {
		return 0, &QueryError{errors.New("give a range that starts before it ends, and a step above zero")}
	}
	if (end-start)/step >= MaxSteps {
		return 0, &QueryError{fmt.Errorf("the range holds more than %d steps; make the step longer", MaxSteps)}
	}
	return (end-start)/step + 1, nil
}

func (c *Client) promStrings(ctx context.Context, src settings.DataSource, path string, match string, start, end int64) ([]string, error) {
	params := url.Values{"start": {seconds(start)}, "end": {seconds(end)}}
	if match != "" {
		params.Set("match[]", match)
	}
	data, _, err := c.prom(ctx, src, http.MethodGet, path, params)
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("the source's answer: %w", err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// PromLabels lists the label names of the series match picks (all
// without one).
func (c *Client) PromLabels(ctx context.Context, src settings.DataSource, match string, start, end int64) ([]string, error) {
	names, err := c.promStrings(ctx, src, "/api/v1/labels", match, start, end)
	if err != nil {
		return nil, err
	}
	out := names[:0]
	for _, n := range names {
		if n != tsdb.MetricName {
			out = append(out, n)
		}
	}
	return out, nil
}

// PromLabelValues lists a label's values among the series match picks.
func (c *Client) PromLabelValues(ctx context.Context, src settings.DataSource, name, match string, start, end int64) ([]string, error) {
	return c.promStrings(ctx, src, "/api/v1/label/"+url.PathEscape(name)+"/values", match, start, end)
}

// PromMetrics lists the metrics among the series match picks, with their
// types where the source knows them.
func (c *Client) PromMetrics(ctx context.Context, src settings.DataSource, match string, start, end int64) ([]tsdb.MetricInfo, error) {
	names, err := c.PromLabelValues(ctx, src, tsdb.MetricName, match, start, end)
	if err != nil {
		return nil, err
	}
	types := map[string]string{}
	// Older servers have no metadata; the names do without.
	if data, _, err := c.prom(ctx, src, http.MethodGet, "/api/v1/metadata", nil); err == nil {
		var meta map[string][]struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &meta) == nil {
			for name, m := range meta {
				if len(m) > 0 {
					types[name] = m[0].Type
				}
			}
		}
	}
	out := make([]tsdb.MetricInfo, 0, len(names))
	for _, n := range names {
		t := types[n]
		if t == "" {
			// A histogram's or summary's series are named after it.
			for _, suffix := range []string{"_bucket", "_sum", "_count"} {
				if base, ok := strings.CutSuffix(n, suffix); ok && types[base] != "" {
					t = types[base]
				}
			}
		}
		out = append(out, tsdb.MetricInfo{Name: n, Type: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// promVersion asks a Prometheus what it is.
func (c *Client) promVersion(ctx context.Context, src settings.DataSource) (string, error) {
	data, _, err := c.prom(ctx, src, http.MethodGet, "/api/v1/status/buildinfo", nil)
	if err == nil {
		var b struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &b) == nil && b.Version != "" {
			return "Prometheus " + b.Version, nil
		}
	}
	// Servers that speak the API without being Prometheus may not have
	// build information; a query tells all the same.
	if _, _, err := c.prom(ctx, src, http.MethodGet, "/api/v1/query", url.Values{"query": {"1"}}); err != nil {
		return "", err
	}
	return "Prometheus API", nil
}

// ErrNoNamespace is a user who sees none of a source's namespaces.
var ErrNoNamespace = errors.New("you see none of the namespaces of this source's cluster")

// alternation is a regular expression that matches exactly the values.
func alternation(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = regexp.QuoteMeta(v)
	}
	return strings.Join(quoted, "|")
}

// ScopePromQL narrows a query to namespaces, as prom-label-proxy does:
// every selector in it also asks that label match one of them. The query
// must be one Kartal Gözü's own parser reads.
func ScopePromQL(q, label string, namespaces []string) (string, error) {
	if len(namespaces) == 0 {
		return "", ErrNoNamespace
	}
	expr, err := query.Parse(q)
	if err != nil {
		return "", fmt.Errorf("you see only some namespaces of this source, so the query must be one Kartal Gözü can read to keep it to them: %w", err)
	}
	m, err := tsdb.NewMatcher(tsdb.MatchRegexp, label, alternation(namespaces))
	if err != nil {
		return "", err
	}
	query.Inspect(expr, func(e query.Expr) {
		if vs, ok := e.(*query.VectorSelector); ok {
			vs.Matchers = append(vs.Matchers, m)
		}
	})
	return expr.String(), nil
}

// ScopeMatch narrows a series selector (empty: all series) to namespaces.
func ScopeMatch(match, label string, namespaces []string) (string, error) {
	if len(namespaces) == 0 {
		return "", ErrNoNamespace
	}
	if match == "" {
		return "{" + label + "=~" + strconv.Quote(alternation(namespaces)) + "}", nil
	}
	return ScopePromQL(match, label, namespaces)
}
