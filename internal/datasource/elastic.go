package datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// ESQuery makes a time series of an Elasticsearch's documents: per step,
// how many match, or a statistic of one of their fields, for all of them
// or for each of the most common values of another field.
type ESQuery struct {
	Index   string `json:"index"`
	Query   string `json:"query"`  // Lucene syntax; empty matches all
	Metric  string `json:"metric"` // count, avg, sum, min, max, cardinality, p50, p75, p90, p95, p99
	Field   string `json:"field,omitempty"`
	GroupBy string `json:"groupBy,omitempty"`
	Size    int    `json:"size,omitempty"` // of the groups; 10 by default
	Start   int64  `json:"start"`
	End     int64  `json:"end"`
	Step    int64  `json:"step"`
}

// ESLogsQuery reads the newest matching documents, with how many match
// per step.
type ESLogsQuery struct {
	Index string `json:"index"`
	Query string `json:"query"`
	Size  int    `json:"size,omitempty"` // 100 by default, at most 500
	Start int64  `json:"start"`
	End   int64  `json:"end"`
	Step  int64  `json:"step"`
}

// LogLine is one document.
type LogLine struct {
	T       int64           `json:"t"` // Unix milliseconds
	Message string          `json:"message"`
	Index   string          `json:"index"`
	ID      string          `json:"id"`
	Source  json.RawMessage `json:"source"`
}

// Logs are the documents a logs query found.
type Logs struct {
	Total     int64         `json:"total"`
	TotalMore bool          `json:"totalMore,omitempty"` // there are more than Total
	Lines     []LogLine     `json:"lines"`
	Counts    *query.Result `json:"counts"`
}

// Field is a field of an index.
type Field struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Aggregatable bool   `json:"aggregatable"`
}

var (
	esField = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_.@-]*$`)
	esIndex = regexp.MustCompile(`^[^\s/\\?#"<>|]+$`)
	esStats = map[string]bool{"count": true, "avg": true, "sum": true, "min": true, "max": true, "cardinality": true,
		"p50": true, "p75": true, "p90": true, "p95": true, "p99": true}
)

const (
	maxGroups = 50
	// maxBuckets stays under Elasticsearch's search.max_buckets.
	maxBuckets = 60000
	maxLogs    = 500
	// maxSource bounds what a log line carries of its document.
	maxSource = 64 << 10
)

func checkIndex(index string) error {
	if index == "" || len(index) > 255 || !esIndex.MatchString(index) {
		return &QueryError{fmt.Errorf("invalid index pattern %q", index)}
	}
	return nil
}

// QueryError is a query that does not make sense, before anything is
// asked of the source.
type QueryError struct{ Err error }

func (e *QueryError) Error() string { return e.Err.Error() }
func (e *QueryError) Unwrap() error { return e.Err }

// Scope keeps the documents of some namespaces, by a field; nil keeps all.
type Scope []string

// filter is the query part: the time range, the text query and the scope.
func filter(src settings.DataSource, text string, start, end int64, scope Scope) map[string]any {
	f := []any{map[string]any{"range": map[string]any{src.TimeField: map[string]any{"gte": start, "lte": end, "format": "epoch_millis"}}}}
	if t := strings.TrimSpace(text); t != "" && t != "*" {
		f = append(f, map[string]any{"query_string": map[string]any{"query": t, "analyze_wildcard": true}})
	}
	if scope != nil {
		f = append(f, map[string]any{"terms": map[string]any{src.NamespaceLabel: []string(scope)}})
	}
	return map[string]any{"bool": map[string]any{"filter": f}}
}

// histogram counts per step; its buckets start where the steps are, the
// offset moving them off the multiples of the step that they would start
// at otherwise.
func histogram(src settings.DataSource, start, end, step int64, interval string) map[string]any {
	h := map[string]any{
		"field": src.TimeField, interval: strconv.FormatInt(step, 10) + "ms", "min_doc_count": 0,
		"extended_bounds": map[string]any{"min": start, "max": end},
	}
	if off := start % step; off != 0 {
		h["offset"] = strconv.FormatInt(off, 10) + "ms"
	}
	return map[string]any{"date_histogram": h}
}

// search runs a search. Elasticsearch before 7.2 takes "interval" where
// later ones take "fixed_interval"; the body is made again for it.
func (c *Client) search(ctx context.Context, src settings.DataSource, index string, body func(interval string) map[string]any) ([]byte, error) {
	run := func(interval string) ([]byte, error) {
		b, err := json.Marshal(body(interval))
		if err != nil {
			return nil, err
		}
		return c.do(ctx, src, request{method: http.MethodPost, path: "/" + url.PathEscape(index) + "/_search", body: b, contentType: "application/json"})
	}
	out, err := run("fixed_interval")
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusBadRequest && strings.Contains(e.Message, "fixed_interval") {
		return run("interval")
	}
	return out, err
}

func (q *ESQuery) check(src settings.DataSource) (int64, error) {
	if q.Index == "" {
		q.Index = src.Index
	}
	if err := checkIndex(q.Index); err != nil {
		return 0, err
	}
	if q.Metric == "" {
		q.Metric = "count"
	}
	if !esStats[q.Metric] {
		return 0, fmt.Errorf("unknown statistic %q", q.Metric)
	}
	if q.Metric != "count" && !esField.MatchString(q.Field) {
		return 0, fmt.Errorf("%s needs a field, such as event.duration", q.Metric)
	}
	if q.GroupBy != "" && !esField.MatchString(q.GroupBy) {
		return 0, fmt.Errorf("invalid field %q", q.GroupBy)
	}
	if q.Size == 0 {
		q.Size = 10
	}
	if q.Size < 1 || q.Size > maxGroups {
		return 0, fmt.Errorf("group into 1 to %d values", maxGroups)
	}
	n, err := steps(q.Start, q.End, q.Step)
	if err != nil {
		return 0, err
	}
	groups := int64(1)
	if q.GroupBy != "" {
		groups = int64(q.Size)
	}
	if n*groups > maxBuckets {
		return 0, fmt.Errorf("%d steps for %d groups make too many buckets; make the step longer or group into fewer", n, groups)
	}
	return n, nil
}

// stat is the aggregation of a statistic; nil for a count.
func (q ESQuery) stat() map[string]any {
	switch q.Metric {
	case "count":
		return nil
	case "avg", "sum", "min", "max", "cardinality":
		return map[string]any{q.Metric: map[string]any{"field": q.Field}}
	}
	p, _ := strconv.Atoi(q.Metric[1:])
	return map[string]any{"percentiles": map[string]any{"field": q.Field, "percents": []int{p}}}
}

// name is how the series of a query are called.
func (q ESQuery) name() string {
	if q.Metric == "count" {
		return "count"
	}
	return q.Metric + "(" + q.Field + ")"
}

type esBucket struct {
	Key         json.RawMessage `json:"key"`
	KeyAsString string          `json:"key_as_string"`
	DocCount    float64         `json:"doc_count"`
	M           *struct {
		Value  *float64            `json:"value"`
		Values map[string]*float64 `json:"values"`
	} `json:"m"`
	T *struct {
		Buckets []esBucket `json:"buckets"`
	} `json:"t"`
}

// ESSeries makes the series of a query.
func (c *Client) ESSeries(ctx context.Context, src settings.DataSource, q ESQuery, scope Scope) (*query.Result, error) {
	n, err := q.check(src)
	if err != nil {
		return nil, &QueryError{err}
	}
	stat := q.stat()
	body, err := c.search(ctx, src, q.Index, func(interval string) map[string]any {
		t := histogram(src, q.Start, q.End, q.Step, interval)
		if stat != nil {
			t["aggs"] = map[string]any{"m": stat}
		}
		aggs := map[string]any{"t": t}
		if q.GroupBy != "" {
			aggs = map[string]any{"g": map[string]any{
				"terms": map[string]any{"field": q.GroupBy, "size": q.Size, "order": map[string]any{"_count": "desc"}},
				"aggs":  aggs,
			}}
		}
		return map[string]any{"size": 0, "query": filter(src, q.Query, q.Start, q.End, scope), "aggs": aggs}
	})
	if err != nil {
		return nil, err
	}
	var r struct {
		Aggregations struct {
			T *struct {
				Buckets []esBucket `json:"buckets"`
			} `json:"t"`
			G *struct {
				Buckets []esBucket `json:"buckets"`
			} `json:"g"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("the source does not answer as Elasticsearch does: %w", err)
	}
	res := &query.Result{Start: q.Start, End: q.Start + (n-1)*q.Step, Step: q.Step, Series: []query.Series{}}
	add := func(labels map[string]string, buckets []esBucket) {
		s := query.Series{Labels: labels, Values: query.Values{V: make([]float64, n), OK: make([]bool, n)}}
		for _, b := range buckets {
			key, err := strconv.ParseInt(string(b.Key), 10, 64)
			if err != nil {
				continue
			}
			i := (key - q.Start) / q.Step
			if i < 0 || i >= n || (key-q.Start)%q.Step != 0 {
				continue
			}
			v, ok := b.value(q.Metric)
			s.Values.V[i], s.Values.OK[i] = v, ok
		}
		res.Series = append(res.Series, s)
	}
	switch {
	case r.Aggregations.G != nil:
		for _, g := range r.Aggregations.G.Buckets {
			if g.T == nil {
				continue
			}
			add(map[string]string{tsdb.MetricName: q.name(), q.GroupBy: g.keyText()}, g.T.Buckets)
		}
	case r.Aggregations.T != nil:
		add(map[string]string{tsdb.MetricName: q.name()}, r.Aggregations.T.Buckets)
	}
	return res, nil
}

// value is a bucket's statistic, if it has one.
func (b esBucket) value(metric string) (float64, bool) {
	if metric == "count" {
		return b.DocCount, true
	}
	if b.M == nil {
		return 0, false
	}
	if b.M.Value != nil {
		return *b.M.Value, true
	}
	for _, v := range b.M.Values {
		if v != nil {
			return *v, true
		}
	}
	return 0, false
}

// keyText is a terms bucket's value as text.
func (b esBucket) keyText() string {
	if b.KeyAsString != "" {
		return b.KeyAsString
	}
	var s string
	if json.Unmarshal(b.Key, &s) == nil {
		return s
	}
	return string(b.Key)
}

// ESLogs reads the newest documents of a query.
func (c *Client) ESLogs(ctx context.Context, src settings.DataSource, q ESLogsQuery, scope Scope) (*Logs, error) {
	if q.Index == "" {
		q.Index = src.Index
	}
	if err := checkIndex(q.Index); err != nil {
		return nil, &QueryError{err}
	}
	if q.Size == 0 {
		q.Size = 100
	}
	if q.Size < 1 || q.Size > maxLogs {
		return nil, &QueryError{fmt.Errorf("read 1 to %d documents", maxLogs)}
	}
	n, err := steps(q.Start, q.End, q.Step)
	if err != nil {
		return nil, &QueryError{err}
	}
	if n > maxBuckets {
		return nil, &QueryError{errors.New("too many steps; make the step longer")}
	}
	body, err := c.search(ctx, src, q.Index, func(interval string) map[string]any {
		return map[string]any{
			"size":  q.Size,
			"sort":  []any{map[string]any{src.TimeField: map[string]any{"order": "desc", "unmapped_type": "date"}}},
			"query": filter(src, q.Query, q.Start, q.End, scope),
			"aggs":  map[string]any{"t": histogram(src, q.Start, q.End, q.Step, interval)},
		}
	})
	if err != nil {
		return nil, err
	}
	var r struct {
		Hits struct {
			Total json.RawMessage `json:"total"`
			Hits  []struct {
				Index  string          `json:"_index"`
				ID     string          `json:"_id"`
				Source json.RawMessage `json:"_source"`
				Sort   []any           `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations struct {
			T struct {
				Buckets []esBucket `json:"buckets"`
			} `json:"t"`
		} `json:"aggregations"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("the source does not answer as Elasticsearch does: %w", err)
	}
	out := &Logs{Lines: []LogLine{}}
	// Total is a number before 7.0, {"value", "relation"} since.
	var total struct {
		Value    int64  `json:"value"`
		Relation string `json:"relation"`
	}
	if json.Unmarshal(r.Hits.Total, &total) == nil {
		out.Total, out.TotalMore = total.Value, total.Relation == "gte"
	} else {
		json.Unmarshal(r.Hits.Total, &out.Total)
	}
	for _, h := range r.Hits.Hits {
		line := LogLine{Index: h.Index, ID: h.ID, Source: h.Source}
		if len(h.Sort) > 0 {
			if num, ok := h.Sort[0].(json.Number); ok {
				line.T, _ = num.Int64()
			}
		}
		var doc map[string]any
		json.Unmarshal(h.Source, &doc)
		line.Message = text(dig(doc, src.MessageField))
		if len(line.Source) > maxSource {
			line.Source, _ = json.Marshal(map[string]string{"_truncated": fmt.Sprintf("the document takes %d KiB; it is not shown", len(h.Source)>>10)})
		}
		if line.Message == "" {
			line.Message = text(doc)
		}
		out.Lines = append(out.Lines, line)
	}
	res := &query.Result{Start: q.Start, End: q.Start + (n-1)*q.Step, Step: q.Step, Series: []query.Series{}}
	s := query.Series{Labels: map[string]string{tsdb.MetricName: "count"}, Values: query.Values{V: make([]float64, n), OK: make([]bool, n)}}
	for _, b := range r.Aggregations.T.Buckets {
		key, err := strconv.ParseInt(string(b.Key), 10, 64)
		if err != nil || key < q.Start || (key-q.Start)%q.Step != 0 {
			continue
		}
		if i := (key - q.Start) / q.Step; i < n {
			s.Values.V[i], s.Values.OK[i] = b.DocCount, true
		}
	}
	res.Series = append(res.Series, s)
	out.Counts = res
	return out, nil
}

// dig finds a field in a document by its dotted name: nested objects, or
// a key with dots in it.
func dig(doc map[string]any, name string) any {
	if v, ok := doc[name]; ok {
		return v
	}
	// a.b.c may be doc["a"]["b.c"], doc["a.b"]["c"] or doc["a"]["b"]["c"].
	for i := 1; i < len(name)-1; i++ {
		if name[i] != '.' {
			continue
		}
		if sub, ok := doc[name[:i]].(map[string]any); ok {
			if v := dig(sub, name[i+1:]); v != nil {
				return v
			}
		}
	}
	return nil
}

// text writes a value for a log line.
func text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// ESFields lists the fields of an index pattern.
func (c *Client) ESFields(ctx context.Context, src settings.DataSource, index string) ([]Field, error) {
	if index == "" {
		index = src.Index
	}
	if err := checkIndex(index); err != nil {
		return nil, err
	}
	body, err := c.do(ctx, src, request{method: http.MethodGet, path: "/" + url.PathEscape(index) + "/_field_caps", query: url.Values{"fields": {"*"}}})
	if err != nil {
		return nil, err
	}
	var r struct {
		Fields map[string]map[string]struct {
			Aggregatable bool `json:"aggregatable"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("the source does not answer as Elasticsearch does: %w", err)
	}
	out := []Field{}
	for name, types := range r.Fields {
		if strings.HasPrefix(name, "_") {
			continue
		}
		f := Field{Name: name}
		for t, caps := range types {
			if f.Type == "" || t < f.Type {
				f.Type = t
			}
			f.Aggregatable = f.Aggregatable || caps.Aggregatable
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// esVersion asks an Elasticsearch (or OpenSearch) what it is.
func (c *Client) esVersion(ctx context.Context, src settings.DataSource) (string, error) {
	body, err := c.do(ctx, src, request{method: http.MethodGet, path: "/"})
	if err != nil {
		return "", err
	}
	var r struct {
		Version struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
		} `json:"version"`
	}
	if json.Unmarshal(body, &r) != nil || r.Version.Number == "" {
		return "", errors.New("the source does not answer as Elasticsearch does; check its address")
	}
	if r.Version.Distribution == "opensearch" {
		return "OpenSearch " + r.Version.Number, nil
	}
	return "Elasticsearch " + r.Version.Number, nil
}

// Test asks a source what it is, to see that it answers.
func (c *Client) Test(ctx context.Context, src settings.DataSource) (string, error) {
	if src.Type == settings.SourceElasticsearch {
		return c.esVersion(ctx, src)
	}
	return c.promVersion(ctx, src)
}
