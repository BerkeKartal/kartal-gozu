// Package fakees is a small Elasticsearch for the demo and the tests: it
// holds the logs of the demo's web apps, made up from the time as they are
// asked for, and answers the searches Explore makes.
package fakees

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server answers as an Elasticsearch 8 with one index, logs-demo.
type Server struct {
	// Now can be replaced in tests.
	Now func() time.Time
}

const (
	every = 15 * time.Second
	keep  = 3 * 24 * time.Hour
)

var pods = func() []struct{ ns, pod string } {
	var out []struct{ ns, pod string }
	for team := 1; team <= 3; team++ {
		for r := 1; r <= 3; r++ {
			out = append(out, struct{ ns, pod string }{fmt.Sprintf("team-%02d", team), fmt.Sprintf("web-5d8c-%02d%d", team, r)})
		}
	}
	return out
}()

var paths = []string{"/api/orders", "/api/orders/{id}", "/api/cart", "/api/products", "/healthz", "/api/payments"}

// doc is a log line, made up from when and where it was written.
type doc struct {
	t      int64 // Unix milliseconds
	fields map[string]any
	flat   map[string]string
}

func noise(parts ...any) uint64 {
	h := fnv.New64a()
	fmt.Fprint(h, parts...)
	return h.Sum64()
}

func makeDoc(t time.Time, ns, pod string) doc {
	n := noise(t.Unix(), pod)
	path := paths[n%uint64(len(paths))]
	method := "GET"
	if n%7 == 0 {
		method = "POST"
	}
	// Every third team's app fails a share of its requests, as its metrics
	// say; the rest now and then.
	status := 200
	failing := uint64(100)
	if ns == "team-03" {
		failing = 4
	}
	switch {
	case n%failing == 1:
		status = 500
	case n%23 == 2:
		status = 404
	}
	level := "INFO"
	if status >= 500 {
		level = "ERROR"
	} else if status >= 400 {
		level = "WARN"
	}
	// Slower in the afternoon, and slower when failing.
	base := 20 + 15*math.Sin(float64(t.Unix())/3600)
	duration := int64(base + float64(n%120))
	if status >= 500 {
		duration += 400
	}
	msg := fmt.Sprintf("%s %s %d %dms", method, path, status, duration)
	if status >= 500 {
		msg += " error=\"upstream connect error or disconnect/reset before headers\""
	}
	fields := map[string]any{
		"@timestamp": t.UTC().Format(time.RFC3339Nano),
		"message":    msg,
		"log":        map[string]any{"level": level},
		"kubernetes": map[string]any{"namespace": ns, "pod": map[string]any{"name": pod}, "container": map[string]any{"name": "web"}},
		"http":       map[string]any{"request": map[string]any{"method": method}, "response": map[string]any{"status_code": status}},
		"url":        map[string]any{"path": path},
		"event":      map[string]any{"duration": duration},
	}
	flat := map[string]string{}
	flatten("", fields, flat)
	return doc{t: t.UnixMilli(), fields: fields, flat: flat}
}

func flatten(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, sub := range x {
			if prefix != "" {
				k = prefix + "." + k
			}
			flatten(k, sub, out)
		}
	default:
		out[prefix] = fmt.Sprint(x)
	}
}

var fieldTypes = map[string]string{
	"@timestamp": "date", "message": "text", "log.level": "keyword", "kubernetes.namespace": "keyword",
	"kubernetes.pod.name": "keyword", "kubernetes.container.name": "keyword", "http.request.method": "keyword",
	"http.response.status_code": "long", "url.path": "keyword", "event.duration": "long",
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/":
		w.Write([]byte(`{"name":"demo","cluster_name":"demo","version":{"number":"8.13.0"},"tagline":"You Know, for Search"}`))
	case strings.HasSuffix(r.URL.Path, "/_field_caps"):
		fields := map[string]any{}
		for name, typ := range fieldTypes {
			fields[name] = map[string]any{typ: map[string]any{"type": typ, "searchable": true, "aggregatable": typ != "text"}}
		}
		json.NewEncoder(w).Encode(map[string]any{"indices": []string{"logs-demo"}, "fields": fields})
	case strings.HasSuffix(r.URL.Path, "/_search") && r.Method == http.MethodPost:
		s.search(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index"}],"type":"index_not_found_exception","reason":"no such index"},"status":404}`))
	}
}

func fail(w http.ResponseWriter, reason string) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"type": "parsing_exception", "reason": reason,
		"root_cause": []any{map[string]any{"type": "parsing_exception", "reason": reason}}}, "status": 400})
}

// search is what Explore asks: a time range, a query string and terms
// filters; the newest documents and a date histogram, by terms or not,
// of a count or a statistic.
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Size  int `json:"size"`
		Query struct {
			Bool struct {
				Filter []map[string]map[string]any `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
		Aggs map[string]json.RawMessage `json:"aggs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, err.Error())
		return
	}
	now := s.now()
	from, to := now.Add(-keep).UnixMilli(), now.UnixMilli()
	var match []func(doc) bool
	for _, f := range body.Query.Bool.Filter {
		for kind, spec := range f {
			switch kind {
			case "range":
				for _, raw := range spec {
					bounds, _ := raw.(map[string]any)
					if v, ok := bounds["gte"].(float64); ok {
						from = max(from, int64(v))
					}
					if v, ok := bounds["lte"].(float64); ok {
						to = min(to, int64(v))
					}
				}
			case "query_string":
				q, _ := spec["query"].(string)
				m, err := parseQuery(q)
				if err != nil {
					fail(w, err.Error())
					return
				}
				match = append(match, m)
			case "terms":
				for field, raw := range spec {
					values := map[string]bool{}
					list, _ := raw.([]any)
					for _, v := range list {
						values[fmt.Sprint(v)] = true
					}
					match = append(match, func(d doc) bool { return values[d.flat[field]] })
				}
			}
		}
	}
	var docs []doc
	start := (from + every.Milliseconds() - 1) / every.Milliseconds() * every.Milliseconds()
	for t := start; t <= to; t += every.Milliseconds() {
		for _, p := range pods {
			d := makeDoc(time.UnixMilli(t), p.ns, p.pod)
			ok := true
			for _, m := range match {
				if !m(d) {
					ok = false
					break
				}
			}
			if ok {
				docs = append(docs, d)
			}
		}
	}
	out := map[string]any{"took": 1, "timed_out": false}
	hits := []any{}
	for i := len(docs) - 1; i >= 0 && len(hits) < body.Size; i-- {
		hits = append(hits, map[string]any{"_index": "logs-demo", "_id": strconv.FormatUint(noise(docs[i].t, docs[i].flat["kubernetes.pod.name"]), 36),
			"_source": docs[i].fields, "sort": []int64{docs[i].t}})
	}
	total := len(docs)
	relation := "eq"
	if total > 10000 {
		total, relation = 10000, "gte"
	}
	out["hits"] = map[string]any{"total": map[string]any{"value": total, "relation": relation}, "hits": hits}
	if len(body.Aggs) > 0 {
		aggs, err := aggregate(body.Aggs, docs)
		if err != nil {
			fail(w, err.Error())
			return
		}
		out["aggregations"] = aggs
	}
	json.NewEncoder(w).Encode(out)
}

func aggregate(specs map[string]json.RawMessage, docs []doc) (map[string]any, error) {
	out := map[string]any{}
	for name, raw := range specs {
		var spec map[string]json.RawMessage
		if err := json.Unmarshal(raw, &spec); err != nil {
			return nil, err
		}
		var sub map[string]json.RawMessage
		if s, ok := spec["aggs"]; ok {
			json.Unmarshal(s, &sub)
		}
		switch {
		case spec["date_histogram"] != nil:
			var h struct {
				Field          string `json:"field"`
				FixedInterval  string `json:"fixed_interval"`
				Interval       string `json:"interval"`
				Offset         string `json:"offset"`
				ExtendedBounds struct {
					Min, Max int64
				} `json:"extended_bounds"`
			}
			json.Unmarshal(spec["date_histogram"], &h)
			iv := h.FixedInterval
			if iv == "" {
				iv = h.Interval
			}
			ms, err := strconv.ParseInt(strings.TrimSuffix(iv, "ms"), 10, 64)
			if err != nil || ms <= 0 {
				return nil, fmt.Errorf("unsupported interval %q", iv)
			}
			var off int64
			if h.Offset != "" {
				if off, err = strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(h.Offset, "+"), "ms"), 10, 64); err != nil {
					return nil, fmt.Errorf("unsupported offset %q", h.Offset)
				}
			}
			bucket := func(t int64) int64 { return floorDiv(t-off, ms)*ms + off }
			byKey := map[int64][]doc{}
			for _, d := range docs {
				k := bucket(d.t)
				byKey[k] = append(byKey[k], d)
			}
			var buckets []any
			for k := bucket(h.ExtendedBounds.Min); k <= h.ExtendedBounds.Max; k += ms {
				b := map[string]any{"key": k, "doc_count": len(byKey[k])}
				if sub != nil {
					inner, err := aggregate(sub, byKey[k])
					if err != nil {
						return nil, err
					}
					for n, v := range inner {
						b[n] = v
					}
				}
				buckets = append(buckets, b)
			}
			out[name] = map[string]any{"buckets": buckets}
		case spec["terms"] != nil:
			var t struct {
				Field string `json:"field"`
				Size  int    `json:"size"`
			}
			json.Unmarshal(spec["terms"], &t)
			groups := map[string][]doc{}
			for _, d := range docs {
				if v, ok := d.flat[t.Field]; ok {
					groups[v] = append(groups[v], d)
				}
			}
			keys := make([]string, 0, len(groups))
			for k := range groups {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				if len(groups[keys[i]]) != len(groups[keys[j]]) {
					return len(groups[keys[i]]) > len(groups[keys[j]])
				}
				return keys[i] < keys[j]
			})
			var buckets []any
			for _, k := range keys[:min(len(keys), max(t.Size, 1))] {
				b := map[string]any{"key": k, "doc_count": len(groups[k])}
				if sub != nil {
					inner, err := aggregate(sub, groups[k])
					if err != nil {
						return nil, err
					}
					for n, v := range inner {
						b[n] = v
					}
				}
				buckets = append(buckets, b)
			}
			out[name] = map[string]any{"buckets": buckets}
		default:
			v, err := statistic(spec, docs)
			if err != nil {
				return nil, err
			}
			out[name] = v
		}
	}
	return out, nil
}

// statistic is avg, sum, min, max, cardinality or percentiles of a field.
func statistic(spec map[string]json.RawMessage, docs []doc) (any, error) {
	for kind, raw := range spec {
		var s struct {
			Field    string    `json:"field"`
			Percents []float64 `json:"percents"`
		}
		json.Unmarshal(raw, &s)
		var vals []float64
		distinct := map[string]bool{}
		for _, d := range docs {
			v, ok := d.flat[s.Field]
			if !ok {
				continue
			}
			distinct[v] = true
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				vals = append(vals, f)
			}
		}
		if kind == "cardinality" {
			return map[string]any{"value": len(distinct)}, nil
		}
		if kind == "percentiles" {
			values := map[string]any{}
			sort.Float64s(vals)
			for _, p := range s.Percents {
				key := strconv.FormatFloat(p, 'f', 1, 64)
				if len(vals) == 0 {
					values[key] = nil
					continue
				}
				values[key] = vals[min(len(vals)-1, int(math.Ceil(p/100*float64(len(vals))))-1+boolInt(p == 0))]
			}
			return map[string]any{"values": values}, nil
		}
		if len(vals) == 0 {
			return map[string]any{"value": nil}, nil
		}
		r := vals[0]
		sum := 0.0
		for _, v := range vals {
			sum += v
			switch kind {
			case "min":
				r = math.Min(r, v)
			case "max":
				r = math.Max(r, v)
			}
		}
		switch kind {
		case "avg":
			r = sum / float64(len(vals))
		case "sum":
			r = sum
		case "min", "max":
		default:
			return nil, fmt.Errorf("unsupported aggregation %q", kind)
		}
		return map[string]any{"value": r}, nil
	}
	return nil, fmt.Errorf("empty aggregation")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseQuery reads the Lucene query strings Explore sends, simply: terms
// joined by AND (or nothing) and OR, field:value or free text, with NOT
// or a leading minus, and * at the end of a value.
func parseQuery(q string) (func(doc) bool, error) {
	q = strings.TrimSpace(q)
	if q == "" || q == "*" {
		return func(doc) bool { return true }, nil
	}
	var alts []func(doc) bool
	for _, part := range strings.Split(q, " OR ") {
		var all []func(doc) bool
		words := tokens(part)
		for i := 0; i < len(words); i++ {
			w := words[i]
			if w == "AND" {
				continue
			}
			neg := false
			if w == "NOT" && i+1 < len(words) {
				neg, i = true, i+1
				w = words[i]
			} else if strings.HasPrefix(w, "-") && len(w) > 1 {
				neg, w = true, w[1:]
			}
			m := term(w)
			if neg {
				inner := m
				m = func(d doc) bool { return !inner(d) }
			}
			all = append(all, m)
		}
		alts = append(alts, func(d doc) bool {
			for _, m := range all {
				if !m(d) {
					return false
				}
			}
			return true
		})
	}
	return func(d doc) bool {
		for _, a := range alts {
			if a(d) {
				return true
			}
		}
		return false
	}, nil
}

// tokens splits on spaces outside quotes.
func tokens(s string) []string {
	var out []string
	var b strings.Builder
	quoted := false
	for _, c := range s {
		switch {
		case c == '"':
			quoted = !quoted
			b.WriteRune(c)
		case c == ' ' && !quoted:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func term(w string) func(doc) bool {
	field, value, ok := strings.Cut(w, ":")
	if !ok || strings.HasPrefix(field, "\"") {
		text := strings.ToLower(strings.Trim(w, "\""))
		return func(d doc) bool { return strings.Contains(strings.ToLower(d.flat["message"]), text) }
	}
	value = strings.Trim(value, "\"")
	if prefix, wild := strings.CutSuffix(value, "*"); wild {
		return func(d doc) bool { return strings.HasPrefix(d.flat[field], prefix) }
	}
	return func(d doc) bool {
		v := d.flat[field]
		if fieldTypes[field] == "text" {
			return strings.Contains(strings.ToLower(v), strings.ToLower(value))
		}
		return v == value
	}
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}
