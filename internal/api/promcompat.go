package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/query"
	"github.com/BerkeKartal/kartal-gozu/internal/tsdb"
)

// routePrometheus serves the metric store with the HTTP API of
// Prometheus, below /prometheus: Grafana, or any other client of it, can
// use the store as a Prometheus data source, with a user's token and what
// that user may see.
func (s *Server) routePrometheus(mux *http.ServeMux) {
	const p = promRoot
	for _, m := range []string{"GET ", "POST "} {
		mux.HandleFunc(m+p+"query", s.require(auth.Viewer, s.promQuery))
		mux.HandleFunc(m+p+"query_range", s.require(auth.Viewer, s.promQueryRange))
		mux.HandleFunc(m+p+"labels", s.require(auth.Viewer, s.promLabels))
		mux.HandleFunc(m+p+"series", s.require(auth.Viewer, s.promSeries))
	}
	mux.HandleFunc("GET "+p+"label/{name}/values", s.require(auth.Viewer, s.promLabelValues))
	mux.HandleFunc("GET "+p+"metadata", s.require(auth.Viewer, s.promMetadata))
	mux.HandleFunc("GET "+p+"status/buildinfo", s.require(auth.Viewer, s.promBuildInfo))
}

func promOK(w http.ResponseWriter, data any, warnings []string) {
	out := map[string]any{"status": "success", "data": data}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	writeJSON(w, http.StatusOK, out)
}

func promFail(w http.ResponseWriter, status int, kind string, err error) {
	writeJSON(w, status, map[string]string{"status": "error", "errorType": kind, "error": err.Error()})
}

// promTime reads a time as Prometheus takes it: Unix seconds or RFC 3339,
// in milliseconds.
func promTime(r *http.Request, name string, def int64) (int64, error) {
	v := r.FormValue(name)
	if v == "" {
		return def, nil
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && math.Abs(f) < 1e12 {
		return int64(math.Round(f * 1000)), nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", name, v)
	}
	return t.UnixMilli(), nil
}

// promStep reads a step: a duration such as 15s, or seconds.
func promStep(v string) (int64, error) {
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 1e9 {
		return int64(math.Round(f * 1000)), nil
	}
	d, err := query.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid step %q", v)
	}
	return d.Milliseconds(), nil
}

// promValue writes a value as Prometheus does: a string, NaN and the
// infinities by name.
func promValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func promPoint(ms int64, v float64) []any {
	return []any{float64(ms) / 1000, promValue(v)}
}

// promEval evaluates a query from start to end for the user.
func (s *Server) promEval(w http.ResponseWriter, r *http.Request, q string, start, end, step int64) (*query.Result, query.Expr, bool) {
	c := s.collector(w)
	if c == nil {
		return nil, nil, false
	}
	if q == "" || len(q) > maxQuery {
		promFail(w, http.StatusBadRequest, "bad_data", errors.New("give a query of up to 16 KiB"))
		return nil, nil, false
	}
	expr, err := query.Parse(q)
	if err != nil {
		promFail(w, http.StatusBadRequest, "bad_data", err)
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	res, err := query.NewEngine(c.DB()).RangeExpr(ctx, expr, start, end, step, sees(userOf(r)))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		promFail(w, http.StatusServiceUnavailable, "timeout", err)
	case err != nil:
		promFail(w, http.StatusUnprocessableEntity, "execution", err)
	default:
		return res, expr, true
	}
	return nil, nil, false
}

func (s *Server) promQueryRange(w http.ResponseWriter, r *http.Request) {
	start, err := promTime(r, "start", 0)
	var end, step int64
	if err == nil {
		end, err = promTime(r, "end", s.now().UnixMilli())
	}
	if err == nil {
		step, err = promStep(r.FormValue("step"))
	}
	if err != nil {
		promFail(w, http.StatusBadRequest, "bad_data", err)
		return
	}
	res, _, ok := s.promEval(w, r, r.FormValue("query"), start, end, step)
	if !ok {
		return
	}
	out := []map[string]any{}
	for _, series := range res.Series {
		values := [][]any{}
		for i, v := range series.Values.V {
			if series.Values.OK[i] {
				values = append(values, promPoint(res.Start+int64(i)*res.Step, v))
			}
		}
		out = append(out, map[string]any{"metric": series.Labels, "values": values})
	}
	promOK(w, map[string]any{"resultType": "matrix", "result": out}, res.Warnings)
}

func (s *Server) promQuery(w http.ResponseWriter, r *http.Request) {
	at, err := promTime(r, "time", s.now().UnixMilli())
	if err != nil {
		promFail(w, http.StatusBadRequest, "bad_data", err)
		return
	}
	res, expr, ok := s.promEval(w, r, r.FormValue("query"), at, at, 1)
	if !ok {
		return
	}
	if query.ResultType(expr) == "scalar" {
		v := math.NaN()
		if len(res.Series) > 0 {
			v = res.Series[0].Values.V[0]
		}
		promOK(w, map[string]any{"resultType": "scalar", "result": promPoint(at, v)}, res.Warnings)
		return
	}
	out := []map[string]any{}
	for _, series := range res.Series {
		out = append(out, map[string]any{"metric": series.Labels, "value": promPoint(at, series.Values.V[0])})
	}
	promOK(w, map[string]any{"resultType": "vector", "result": out}, res.Warnings)
}

// promSelector is the store's selection for match[] (all series without
// one) and the user.
func promSelectors(w http.ResponseWriter, r *http.Request) ([]tsdb.Selector, bool) {
	r.ParseForm()
	keep := sees(userOf(r))
	var out []tsdb.Selector
	for _, m := range r.Form["match[]"] {
		vs, err := query.ParseSelector(m)
		if err != nil {
			promFail(w, http.StatusBadRequest, "bad_data", err)
			return nil, false
		}
		out = append(out, tsdb.Selector{Matchers: vs.Matchers, Keep: keep})
	}
	if len(out) == 0 {
		out = append(out, tsdb.Selector{Keep: keep})
	}
	return out, true
}

// promRange reads start and end; without them, the last six hours.
func (s *Server) promRange(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	now := s.now().UnixMilli()
	start, err := promTime(r, "start", now-6*time.Hour.Milliseconds())
	var end int64
	if err == nil {
		end, err = promTime(r, "end", now)
	}
	if err != nil {
		promFail(w, http.StatusBadRequest, "bad_data", err)
		return 0, 0, false
	}
	return start, end, true
}

// promStrings gathers the names a list function finds for each selector.
func (s *Server) promStrings(w http.ResponseWriter, r *http.Request, list func(db *tsdb.DB, from, to int64, sel tsdb.Selector) ([]string, error)) {
	c := s.collector(w)
	if c == nil {
		return
	}
	from, to, ok := s.promRange(w, r)
	if !ok {
		return
	}
	sels, ok := promSelectors(w, r)
	if !ok {
		return
	}
	set := map[string]bool{}
	for _, sel := range sels {
		names, err := list(c.DB(), from, to, sel)
		if err != nil {
			promFail(w, http.StatusUnprocessableEntity, "execution", err)
			return
		}
		for _, n := range names {
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	promOK(w, out, nil)
}

func (s *Server) promLabels(w http.ResponseWriter, r *http.Request) {
	s.promStrings(w, r, func(db *tsdb.DB, from, to int64, sel tsdb.Selector) ([]string, error) {
		names, err := db.LabelNames(from, to, sel)
		return append(names, tsdb.MetricName), err
	})
}

func (s *Server) promLabelValues(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.promStrings(w, r, func(db *tsdb.DB, from, to int64, sel tsdb.Selector) ([]string, error) {
		return db.LabelValues(name, from, to, sel)
	})
}

func (s *Server) promSeries(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	from, to, ok := s.promRange(w, r)
	if !ok {
		return
	}
	sels, ok := promSelectors(w, r)
	if !ok {
		return
	}
	out := []map[string]string{}
	seen := map[string]bool{}
	for _, sel := range sels {
		series, err := c.DB().SeriesLabels(from, to, sel)
		if err != nil {
			promFail(w, http.StatusUnprocessableEntity, "execution", err)
			return
		}
		for _, ls := range series {
			if k := ls.String(); !seen[k] {
				seen[k] = true
				m := ls.Map()
				m[tsdb.MetricName] = ls.Get(tsdb.MetricName)
				out = append(out, m)
			}
		}
	}
	promOK(w, out, nil)
}

func (s *Server) promMetadata(w http.ResponseWriter, r *http.Request) {
	c := s.collector(w)
	if c == nil {
		return
	}
	now := s.now().UnixMilli()
	metrics, err := c.DB().Metrics(now-24*time.Hour.Milliseconds(), now, tsdb.Selector{Keep: sees(userOf(r))})
	if err != nil {
		promFail(w, http.StatusUnprocessableEntity, "execution", err)
		return
	}
	out := map[string][]map[string]string{}
	for _, m := range metrics {
		out[m.Name] = []map[string]string{{"type": m.Type, "help": "", "unit": ""}}
	}
	promOK(w, out, nil)
}

func (s *Server) promBuildInfo(w http.ResponseWriter, _ *http.Request) {
	promOK(w, map[string]string{"version": "kartal-gozu", "revision": "", "branch": "", "goVersion": ""}, nil)
}
