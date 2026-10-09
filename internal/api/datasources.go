package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/datasource"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// routeDataSources adds the Prometheus and Elasticsearch servers that
// Explore queries: admins set them up; everyone queries those they may.
func (s *Server) routeDataSources(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/datasources", s.require(auth.Viewer, s.dataSourceList))
	const set = "/api/v1/settings/datasources"
	mux.HandleFunc("GET "+set, s.requireEverywhere(auth.Admin, s.dataSourceSettings))
	mux.HandleFunc("POST "+set, s.requireEverywhere(auth.Admin, s.addDataSource))
	mux.HandleFunc("POST "+set+"/test", s.requireEverywhere(auth.Admin, s.testDataSource))
	mux.HandleFunc("PUT "+set+"/{id}", s.requireEverywhere(auth.Admin, s.changeDataSource))
	mux.HandleFunc("DELETE "+set+"/{id}", s.requireEverywhere(auth.Admin, s.removeDataSource))
	const d = "/api/v1/datasources/{id}"
	mux.HandleFunc("GET "+d+"/query_range", s.require(auth.Viewer, s.dsQueryRange))
	mux.HandleFunc("GET "+d+"/labels", s.require(auth.Viewer, s.dsLabels))
	mux.HandleFunc("GET "+d+"/labels/{name}/values", s.require(auth.Viewer, s.dsLabelValues))
	mux.HandleFunc("GET "+d+"/metrics", s.require(auth.Viewer, s.dsMetrics))
	mux.HandleFunc("POST "+d+"/series", s.require(auth.Viewer, s.dsSeries))
	mux.HandleFunc("POST "+d+"/logs", s.require(auth.Viewer, s.dsLogs))
	mux.HandleFunc("GET "+d+"/fields", s.require(auth.Viewer, s.dsFields))
}

// sourceTimeout bounds a query to a source, beyond the agent's own bound.
const sourceTimeout = 35 * time.Second

// promLabelName is a label's name, as Prometheus's API takes it in a path.
var promLabelName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const dataSourceFields = `{"name", "type", "url", "via", "cluster", "namespaceLabel", "auth", "username", "password", "token", "insecure", "interval", "index", "timeField", "messageField"}`

func (s *Server) dataSources(w http.ResponseWriter) *datasource.Manager {
	if s.cfg.DataSources == nil {
		writeError(w, http.StatusNotFound, "data sources are not available on this server")
	}
	return s.cfg.DataSources
}

var errSourceForAll = errors.New("this source is for people who see every cluster and namespace; an admin can tie it to a cluster to share it by namespace")

// sourceScope says what of a source a user may query: everything (nil),
// or the namespaces they see of its cluster.
func (s *Server) sourceScope(u auth.User, src settings.DataSource) ([]string, error) {
	if u.Everywhere() >= auth.Viewer {
		return nil, nil
	}
	if src.Cluster == "" {
		return nil, errSourceForAll
	}
	if u.RoleIn(src.Cluster, "") >= auth.Viewer {
		return nil, nil
	}
	var ns []string
	if ci, ok := s.st.Cluster(src.Cluster); ok && ci.Snapshot != nil {
		for _, n := range ci.Snapshot.Namespaces {
			if u.RoleIn(src.Cluster, n.Name) >= auth.Viewer {
				ns = append(ns, n.Name)
			}
		}
	}
	if len(ns) == 0 {
		return nil, datasource.ErrNoNamespace
	}
	return ns, nil
}

// sourceFor finds the source in the path, if the user may query it, with
// the namespaces they may (nil: all of it).
func (s *Server) sourceFor(w http.ResponseWriter, r *http.Request, typ string) (*datasource.Manager, settings.DataSource, []string, bool) {
	m := s.dataSources(w)
	if m == nil {
		return nil, settings.DataSource{}, nil, false
	}
	src, ok := m.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, datasource.ErrNotFound.Error())
		return nil, src, nil, false
	}
	scope, err := s.sourceScope(userOf(r), src)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return nil, src, nil, false
	}
	if typ != "" && src.Type != typ {
		writeError(w, http.StatusBadRequest, src.Name+" is not "+typ)
		return nil, src, nil, false
	}
	return m, src, scope, true
}

// sourceError answers for a query that failed: the source's own refusal,
// or not reaching it.
func sourceError(w http.ResponseWriter, err error) {
	var e *datasource.Error
	var q *datasource.QueryError
	switch {
	case errors.As(err, &q):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "the source did not answer in time")
	case errors.As(err, &e) && e.Status/100 == 4:
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusBadGateway, err.Error())
	}
}

// Public is a source as everyone who may query it sees it.
type Public struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Interval     int    `json:"interval,omitempty"`
	Index        string `json:"index,omitempty"`
	TimeField    string `json:"timeField,omitempty"`
	MessageField string `json:"messageField,omitempty"`
}

func (s *Server) dataSourceList(w http.ResponseWriter, r *http.Request) {
	m := s.dataSources(w)
	if m == nil {
		return
	}
	u := userOf(r)
	out := []Public{}
	for _, d := range m.List() {
		if _, err := s.sourceScope(u, d); err != nil {
			continue
		}
		p := Public{ID: d.ID, Name: d.Name, Type: d.Type, Index: d.Index, TimeField: d.TimeField, MessageField: d.MessageField}
		if d.Type == settings.SourcePrometheus {
			p.Interval = d.EffectiveInterval()
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dataSourceSettings(w http.ResponseWriter, _ *http.Request) {
	m := s.dataSources(w)
	if m == nil {
		return
	}
	views := []datasource.View{}
	for _, d := range m.List() {
		views = append(views, datasource.ViewOf(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": views, "where": m.Where(), "loadError": m.LoadError()})
}

// readDataSource reads a source from the body; the clusters it names
// must exist.
func (s *Server) readDataSource(w http.ResponseWriter, r *http.Request) (settings.DataSource, bool) {
	var d settings.DataSource
	if !readJSON(w, r, &d, dataSourceFields) {
		return d, false
	}
	for _, c := range []string{d.Via, d.Cluster} {
		if c == "" {
			continue
		}
		if _, ok := s.st.Cluster(c); !ok {
			writeError(w, http.StatusBadRequest, "there is no cluster "+c)
			return d, false
		}
	}
	return d, true
}

// dataSourceError answers for a change that failed; it reports whether
// one did.
func dataSourceError(w http.ResponseWriter, err error) bool {
	var invalid *settings.InvalidError
	switch {
	case err == nil:
		return false
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, datasource.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "the data sources could not be saved: "+err.Error())
	}
	return true
}

func (s *Server) noteDataSource(r *http.Request, action string, d settings.DataSource, err error) {
	var invalid *settings.InvalidError
	if errors.As(err, &invalid) || errors.Is(err, datasource.ErrNotFound) {
		return
	}
	s.note(r, action, "datasource/"+d.Name, d.Type+" "+d.URL, err)
}

func (s *Server) addDataSource(w http.ResponseWriter, r *http.Request) {
	m := s.dataSources(w)
	if m == nil {
		return
	}
	d, ok := s.readDataSource(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Add(ctx, d)
	s.noteDataSource(r, "add-datasource", saved, err)
	if !dataSourceError(w, err) {
		writeJSON(w, http.StatusCreated, datasource.ViewOf(saved))
	}
}

func (s *Server) changeDataSource(w http.ResponseWriter, r *http.Request) {
	m := s.dataSources(w)
	if m == nil {
		return
	}
	d, ok := s.readDataSource(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	saved, err := m.Change(ctx, r.PathValue("id"), d)
	s.noteDataSource(r, "change-datasource", saved, err)
	if !dataSourceError(w, err) {
		writeJSON(w, http.StatusOK, datasource.ViewOf(saved))
	}
}

func (s *Server) removeDataSource(w http.ResponseWriter, r *http.Request) {
	m := s.dataSources(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	gone, err := m.Remove(ctx, r.PathValue("id"))
	s.noteDataSource(r, "remove-datasource", gone, err)
	if !dataSourceError(w, err) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "removed " + gone.Name})
	}
}

// testDataSource asks a source, as the body sets it up, what it is, before
// anyone relies on it. With the ID of a saved source, an empty password or
// token is the saved one.
func (s *Server) testDataSource(w http.ResponseWriter, r *http.Request) {
	m := s.dataSources(w)
	if m == nil {
		return
	}
	var d settings.DataSource
	if !readJSON(w, r, &d, `{"id", `+dataSourceFields[1:]) {
		return
	}
	if err := m.Complete(&d); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := d.Normalize(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if d.Via != "" {
		if _, ok := s.st.Cluster(d.Via); !ok {
			writeError(w, http.StatusBadRequest, "there is no cluster "+d.Via)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	version, err := m.Client.Test(ctx, d)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
}

func (s *Server) dsQueryRange(w http.ResponseWriter, r *http.Request) {
	m, src, scope, ok := s.sourceFor(w, r, settings.SourcePrometheus)
	if !ok {
		return
	}
	q := r.URL.Query().Get("query")
	if q == "" || len(q) > maxQuery {
		writeError(w, http.StatusBadRequest, "give a query of up to 16 KiB")
		return
	}
	now := s.now().UnixMilli()
	end, err := msParam(r, "end", now)
	var start, step int64
	if err == nil {
		start, err = msParam(r, "start", end-time.Hour.Milliseconds())
	}
	if err == nil {
		step, err = msParam(r, "step", max(1000, (end-start)/300/1000*1000))
	}
	if err == nil && scope != nil {
		q, err = datasource.ScopePromQL(q, src.NamespaceLabel, scope)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sourceTimeout)
	defer cancel()
	res, err := m.Client.PromRange(ctx, src, q, start, end, step)
	if err != nil {
		sourceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// sourceMatch is ?match= narrowed to the namespaces the user may see.
func sourceMatch(w http.ResponseWriter, r *http.Request, src settings.DataSource, scope []string) (string, bool) {
	match := r.URL.Query().Get("match")
	if scope == nil {
		return match, true
	}
	m, err := datasource.ScopeMatch(match, src.NamespaceLabel, scope)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return m, true
}

func (s *Server) dsLabels(w http.ResponseWriter, r *http.Request) {
	s.dsList(w, r, func(ctx context.Context, m *datasource.Manager, src settings.DataSource, match string, from, to int64) (any, error) {
		return m.Client.PromLabels(ctx, src, match, from, to)
	})
}

func (s *Server) dsLabelValues(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !promLabelName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid label name "+strconv.Quote(name))
		return
	}
	s.dsList(w, r, func(ctx context.Context, m *datasource.Manager, src settings.DataSource, match string, from, to int64) (any, error) {
		return m.Client.PromLabelValues(ctx, src, name, match, from, to)
	})
}

func (s *Server) dsMetrics(w http.ResponseWriter, r *http.Request) {
	s.dsList(w, r, func(ctx context.Context, m *datasource.Manager, src settings.DataSource, match string, from, to int64) (any, error) {
		return m.Client.PromMetrics(ctx, src, match, from, to)
	})
}

func (s *Server) dsList(w http.ResponseWriter, r *http.Request, list func(context.Context, *datasource.Manager, settings.DataSource, string, int64, int64) (any, error)) {
	m, src, scope, ok := s.sourceFor(w, r, settings.SourcePrometheus)
	if !ok {
		return
	}
	from, to, err := timeRange(r, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	match, ok := sourceMatch(w, r, src, scope)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sourceTimeout)
	defer cancel()
	out, err := list(ctx, m, src, match, from, to)
	if err != nil {
		sourceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dsSeries(w http.ResponseWriter, r *http.Request) {
	m, src, scope, ok := s.sourceFor(w, r, settings.SourceElasticsearch)
	if !ok {
		return
	}
	var q datasource.ESQuery
	if !readJSON(w, r, &q, `{"index", "query", "metric", "field", "groupBy", "size", "start", "end", "step"}`) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sourceTimeout)
	defer cancel()
	res, err := m.Client.ESSeries(ctx, src, q, scope)
	if err != nil {
		sourceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) dsLogs(w http.ResponseWriter, r *http.Request) {
	m, src, scope, ok := s.sourceFor(w, r, settings.SourceElasticsearch)
	if !ok {
		return
	}
	var q datasource.ESLogsQuery
	if !readJSON(w, r, &q, `{"index", "query", "size", "start", "end", "step"}`) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sourceTimeout)
	defer cancel()
	logs, err := m.Client.ESLogs(ctx, src, q, scope)
	if err != nil {
		sourceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func (s *Server) dsFields(w http.ResponseWriter, r *http.Request) {
	m, src, _, ok := s.sourceFor(w, r, settings.SourceElasticsearch)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sourceTimeout)
	defer cancel()
	fields, err := m.Client.ESFields(ctx, src, r.URL.Query().Get("index"))
	if err != nil {
		sourceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fields)
}
