package api

// The MCP endpoint lets AI assistants and agents use Kartal Gözü through the
// Model Context Protocol: Streamable HTTP, answered with JSON, without
// sessions. It takes the tokens of the REST API, and every tool is a call
// of that API made inside the server for the caller, so a tool sees and
// may do exactly what the caller's token may: a viewer gets the tools that
// read, an operator the actions too, and an admin also runs commands in
// containers and saves objects' YAML. Actions go to the audit log as made
// through MCP.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

const mcpPath = "/api/v1/mcp"

// mcpVersions are the protocol versions the endpoint speaks, newest first.
var mcpVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

const (
	maxMCPBody = 1 << 20
	// maxToolText is how much of an answer a tool returns; the rest is cut,
	// with a word on how to ask for less.
	maxToolText = 100_000
)

const mcpInstructions = `Kartal Gözü watches Kubernetes clusters through an agent in each.
Start with list_clusters, then list_objects with problems=true to find what needs attention, and pod_logs, object_events and get_resource to see why.
Lists come from each agent's latest snapshot, a few seconds old; get_resource, pod_logs, object_events and rollout_history ask the cluster live.
Actions (restart, scale, rollback, deleting a pod, cordoning a node, running or suspending a CronJob) need the operator role where they act, and the cluster's agent must allow changes ("write" among its capabilities in list_clusters).
Running a command in a container (exec_in_pod) and saving an object (edit_resource) need the admin role where they act, and the agent's "exec" or "edit" capability. Save with edit_resource only after a dry run the person has seen.
Every action is written to the audit log with your user's name. Ask the person you work for before you change anything.`

// viaKey marks the requests the MCP endpoint makes for its tools.
type viaKey struct{}

// via says through what a request came: "mcp" for a tool's call.
func via(r *http.Request) string {
	v, _ := r.Context().Value(viaKey{}).(string)
	return v
}

func (s *Server) routeMCP(mux *http.ServeMux) {
	mux.HandleFunc("POST "+mcpPath, s.require(auth.Viewer, s.mcp))
	// No stream for the server's own messages, and no session to end.
	other := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "this MCP endpoint answers JSON-RPC messages POSTed to it, with JSON; it keeps no stream and no session")
	}
	mux.HandleFunc("GET "+mcpPath, other)
	mux.HandleFunc("DELETE "+mcpPath, other)
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcNoMethod       = -32601
	rpcInvalidParams  = -32602
)

func rpcReply(w http.ResponseWriter, status int, id json.RawMessage, result any, e *rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		body["error"] = e
	} else {
		body["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	// A page of another site must not reach the server through a browser
	// that can (DNS rebinding); clients that are not browsers send no Origin.
	if o := r.Header.Get("Origin"); o != "" && !sameHost(o, r) {
		writeError(w, http.StatusForbidden, "requests from another site's pages are not accepted")
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(mcpVersions, v) {
		writeError(w, http.StatusBadRequest, "MCP-Protocol-Version "+v+" is not supported; this server speaks "+strings.Join(mcpVersions, ", "))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMCPBody))
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		rpcReply(w, status, nil, nil, &rpcError{rpcParseError, "the message could not be read: " + err.Error()})
		return
	}
	body = bytes.TrimSpace(body)
	switch {
	case len(body) > 0 && body[0] == '[':
		rpcReply(w, http.StatusBadRequest, nil, nil, &rpcError{rpcInvalidRequest, "batches are not supported: send one message a request"})
		return
	case len(body) > 0 && body[0] != '{' && json.Valid(body):
		rpcReply(w, http.StatusBadRequest, nil, nil, &rpcError{rpcInvalidRequest, "a message is a JSON object"})
		return
	}
	var m rpcMessage
	if err := json.Unmarshal(body, &m); err != nil {
		rpcReply(w, http.StatusBadRequest, nil, nil, &rpcError{rpcParseError, "not a JSON-RPC message: " + err.Error()})
		return
	}
	if m.JSONRPC != "2.0" {
		rpcReply(w, http.StatusBadRequest, m.ID, nil, &rpcError{rpcInvalidRequest, `"jsonrpc" must be "2.0"`})
		return
	}
	// Notifications, and the client's answers, need no answer.
	if m.Method == "" || len(m.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	u := userOf(r)
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		v := mcpVersions[0]
		if slices.Contains(mcpVersions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		version := s.cfg.Version
		if version == "" {
			version = "dev"
		}
		rpcReply(w, http.StatusOK, m.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "kartal-gozu", "title": "Kartal Gözü", "version": version},
			"instructions":    mcpInstructions,
		}, nil)
	case "ping":
		rpcReply(w, http.StatusOK, m.ID, map[string]any{}, nil)
	case "tools/list":
		list := []map[string]any{}
		for _, t := range mcpTools {
			if u.Role >= t.role {
				list = append(list, t.describe())
			}
		}
		rpcReply(w, http.StatusOK, m.ID, map[string]any{"tools": list}, nil)
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			rpcReply(w, http.StatusOK, m.ID, nil, &rpcError{rpcInvalidParams, "params must be {\"name\": ..., \"arguments\": {...}}"})
			return
		}
		t := toolNamed(p.Name)
		if t == nil {
			rpcReply(w, http.StatusOK, m.ID, nil, &rpcError{rpcInvalidParams, "unknown tool: " + p.Name})
			return
		}
		rpcReply(w, http.StatusOK, m.ID, s.callTool(r, t, p.Arguments), nil)
	default:
		rpcReply(w, http.StatusOK, m.ID, nil, &rpcError{rpcNoMethod, "method not found: " + m.Method})
	}
}

// sameHost tells whether an Origin is the server's own site, as the
// request addresses it directly or through a proxy.
func sameHost(origin string, r *http.Request) bool {
	o, err := url.Parse(origin)
	if err != nil || o.Host == "" {
		return false
	}
	for _, h := range []string{r.Host, r.Header.Get("X-Forwarded-Host")} {
		if h != "" && strings.EqualFold(o.Host, strings.TrimSpace(strings.Split(h, ",")[0])) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- tools

type toolResult struct {
	Content []toolText `json:"content"`
	IsError bool       `json:"isError,omitempty"`
}

type toolText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func toolFailed(msg string) toolResult {
	return toolResult{Content: []toolText{{Type: "text", Text: msg}}, IsError: true}
}

// toolArg is one argument of a tool.
type toolArg struct {
	name, typ, doc string // typ: "string", "integer" or "boolean"
	required       bool
	enum           []string
	min, max       int // for integers, when max > min
}

type tool struct {
	name, title, doc              string
	role                          auth.Role
	args                          []toolArg
	readOnly, destructive, repeat bool
	// call is the REST call the arguments make; an error is the caller's.
	call func(a toolArgs) (method, target string, body any, err error)
}

func toolNamed(name string) *tool {
	for i := range mcpTools {
		if mcpTools[i].name == name {
			return &mcpTools[i]
		}
	}
	return nil
}

// describe is the tool as tools/list tells it.
func (t *tool) describe() map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, a := range t.args {
		p := map[string]any{"type": a.typ, "description": a.doc}
		if len(a.enum) > 0 {
			p["enum"] = a.enum
		}
		if a.max > a.min {
			p["minimum"], p["maximum"] = a.min, a.max
		}
		props[a.name] = p
		if a.required {
			required = append(required, a.name)
		}
	}
	return map[string]any{
		"name": t.name, "title": t.title, "description": t.doc,
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false},
		"annotations": map[string]any{"title": t.title, "readOnlyHint": t.readOnly, "destructiveHint": t.destructive,
			"idempotentHint": t.repeat, "openWorldHint": false},
	}
}

// toolArgs are a call's arguments, checked against the tool's.
type toolArgs map[string]any

func (a toolArgs) str(name string) string {
	s, _ := a[name].(string)
	return s
}

func (a toolArgs) num(name string) int {
	n, _ := a[name].(int)
	return n
}

func (a toolArgs) flag(name string) bool {
	b, _ := a[name].(bool)
	return b
}

func (a toolArgs) has(name string) bool {
	_, ok := a[name]
	return ok
}

// check reads the arguments as the tool declares them: strings, whole
// numbers (as int) and booleans.
func (t *tool) check(raw map[string]any) (toolArgs, error) {
	out := toolArgs{}
	for _, a := range t.args {
		v, ok := raw[a.name]
		if !ok || v == nil {
			if a.required {
				return nil, fmt.Errorf("%s is required", a.name)
			}
			continue
		}
		switch a.typ {
		case "string":
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string", a.name)
			}
			if s = strings.TrimSpace(s); s == "" {
				if a.required {
					return nil, fmt.Errorf("%s is required", a.name)
				}
				continue
			}
			if len(a.enum) > 0 {
				i := slices.IndexFunc(a.enum, func(e string) bool { return strings.EqualFold(e, s) })
				if i < 0 {
					return nil, fmt.Errorf("%s must be one of %s", a.name, strings.Join(a.enum, ", "))
				}
				s = a.enum[i]
			}
			out[a.name] = s
		case "integer":
			f, ok := v.(float64)
			if !ok || f != math.Trunc(f) || math.Abs(f) > 1<<31 {
				return nil, fmt.Errorf("%s must be a whole number", a.name)
			}
			n := int(f)
			if a.max > a.min && (n < a.min || n > a.max) {
				return nil, fmt.Errorf("%s must be between %d and %d", a.name, a.min, a.max)
			}
			out[a.name] = n
		case "boolean":
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("%s must be true or false", a.name)
			}
			out[a.name] = b
		}
	}
	for name := range raw {
		if !slices.ContainsFunc(t.args, func(a toolArg) bool { return a.name == name }) {
			return nil, fmt.Errorf("%s takes no argument %q", t.name, name)
		}
	}
	return out, nil
}

// callTool runs a tool: its REST call, made inside the server with the
// caller's token.
func (s *Server) callTool(r *http.Request, t *tool, raw map[string]any) toolResult {
	a, err := t.check(raw)
	if err != nil {
		return toolFailed(err.Error())
	}
	if u := userOf(r); u.Role < t.role {
		return toolFailed("this needs the " + t.role.String() + " role; you have " + u.Role.String())
	}
	method, target, body, err := t.call(a)
	if err != nil {
		return toolFailed(err.Error())
	}
	rd, contentType := io.Reader(http.NoBody), ""
	if y, ok := body.(yamlBody); ok {
		rd, contentType = strings.NewReader(string(y)), "application/yaml"
	} else if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return toolFailed(err.Error())
		}
		rd, contentType = bytes.NewReader(b), "application/json"
	}
	req, err := http.NewRequestWithContext(context.WithValue(r.Context(), viaKey{}, "mcp"), method, target, rd)
	if err != nil {
		return toolFailed(err.Error())
	}
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.RemoteAddr, req.Host = r.RemoteAddr, r.Host
	rec := &toolResponse{header: http.Header{}, status: http.StatusOK}
	s.handler.ServeHTTP(rec, req)
	// What an assistant asked is logged, at the level a request with the
	// same answer is: the endpoint itself answers 200 even when a tool fails.
	level := slog.LevelInfo
	switch {
	case rec.status >= 500:
		level = slog.LevelError
	case rec.status >= 400:
		level = slog.LevelWarn
	}
	s.log.Log(r.Context(), level, "mcp tool", "user", userOf(r).Name, "tool", t.name, "method", method, "path", req.URL.Path,
		"status", rec.status, "bytes", rec.total)
	if rec.status/100 != 2 {
		msg := rec.body.String()
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(rec.body.Bytes(), &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return toolFailed(fmt.Sprintf("%d %s: %s", rec.status, http.StatusText(rec.status), msg))
	}
	return toolResult{Content: []toolText{{Type: "text", Text: rec.text()}}}
}

// toolResponse keeps what a tool's REST call answers, up to maxToolText.
type toolResponse struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
	total  int
}

func (t *toolResponse) Header() http.Header { return t.header }

func (t *toolResponse) WriteHeader(code int) {
	if !t.wrote {
		t.status, t.wrote = code, true
	}
}

func (t *toolResponse) Write(p []byte) (int, error) {
	t.WriteHeader(http.StatusOK)
	t.total += len(p)
	if room := maxToolText - t.body.Len(); room > 0 {
		t.body.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (t *toolResponse) text() string {
	s := t.body.String()
	if t.total <= len(s) {
		return s
	}
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + fmt.Sprintf("\n\n[cut: the first %d of %d bytes; ask for less, such as one namespace, problems=true or fewer log lines]", len(s), t.total)
}

// ---------------------------------------------------------------- the tools' REST calls

// yamlBody is a tool's body sent as it is, as YAML, rather than as JSON.
type yamlBody string

// hasResourceVersion tells whether an object's YAML or JSON keeps
// metadata.resourceVersion, which makes the API server refuse to save over
// a newer version of the object.
var hasResourceVersion = regexp.MustCompile(`"?resourceVersion"?\s*:\s*['"]?[0-9]`)

func seg(s string) string { return url.PathEscape(s) }

func clusterURL(a toolArgs) string { return "/api/v1/clusters/" + seg(a.str("cluster")) }

func withQuery(path string, q url.Values) string {
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// set adds the arguments given to a query, under their own names.
func set(q url.Values, a toolArgs, names ...string) url.Values {
	for _, n := range names {
		switch v := a[n].(type) {
		case string:
			q.Set(n, v)
		case int:
			q.Set(n, strconv.Itoa(v))
		case bool:
			q.Set(n, strconv.FormatBool(v))
		}
	}
	return q
}

// mcpKinds are the types tools name by kind, with their API path.
var mcpKinds = []struct{ kind, gvr, short string }{
	{"Pod", "core/v1/pods", "po"}, {"Service", "core/v1/services", "svc"}, {"ConfigMap", "core/v1/configmaps", "cm"},
	{"Secret", "core/v1/secrets", ""}, {"Node", "core/v1/nodes", "no"}, {"Namespace", "core/v1/namespaces", "ns"},
	{"PersistentVolumeClaim", "core/v1/persistentvolumeclaims", "pvc"}, {"PersistentVolume", "core/v1/persistentvolumes", "pv"},
	{"ServiceAccount", "core/v1/serviceaccounts", "sa"}, {"Event", "core/v1/events", "ev"}, {"Endpoints", "core/v1/endpoints", "ep"},
	{"Deployment", "apps/v1/deployments", "deploy"}, {"StatefulSet", "apps/v1/statefulsets", "sts"},
	{"DaemonSet", "apps/v1/daemonsets", "ds"}, {"ReplicaSet", "apps/v1/replicasets", "rs"},
	{"Job", "batch/v1/jobs", ""}, {"CronJob", "batch/v1/cronjobs", "cj"},
	{"Ingress", "networking.k8s.io/v1/ingresses", "ing"}, {"NetworkPolicy", "networking.k8s.io/v1/networkpolicies", "netpol"},
	{"HorizontalPodAutoscaler", "autoscaling/v2/horizontalpodautoscalers", "hpa"},
	{"PodDisruptionBudget", "policy/v1/poddisruptionbudgets", "pdb"}, {"StorageClass", "storage.k8s.io/v1/storageclasses", "sc"},
	{"Role", "rbac.authorization.k8s.io/v1/roles", ""}, {"RoleBinding", "rbac.authorization.k8s.io/v1/rolebindings", ""},
	{"ClusterRole", "rbac.authorization.k8s.io/v1/clusterroles", ""},
	{"ClusterRoleBinding", "rbac.authorization.k8s.io/v1/clusterrolebindings", ""},
	{"IngressRoute", "traefik.io/v1alpha1/ingressroutes", ""},
}

// resolveKind reads a kind ("Deployment", "deployments", "deploy") or an
// API path ("traefik.io/v1alpha1/middlewares", "v1/pods").
func resolveKind(s string) (kind, gvr string, err error) {
	s = strings.TrimSpace(s)
	for _, k := range mcpKinds {
		plural := k.gvr[strings.LastIndex(k.gvr, "/")+1:]
		if strings.EqualFold(s, k.kind) || strings.EqualFold(s, plural) || (k.short != "" && strings.EqualFold(s, k.short)) {
			return k.kind, k.gvr, nil
		}
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) == 2 {
		parts = append([]string{"core"}, parts...)
	}
	if len(parts) == 3 && parts[1] != "" && parts[2] != "" {
		return "", strings.Join(parts, "/"), nil
	}
	return "", "", fmt.Errorf("unknown kind %q: give a kind such as Deployment, or the type's group/version/resource such as traefik.io/v1alpha1/middlewares", s)
}

const (
	clusterDoc   = "The cluster's name, as list_clusters gives it."
	namespaceDoc = "The namespace."
)

func clusterArg() toolArg {
	return toolArg{name: "cluster", typ: "string", doc: clusterDoc, required: true}
}
func namespaceArg() toolArg {
	return toolArg{name: "namespace", typ: "string", doc: namespaceDoc, required: true}
}

var listKinds = []string{"nodes", "namespaces", "workloads", "pods", "services", "ingresses", "configmaps", "secrets",
	"certificates", "volumeclaims", "jobs", "cronjobs", "events"}

var mcpTools = []tool{
	{
		name: "list_clusters", title: "List clusters", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "The clusters you may see: whether their agent is online, the Kubernetes and agent versions, capacity, requests and usage, " +
			"counts of objects and of problems, the actions their agent allows (capabilities) and how many alerts are active. Start here.",
		call: func(toolArgs) (string, string, any, error) { return http.MethodGet, "/api/v1/clusters", nil, nil },
	},
	{
		name: "list_objects", title: "List objects", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "One kind of object in a cluster, from its agent's latest snapshot: names and status, not full specs. " +
			"problems=true keeps only what needs attention (for nodes, workloads, pods, volumeclaims, certificates and jobs). " +
			"Workloads are the Deployments, StatefulSets and DaemonSets. Secrets are listed by name; their values are never read.",
		args: []toolArg{clusterArg(),
			{name: "kind", typ: "string", doc: "What to list.", required: true, enum: listKinds},
			{name: "namespace", typ: "string", doc: "Only this namespace; all of those you may see without it."},
			{name: "problems", typ: "boolean", doc: "Only what needs attention."}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodGet, withQuery(clusterURL(a)+"/"+a.str("kind"), set(url.Values{}, a, "namespace", "problems")), nil, nil
		},
	},
	{
		name: "get_resource", title: "Get an object", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "An object's full contents (with a name), or every object of a type (without), of any type including CRDs, asked from the cluster now. " +
			"Secrets come with their values left out.",
		args: []toolArg{clusterArg(),
			{name: "kind", typ: "string", required: true, doc: "A kind such as Deployment, Pod, ConfigMap, HorizontalPodAutoscaler or IngressRoute (also plurals and kubectl's short names), " +
				"or any type as group/version/resource, such as traefik.io/v1alpha1/middlewares or v1/pods."},
			{name: "name", typ: "string", doc: "The object's name; without it, the list."},
			{name: "namespace", typ: "string", doc: "The object's namespace; leave it out for cluster-wide types, or to list in every namespace."}},
		call: func(a toolArgs) (string, string, any, error) {
			_, gvr, err := resolveKind(a.str("kind"))
			if err != nil {
				return "", "", nil, err
			}
			parts := strings.Split(gvr, "/")
			path := clusterURL(a) + "/resources/" + seg(parts[0]) + "/" + seg(parts[1]) + "/" + seg(parts[2])
			if a.has("name") {
				path += "/" + seg(a.str("name"))
			}
			return http.MethodGet, withQuery(path, set(url.Values{}, a, "namespace")), nil, nil
		},
	},
	{
		name: "pod_logs", title: "Read a pod's logs", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "The last lines a pod's container wrote. previous=true reads the container that ran before the last restart, which tells why it crashed.",
		args: []toolArg{clusterArg(), namespaceArg(),
			{name: "pod", typ: "string", doc: "The pod's name.", required: true},
			{name: "container", typ: "string", doc: "The container; needed when the pod has several."},
			{name: "tail", typ: "integer", doc: "How many of the last lines (200 when left out).", min: 1, max: 5000},
			{name: "previous", typ: "boolean", doc: "Read the container that ran before the last restart."}},
		call: func(a toolArgs) (string, string, any, error) {
			if !a.has("tail") {
				a["tail"] = 200
			}
			path := clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/pods/" + seg(a.str("pod")) + "/logs"
			return http.MethodGet, withQuery(path, set(url.Values{}, a, "container", "tail", "previous")), nil, nil
		},
	},
	{
		name: "object_events", title: "Events of an object", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "Every event about one object, newest first: why a pod does not start, a node's trouble, a failed mount. Asked from the cluster now.",
		args: []toolArg{clusterArg(),
			{name: "kind", typ: "string", doc: "The object's kind, such as Pod, Deployment or Node.", required: true},
			{name: "name", typ: "string", doc: "The object's name.", required: true},
			{name: "namespace", typ: "string", doc: "The object's namespace; leave it out for a node."}},
		call: func(a toolArgs) (string, string, any, error) {
			kind, _, err := resolveKind(a.str("kind"))
			if kind == "" {
				if err == nil {
					err = fmt.Errorf("give the object's kind, such as Pod, not a type's path")
				}
				return "", "", nil, err
			}
			q := set(url.Values{"kind": {kind}}, a, "name", "namespace")
			return http.MethodGet, withQuery(clusterURL(a)+"/object-events", q), nil, nil
		},
	},
	{
		name: "rollout_history", title: "A Deployment's revisions", role: auth.Viewer, readOnly: true, repeat: true,
		doc:  "A Deployment's revisions with their images, change cause and readiness; rollback_deployment takes one of their numbers.",
		args: []toolArg{clusterArg(), namespaceArg(), {name: "name", typ: "string", doc: "The Deployment's name.", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodGet, clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/deployments/" + seg(a.str("name")) + "/history", nil, nil
		},
	},
	{
		name: "list_alerts", title: "List alerts", role: auth.Viewer, readOnly: true, repeat: true,
		doc:  "The active and recently resolved problems of every cluster you may see (a node not ready, a pod crash-looping, a volume filling up, a rollout stuck...), the notification channels, silences and log rules.",
		call: func(toolArgs) (string, string, any, error) { return http.MethodGet, "/api/v1/alerts", nil, nil },
	},
	{
		name: "list_changes", title: "What changed", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "What changed in the clusters, newest first: workloads created or deleted, new images, scaling, restarts, nodes cordoned or not ready. " +
			"The first thing to look at when something broke after it had worked.",
		args: []toolArg{{name: "cluster", typ: "string", doc: "Only this cluster."}, {name: "namespace", typ: "string", doc: "Only this namespace."},
			{name: "kind", typ: "string", doc: "Only objects of this kind, such as Deployment."}, {name: "name", typ: "string", doc: "Only objects of this name."},
			{name: "limit", typ: "integer", doc: "How many (100 when left out).", min: 1, max: 2000}},
		call: func(a toolArgs) (string, string, any, error) {
			if !a.has("limit") {
				a["limit"] = 100
			}
			return http.MethodGet, withQuery("/api/v1/changes", set(url.Values{}, a, "cluster", "namespace", "kind", "name", "limit")), nil, nil
		},
	},
	{
		name: "list_rollouts", title: "List rollouts", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "Each new version of a workload, newest first: from which image to which, how long it took, and whether it is stuck and why.",
		args: []toolArg{{name: "cluster", typ: "string", doc: "Only this cluster."}, {name: "namespace", typ: "string", doc: "Only this namespace."},
			{name: "state", typ: "string", doc: "Only rollouts in this state.", enum: []string{"progressing", "done", "stuck", "replaced", "deleted"}},
			{name: "limit", typ: "integer", doc: "How many (50 when left out).", min: 1, max: 2000}},
		call: func(a toolArgs) (string, string, any, error) {
			if !a.has("limit") {
				a["limit"] = 50
			}
			return http.MethodGet, withQuery("/api/v1/rollouts", set(url.Values{}, a, "cluster", "namespace", "state", "limit")), nil, nil
		},
	},
	{
		name: "app_versions", title: "Apps' versions", role: auth.Viewer, readOnly: true, repeat: true,
		doc:  "Every workload in every cluster with its images and readiness, to compare an app's versions between clusters such as test and production.",
		call: func(toolArgs) (string, string, any, error) { return http.MethodGet, "/api/v1/releases", nil, nil },
	},
	{
		name: "helm_releases", title: "Helm releases", role: auth.Viewer, readOnly: true, repeat: true,
		doc:  "A cluster's Helm releases with their chart, version and status (never their values).",
		args: []toolArg{clusterArg()},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodGet, clusterURL(a) + "/helm", nil, nil
		},
	},
	{
		name: "resource_usage", title: "CPU and memory use", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "The CPU and memory used by a cluster, a node or a pod over the last hours, a point a minute (needs metrics-server in the cluster).",
		args: []toolArg{clusterArg(),
			{name: "kind", typ: "string", doc: "Whose use (cluster when left out).", enum: []string{"cluster", "node", "pod"}},
			{name: "name", typ: "string", doc: "The node's or the pod's name."},
			{name: "namespace", typ: "string", doc: "The pod's namespace."},
			{name: "hours", typ: "integer", doc: "How many of the last hours (1 when left out).", min: 1, max: 6}},
		call: func(a toolArgs) (string, string, any, error) {
			if !a.has("kind") {
				a["kind"] = "cluster"
			}
			return http.MethodGet, withQuery(clusterURL(a)+"/metrics", set(url.Values{}, a, "kind", "name", "namespace", "hours")), nil, nil
		},
	},
	{
		name: "right_sizing", title: "Requests and limits to set", role: auth.Viewer, readOnly: true, repeat: true,
		doc:  "For each workload: its requests and limits, what its pods used over up to 7 days, the requests and limits suggested, and its issues (killed for memory, CPU throttled, over-requested).",
		args: []toolArg{clusterArg(), {name: "namespace", typ: "string", doc: "Only this namespace."}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodGet, withQuery(clusterURL(a)+"/sizing", set(url.Values{}, a, "namespace")), nil, nil
		},
	},
	{
		name: "query_metrics", title: "Query the metric store", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "Runs a PromQL query over the metrics Kartal Gözü collects from the apps (its own metric store, not a Prometheus of the cluster). " +
			"Without minutes, the value now; with minutes, the values over that many last minutes.",
		args: []toolArg{{name: "query", typ: "string", doc: "A PromQL query, such as rate(http_requests_total{namespace=\"shop\"}[5m]).", required: true},
			{name: "minutes", typ: "integer", doc: "Over how many of the last minutes.", min: 1, max: 1440}},
		call: func(a toolArgs) (string, string, any, error) {
			q := url.Values{"query": {a.str("query")}}
			if !a.has("minutes") {
				return http.MethodGet, withQuery("/api/v1/store/query", q), nil, nil
			}
			// About 60 values a series: enough to read a trend, few
			// enough to read at all.
			end, span := time.Now().UnixMilli(), int64(a.num("minutes"))*60_000
			q.Set("start", strconv.FormatInt(end-span, 10))
			q.Set("end", strconv.FormatInt(end, 10))
			q.Set("step", strconv.FormatInt(max(span/60, 15_000), 10))
			return http.MethodGet, withQuery("/api/v1/store/query_range", q), nil, nil
		},
	},
	{
		name: "url_checks", title: "URL checks", role: auth.Viewer, readOnly: true, repeat: true,
		doc:  "The addresses Kartal Gözü checks, with their latest result, uptime and last 24 hours.",
		call: func(toolArgs) (string, string, any, error) { return http.MethodGet, "/api/v1/checks", nil, nil },
	},
	{
		name: "versions", title: "Versions that run", role: auth.Viewer, readOnly: true, repeat: true,
		doc: "The server's version and the repository it is built from, each cluster's agent version (and whether it differs from the server's), " +
			"and the Kubernetes versions of each cluster's API server and nodes, with the upstream release each stands for. " +
			"Known vulnerabilities are not looked up by the server; OSV.dev has them: POST https://api.osv.dev/v1/query with " +
			`{"package": {"name": "k8s.io/kubernetes", "ecosystem": "Go"}, "version": "<upstream>"}.`,
		call: func(toolArgs) (string, string, any, error) { return http.MethodGet, "/api/v1/versions", nil, nil },
	},
	{
		name: "audit_log", title: "Audit log", role: auth.Operator, readOnly: true, repeat: true,
		doc:  "The last changes people made through Kartal Gözü (and through MCP), newest first, where you are an operator.",
		call: func(toolArgs) (string, string, any, error) { return http.MethodGet, "/api/v1/audit", nil, nil },
	},

	// The actions.
	{
		name: "restart_workload", title: "Restart a workload", role: auth.Operator, destructive: true,
		doc: "Restarts a Deployment's, StatefulSet's or DaemonSet's pods one after another, as kubectl rollout restart does.",
		args: []toolArg{clusterArg(), namespaceArg(),
			{name: "kind", typ: "string", doc: "The workload's kind.", required: true, enum: []string{"Deployment", "StatefulSet", "DaemonSet"}},
			{name: "name", typ: "string", doc: "The workload's name.", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodPost, workloadURL(a) + "/restart", nil, nil
		},
	},
	{
		name: "scale_workload", title: "Scale a workload", role: auth.Operator, destructive: true, repeat: true,
		doc: "Sets how many replicas a Deployment or StatefulSet runs; 0 stops it.",
		args: []toolArg{clusterArg(), namespaceArg(),
			{name: "kind", typ: "string", doc: "The workload's kind.", required: true, enum: []string{"Deployment", "StatefulSet"}},
			{name: "name", typ: "string", doc: "The workload's name.", required: true},
			{name: "replicas", typ: "integer", doc: "How many replicas.", required: true, min: 0, max: 50}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodPost, workloadURL(a) + "/scale", map[string]int{"replicas": a.num("replicas")}, nil
		},
	},
	{
		name: "rollback_deployment", title: "Roll a Deployment back", role: auth.Operator, destructive: true, repeat: true,
		doc: "Puts a Deployment back to an earlier revision (from rollout_history), as kubectl rollout undo --to-revision does.",
		args: []toolArg{clusterArg(), namespaceArg(), {name: "name", typ: "string", doc: "The Deployment's name.", required: true},
			{name: "revision", typ: "integer", doc: "The revision to go back to.", required: true, min: 1, max: math.MaxInt32}},
		call: func(a toolArgs) (string, string, any, error) {
			path := clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/deployments/" + seg(a.str("name")) + "/rollback"
			return http.MethodPost, path, map[string]int{"revision": a.num("revision")}, nil
		},
	},
	{
		name: "delete_pod", title: "Delete a pod", role: auth.Operator, destructive: true, repeat: true,
		doc:  "Deletes a pod; its workload starts a new one.",
		args: []toolArg{clusterArg(), namespaceArg(), {name: "pod", typ: "string", doc: "The pod's name.", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodDelete, clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/pods/" + seg(a.str("pod")), nil, nil
		},
	},
	{
		name: "cordon_node", title: "Cordon or uncordon a node", role: auth.Operator, destructive: true, repeat: true,
		doc: "Stops new pods from being placed on a node (unschedulable=true), or lets them again (false). Running pods stay. Needs the operator role over the whole cluster.",
		args: []toolArg{clusterArg(), {name: "node", typ: "string", doc: "The node's name.", required: true},
			{name: "unschedulable", typ: "boolean", doc: "true to cordon, false to uncordon.", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodPost, clusterURL(a) + "/nodes/" + seg(a.str("node")) + "/cordon", map[string]bool{"unschedulable": a.flag("unschedulable")}, nil
		},
	},
	{
		name: "run_cronjob", title: "Run a CronJob now", role: auth.Operator,
		doc:  "Starts a Job from a CronJob now, outside its schedule.",
		args: []toolArg{clusterArg(), namespaceArg(), {name: "name", typ: "string", doc: "The CronJob's name.", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodPost, clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/cronjobs/" + seg(a.str("name")) + "/trigger", nil, nil
		},
	},
	{
		name: "suspend_cronjob", title: "Suspend or resume a CronJob", role: auth.Operator, destructive: true, repeat: true,
		doc: "Stops a CronJob from starting Jobs on its schedule (suspend=true), or lets it again (false).",
		args: []toolArg{clusterArg(), namespaceArg(), {name: "name", typ: "string", doc: "The CronJob's name.", required: true},
			{name: "suspend", typ: "boolean", doc: "true to suspend, false to resume.", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			path := clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/cronjobs/" + seg(a.str("name")) + "/suspend"
			return http.MethodPost, path, map[string]bool{"suspend": a.flag("suspend")}, nil
		},
	},

	// What only an admin does, as in the UI: the pod console and the YAML editor.
	{
		name: "exec_in_pod", title: "Run a command in a container", role: auth.Admin, destructive: true,
		doc: "Runs a command in a pod's container with sh -c, as the UI's console does, and returns what it wrote to stdout and stderr and its exit code. " +
			"Needs the admin role where the pod is, and the cluster's agent must allow it (\"exec\" among its capabilities in list_clusters). " +
			"The command is written to the audit log. A container without sh cannot run it. Ask the person you work for before you run anything that changes something.",
		args: []toolArg{clusterArg(), namespaceArg(), {name: "pod", typ: "string", doc: "The pod's name.", required: true},
			{name: "container", typ: "string", doc: "The container; needed when the pod has several."},
			{name: "command", typ: "string", doc: "The shell command, such as: ls -la /app && df -h", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			path := clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/pods/" + seg(a.str("pod")) + "/exec"
			return http.MethodPost, path, map[string]any{"container": a.str("container"), "command": []string{"sh", "-c", a.str("command")}}, nil
		},
	},
	{
		name: "edit_resource", title: "Save an object", role: auth.Admin, destructive: true, repeat: true,
		doc: "Replaces an object with new contents, as the UI's YAML editor does. Start from get_resource's answer, change only what is needed, and keep metadata.resourceVersion: " +
			"the API server then refuses the save when the object has changed since. Without dry_run=false nothing is saved: the answer is the object as the API server would save it, " +
			"to show the person you work for before you save. Secrets cannot be saved. Needs the admin role where the object is, and the agent's \"edit\" capability.",
		args: []toolArg{clusterArg(),
			{name: "kind", typ: "string", required: true, doc: "The object's kind, such as Deployment or ConfigMap (also plurals and kubectl's short names), or its type as group/version/resource."},
			{name: "name", typ: "string", doc: "The object's name.", required: true},
			{name: "namespace", typ: "string", doc: "The object's namespace; leave it out for cluster-wide types."},
			{name: "object", typ: "string", doc: "The whole object as YAML or JSON, with metadata.resourceVersion.", required: true},
			{name: "dry_run", typ: "boolean", doc: "false to save; when left out or true, only shows what would be saved."}},
		call: func(a toolArgs) (string, string, any, error) {
			_, gvr, err := resolveKind(a.str("kind"))
			if err != nil {
				return "", "", nil, err
			}
			save := a.has("dry_run") && !a.flag("dry_run")
			if save && !hasResourceVersion.MatchString(a.str("object")) {
				return "", "", nil, errors.New("the object must keep metadata.resourceVersion (as get_resource gives it), so that a newer version is never saved over")
			}
			parts := strings.Split(gvr, "/")
			path := clusterURL(a) + "/resources/" + seg(parts[0]) + "/" + seg(parts[1]) + "/" + seg(parts[2]) + "/" + seg(a.str("name"))
			q := set(url.Values{}, a, "namespace")
			if !save {
				q.Set("dryRun", "true")
			}
			return http.MethodPut, withQuery(path, q), yamlBody(a.str("object")), nil
		},
	},
}

func workloadURL(a toolArgs) string {
	return clusterURL(a) + "/namespaces/" + seg(a.str("namespace")) + "/workloads/" + strings.ToLower(a.str("kind")) + "/" + seg(a.str("name"))
}
