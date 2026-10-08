package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	defaultTailLines = 500
	maxTailLines     = 5000
	maxReplicas      = 50
	maxListItems     = 5000
	maxObjectBytes   = 4 << 20
	// RestartAnnotation is bumped on the pod template to trigger a rollout.
	RestartAnnotation = "kartal-gozu.io/restartedAt"
	redacted          = "<redacted>"
)

var (
	errWriteDisabled = errors.New("write commands are disabled on this agent (KARTAL_ALLOW_WRITE=false)")
	errExecDisabled  = errors.New("running commands in containers is disabled on this agent (KARTAL_ALLOW_EXEC=false)")
	errEditDisabled  = errors.New("editing objects is disabled on this agent (KARTAL_ALLOW_EDIT=false)")
	namePattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	versionPattern   = regexp.MustCompile(`^v[0-9]+((alpha|beta)[0-9]+)?$`)
	labelPattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// checkNamespace refuses anything that is not a namespace name (a DNS label).
func checkNamespace(ns string) error {
	if len(ns) > 63 || !labelPattern.MatchString(ns) {
		return fmt.Errorf("invalid namespace %q", ns)
	}
	return nil
}

// checkName applies the API server's own rule for object names, which become
// URL path segments: a crafted "..", "/" or "%" must not reach another path.
func checkName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 253 || strings.ContainsAny(name, "/%") {
		return fmt.Errorf("invalid name %q", name)
	}
	return nil
}

// Executor runs commands received from the server against the cluster.
type Executor struct {
	Kube *kube.Client
	// AllowWrite enables restart, scale, pod delete, cordon, CronJob
	// suspend/trigger and rollback; AllowExec running commands in containers;
	// AllowEdit changing objects from YAML.
	AllowWrite bool
	AllowExec  bool
	AllowEdit  bool
	// AllowScrape enables reading the metrics that pods expose.
	AllowScrape bool
	Namespaces  []string
	MaxLogBytes int64
	Now         func() time.Time
}

// Capabilities lists what the executor may do beyond reading, for the
// snapshot: the UI offers only actions the agent will accept.
func (e *Executor) Capabilities() []string {
	var out []string
	if e.AllowWrite {
		out = append(out, protocol.CapabilityWrite)
	}
	if e.AllowExec {
		out = append(out, protocol.CapabilityExec)
	}
	if e.AllowEdit {
		out = append(out, protocol.CapabilityEdit)
	}
	if e.AllowScrape {
		out = append(out, protocol.CapabilityScrape, protocol.CapabilityCollect)
	}
	return out
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Executor) Run(ctx context.Context, cmd protocol.Command) protocol.Result {
	res := protocol.Result{CommandID: cmd.ID}
	out, err := e.run(ctx, cmd)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK, res.Output = true, out
	return res
}

func (e *Executor) run(ctx context.Context, cmd protocol.Command) (string, error) {
	switch cmd.Type {
	case protocol.CommandLogs:
		if err := e.checkObject(cmd.Namespace, cmd.Name); err != nil {
			return "", err
		}
		return e.logs(ctx, cmd)
	case protocol.CommandRestart, protocol.CommandScale:
		if err := e.checkObject(cmd.Namespace, cmd.Name); err != nil {
			return "", err
		}
		if !e.AllowWrite {
			return "", errWriteDisabled
		}
		if cmd.Type == protocol.CommandRestart {
			return e.restart(ctx, cmd)
		}
		return e.scale(ctx, cmd)
	case protocol.CommandResources:
		return e.resources(ctx)
	case protocol.CommandList:
		path, err := e.collectionPath(cmd)
		if err != nil {
			return "", err
		}
		return e.list(ctx, path)
	case protocol.CommandGet:
		if err := checkName(cmd.Name); err != nil {
			return "", err
		}
		path, err := e.collectionPath(cmd)
		if err != nil {
			return "", err
		}
		return e.get(ctx, path+"/"+kube.Seg(cmd.Name))
	case protocol.CommandEvents:
		return e.objectEvents(ctx, cmd)
	case protocol.CommandHistory:
		if err := e.checkObject(cmd.Namespace, cmd.Name); err != nil {
			return "", err
		}
		h, err := e.history(ctx, cmd.Namespace, cmd.Name)
		if err != nil {
			return "", err
		}
		return marshal(h.History)
	case protocol.CommandHelm:
		return e.helmReleases(ctx)
	case protocol.CommandDelete, protocol.CommandSuspend, protocol.CommandTrigger, protocol.CommandRollback:
		if err := e.checkObject(cmd.Namespace, cmd.Name); err != nil {
			return "", err
		}
		if !e.AllowWrite {
			return "", errWriteDisabled
		}
		switch cmd.Type {
		case protocol.CommandDelete:
			return e.deletePod(ctx, cmd)
		case protocol.CommandSuspend:
			return e.suspend(ctx, cmd)
		case protocol.CommandTrigger:
			return e.trigger(ctx, cmd)
		default:
			return e.rollback(ctx, cmd)
		}
	case protocol.CommandCordon:
		if !namePattern.MatchString(cmd.Name) {
			return "", fmt.Errorf("invalid node name %q", cmd.Name)
		}
		if len(e.Namespaces) > 0 {
			return "", errors.New("this agent is limited to specific namespaces; nodes are outside its scope")
		}
		if !e.AllowWrite {
			return "", errWriteDisabled
		}
		return e.cordon(ctx, cmd)
	case protocol.CommandExec:
		if err := e.checkObject(cmd.Namespace, cmd.Name); err != nil {
			return "", err
		}
		if !e.AllowExec {
			return "", errExecDisabled
		}
		return e.exec(ctx, cmd)
	case protocol.CommandApply:
		if !e.AllowEdit {
			return "", errEditDisabled
		}
		return e.apply(ctx, cmd)
	case protocol.CommandFindMetrics:
		if !e.AllowScrape {
			return "", errScrapeDisabled
		}
		return e.findMetrics(ctx, cmd)
	case protocol.CommandScrape, protocol.CommandSample, protocol.CommandCollect:
		if cmd.Path == "" {
			cmd.Path = "/metrics"
		}
		var err error
		switch cmd.Type {
		case protocol.CommandScrape:
			err = e.checkObject(cmd.Namespace, cmd.Name)
		case protocol.CommandSample:
			err = e.checkSample(cmd)
		default:
			err = e.checkPods(cmd)
		}
		if err != nil {
			return "", err
		}
		if err := protocol.CheckEndpoint(cmd.Port, cmd.Path); err != nil {
			return "", err
		}
		if !e.AllowScrape {
			return "", errScrapeDisabled
		}
		switch cmd.Type {
		case protocol.CommandScrape:
			return e.scrape(ctx, cmd)
		case protocol.CommandSample:
			return e.sample(ctx, cmd)
		}
		return e.collect(ctx, cmd)
	default:
		return "", fmt.Errorf("unsupported command %q", cmd.Type)
	}
}

func (e *Executor) checkObject(ns, name string) error {
	if ns == "" || name == "" {
		return errors.New("namespace and name are required")
	}
	if err := checkNamespace(ns); err != nil {
		return err
	}
	if err := checkName(name); err != nil {
		return err
	}
	if !e.namespaceAllowed(ns) {
		return fmt.Errorf("namespace %q is outside this agent's scope", ns)
	}
	return nil
}

func (e *Executor) namespaceAllowed(ns string) bool {
	return len(e.Namespaces) == 0 || slices.Contains(e.Namespaces, ns)
}

// collectionPath validates group/version/resource (they become URL path
// segments) and returns the collection path, scoped to cmd.Namespace if set.
func (e *Executor) collectionPath(cmd protocol.Command) (string, error) {
	if cmd.Group != "" && !namePattern.MatchString(cmd.Group) {
		return "", fmt.Errorf("invalid API group %q", cmd.Group)
	}
	if !versionPattern.MatchString(cmd.Version) {
		return "", fmt.Errorf("invalid API version %q", cmd.Version)
	}
	if !namePattern.MatchString(cmd.Resource) {
		return "", fmt.Errorf("invalid resource %q", cmd.Resource)
	}
	prefix := "/api/" + cmd.Version
	if cmd.Group != "" {
		prefix = "/apis/" + cmd.Group + "/" + cmd.Version
	}
	if cmd.Namespace == "" {
		if len(e.Namespaces) > 0 {
			return "", errors.New("this agent is limited to specific namespaces; a namespace is required")
		}
		return prefix + "/" + cmd.Resource, nil
	}
	if err := checkNamespace(cmd.Namespace); err != nil {
		return "", err
	}
	if !e.namespaceAllowed(cmd.Namespace) {
		return "", fmt.Errorf("namespace %q is outside this agent's scope", cmd.Namespace)
	}
	return prefix + "/namespaces/" + kube.Seg(cmd.Namespace) + "/" + cmd.Resource, nil
}

func marshal(v any) (string, error) { return encode(v, false) }

// encode writes JSON without HTML escaping, so values such as "a && b" or
// "<redacted>" stay readable for the people looking at them.
func encode(v any, indent bool) (string, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// resources discovers every listable resource type, CRDs included.
func (e *Executor) resources(ctx context.Context) (string, error) {
	var core kube.APIResourceList
	if err := e.Kube.Get(ctx, "/api/v1", &core); err != nil {
		return "", err
	}
	var groups kube.APIGroupList
	if err := e.Kube.Get(ctx, "/apis", &groups); err != nil {
		return "", err
	}
	out := appendResources(nil, "", "v1", core)
	var (
		mu   sync.Mutex
		errs []string
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, collectConcurrency)
	for _, g := range groups.Groups {
		wg.Add(1)
		sem <- struct{}{}
		go func(group, version string) {
			defer wg.Done()
			defer func() { <-sem }()
			var list kube.APIResourceList
			err := e.Kube.Get(ctx, "/apis/"+group+"/"+version, &list)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// One broken aggregated API must not hide all the others.
				errs = append(errs, group+"/"+version+": "+err.Error())
				return
			}
			out = appendResources(out, group, version, list)
		}(g.Name, g.PreferredVersion.Version)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Resource < out[j].Resource
	})
	sort.Strings(errs)
	return marshal(struct {
		Resources []protocol.APIResource `json:"resources"`
		Errors    []string               `json:"errors,omitempty"`
	}{out, errs})
}

func appendResources(out []protocol.APIResource, group, version string, l kube.APIResourceList) []protocol.APIResource {
	for _, r := range l.Resources {
		if strings.Contains(r.Name, "/") || !slices.Contains(r.Verbs, "list") {
			continue // subresources such as pods/log, and unlistable types
		}
		out = append(out, protocol.APIResource{Group: group, Version: version, Resource: r.Name, Kind: r.Kind, Namespaced: r.Namespaced})
	}
	return out
}

// list returns names only; object contents stay in the cluster.
func (e *Executor) list(ctx context.Context, path string) (string, error) {
	items, err := kube.ListMeta(ctx, e.Kube, path, maxListItems)
	if err != nil {
		return "", err
	}
	refs := make([]protocol.ObjectRef, 0, len(items))
	for _, m := range items {
		refs = append(refs, protocol.ObjectRef{Namespace: m.Namespace, Name: m.Name, CreatedAt: m.CreationTimestamp})
	}
	sortByNSName(refs, func(x protocol.ObjectRef) (string, string) { return x.Namespace, x.Name })
	return marshal(refs)
}

func (e *Executor) get(ctx context.Context, path string) (string, error) {
	raw, err := e.Kube.GetRaw(ctx, path, maxObjectBytes)
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", fmt.Errorf("decode object: %w", err)
	}
	Sanitize(obj)
	return encode(obj, true)
}

// Sanitize drops bookkeeping noise and, for Secrets, every value: data,
// stringData and the last-applied annotation in which kubectl apply keeps a
// full copy of the object.
func Sanitize(obj map[string]any) {
	md, _ := obj["metadata"].(map[string]any)
	if md != nil {
		delete(md, "managedFields")
	}
	if obj["kind"] != "Secret" {
		return
	}
	for _, field := range []string{"data", "stringData"} {
		if m, ok := obj[field].(map[string]any); ok {
			for k := range m {
				m[k] = redacted
			}
		}
	}
	if ann, ok := md["annotations"].(map[string]any); ok {
		delete(ann, "kubectl.kubernetes.io/last-applied-configuration")
	}
}

func (e *Executor) logs(ctx context.Context, cmd protocol.Command) (string, error) {
	tail := cmd.TailLines
	if tail <= 0 {
		tail = defaultTailLines
	}
	tail = min(tail, maxTailLines)
	limit := e.MaxLogBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	q := url.Values{
		"tailLines":  {strconv.Itoa(tail)},
		"timestamps": {"true"},
		"limitBytes": {strconv.FormatInt(limit, 10)},
	}
	if cmd.Previous {
		q.Set("previous", "true")
	}
	if cmd.Container != "" {
		q.Set("container", cmd.Container)
	}
	path := "/api/v1/namespaces/" + kube.Seg(cmd.Namespace) + "/pods/" + kube.Seg(cmd.Name) + "/log?" + q.Encode()
	return e.Kube.GetText(ctx, path, limit)
}

// workloadPath maps a user-facing kind to its apps/v1 resource path.
func workloadPath(ns, kind, name string, allowed ...string) (string, error) {
	kind = strings.ToLower(kind)
	if !slices.Contains(allowed, kind) {
		return "", fmt.Errorf("kind %q is not supported here (allowed: %s)", kind, strings.Join(allowed, ", "))
	}
	return "/apis/apps/v1/namespaces/" + kube.Seg(ns) + "/" + kind + "s/" + kube.Seg(name), nil
}

func (e *Executor) restart(ctx context.Context, cmd protocol.Command) (string, error) {
	path, err := workloadPath(cmd.Namespace, cmd.Kind, cmd.Name, "deployment", "statefulset", "daemonset")
	if err != nil {
		return "", err
	}
	patch := map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
		"annotations": map[string]string{RestartAnnotation: e.now().UTC().Format(time.RFC3339)},
	}}}}
	if err := e.Kube.Patch(ctx, path, "application/strategic-merge-patch+json", patch); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s restarted", strings.ToLower(cmd.Kind), cmd.Name), nil
}

func (e *Executor) scale(ctx context.Context, cmd protocol.Command) (string, error) {
	path, err := workloadPath(cmd.Namespace, cmd.Kind, cmd.Name, "deployment", "statefulset")
	if err != nil {
		return "", err
	}
	if cmd.Replicas == nil || *cmd.Replicas < 0 || *cmd.Replicas > maxReplicas {
		return "", fmt.Errorf("replicas must be between 0 and %d", maxReplicas)
	}
	patch := map[string]any{"spec": map[string]any{"replicas": *cmd.Replicas}}
	if err := e.Kube.Patch(ctx, path, "application/merge-patch+json", patch); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s scaled to %d", strings.ToLower(cmd.Kind), cmd.Name, *cmd.Replicas), nil
}
