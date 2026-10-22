package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/netcheck"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// A network check tries TCP connections from the agent's own pod and from a
// short-lived pod on each node asked for. Those pods run the agent's own
// image ("kartal-agent net-check host:port ..."), print their results and
// stop; the agent reads the results from their logs and then removes them.
// Their traffic leaves the node as any pod's does, so a firewall sees what
// the applications on that node would send.
const (
	netCheckApp   = "kartal-net-check"
	netCheckLabel = "kartal-gozu.io/net-check"
	// netCheckDeadline bounds a check pod's life, pulling the image included.
	netCheckDeadline = 120
	// netCheckKeep is when the pods of a check nobody asked about again are
	// removed anyway.
	netCheckKeep = 10 * time.Minute
	// AgentBinary is where the image keeps the agent.
	AgentBinary = "/usr/local/bin/kartal-agent"
)

var (
	errNetCheckDisabled = errors.New("network checks are disabled on this agent (KARTAL_NETWORK_CHECKS=false)")
	checkIDPattern      = regexp.MustCompile(`^[a-f0-9]{8,32}$`)
)

// netCheckImage is where the check pods start and what they run.
type netCheckImage struct {
	namespace, image string
	pullSecrets      []string
}

// netCheckPlace finds the namespace and image of the check pods: given, or
// those of the agent's own pod.
func (e *Executor) netCheckPlace(ctx context.Context) (netCheckImage, error) {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	if e.netPlace != nil {
		return *e.netPlace, nil
	}
	if e.NetCheckNamespace == "" {
		return netCheckImage{}, errors.New("checks from the nodes need the agent to run in the cluster")
	}
	place := netCheckImage{namespace: e.NetCheckNamespace, image: e.NetCheckImage}
	if place.image == "" {
		self, err := os.Hostname()
		if err != nil {
			return netCheckImage{}, err
		}
		var pod kube.Pod
		if err := e.Kube.Get(ctx, "/api/v1/namespaces/"+kube.Seg(place.namespace)+"/pods/"+kube.Seg(self), &pod); err != nil {
			return netCheckImage{}, fmt.Errorf("finding the agent's own image: %w", err)
		}
		for _, c := range pod.Spec.Containers {
			if place.image == "" || c.Name == "agent" {
				place.image = c.Image
			}
		}
		for _, s := range pod.Spec.ImagePullSecrets {
			place.pullSecrets = append(place.pullSecrets, s.Name)
		}
		if place.image == "" {
			return netCheckImage{}, errors.New("the agent's pod has no image to start checks with")
		}
	}
	e.netPlace = &place
	return place, nil
}

func (e *Executor) netCheck(ctx context.Context, cmd protocol.Command) (string, error) {
	var req protocol.NetCheckRequest
	if err := json.Unmarshal([]byte(cmd.Body), &req); err != nil {
		return "", fmt.Errorf("invalid request: %w", err)
	}
	targets, err := netcheck.ParseTargets(req.Targets)
	if err != nil {
		return "", err
	}
	nodes := dedupe(req.Nodes)
	switch {
	case !req.Agent && len(nodes) == 0:
		return "", errors.New("choose where to check from: the agent, nodes or both")
	case len(nodes) > protocol.MaxNetCheckNodes:
		return "", fmt.Errorf("at most %d nodes at once", protocol.MaxNetCheckNodes)
	case len(nodes) > 0 && len(e.Namespaces) > 0:
		return "", errors.New("this agent is limited to specific namespaces; nodes are outside its scope")
	}
	out := protocol.NetCheckStarted{Targets: targets}
	var wg sync.WaitGroup
	if req.Agent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out.Agent = netcheck.Run(ctx, e.Dialer, targets)
		}()
	}
	if len(nodes) > 0 {
		id := cmd.ID
		if len(id) > 16 {
			id = id[:16]
		}
		if !checkIDPattern.MatchString(id) {
			id = fmt.Sprintf("%x", e.now().UnixNano())
		}
		started, errs, err := e.startNetCheck(ctx, id, nodes, targets)
		if err != nil {
			// The agent's own results still count.
			errs = map[string]string{}
			for _, n := range nodes {
				errs[n] = err.Error()
			}
		}
		if len(started) > 0 {
			out.ID, out.Nodes = id, started
		}
		out.Errors = errs
	}
	wg.Wait()
	return marshal(out)
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// startNetCheck starts a check pod on each node; the nodes it could not
// start one on come back with the reason.
func (e *Executor) startNetCheck(ctx context.Context, id string, nodes, targets []string) ([]string, map[string]string, error) {
	place, err := e.netCheckPlace(ctx)
	if err != nil {
		return nil, nil, err
	}
	known, err := kube.ListMeta(ctx, e.Kube, "/api/v1/nodes", 0)
	if err != nil {
		return nil, nil, fmt.Errorf("listing nodes: %w", err)
	}
	exists := map[string]bool{}
	for _, m := range known {
		exists[m.Name] = true
	}
	e.sweepNetChecks(ctx, place.namespace)
	path := "/api/v1/namespaces/" + kube.Seg(place.namespace) + "/pods"
	errs := map[string]string{}
	var started []string
	for _, node := range nodes {
		if !exists[node] {
			errs[node] = "no such node"
			continue
		}
		body, err := json.Marshal(netCheckPod(id, node, place, targets))
		if err != nil {
			return nil, nil, err
		}
		if _, err := e.Kube.Send(ctx, http.MethodPost, path, "application/json", body, 1<<20); err != nil {
			errs[node] = err.Error()
			continue
		}
		started = append(started, node)
	}
	if len(errs) == 0 {
		errs = nil
	}
	return started, errs, nil
}

// netCheckPod is a pod that runs the check on one node and stops: no
// service account token, no privileges, nothing kept.
func netCheckPod(id, node string, place netCheckImage, targets []string) map[string]any {
	var secrets []map[string]string
	for _, s := range place.pullSecrets {
		secrets = append(secrets, map[string]string{"name": s})
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"generateName": netCheckApp + "-",
			"labels":       map[string]string{"app.kubernetes.io/name": netCheckApp, netCheckLabel: id},
		},
		"spec": map[string]any{
			// Set by hand, the node takes the pod without the scheduler: taints
			// that keep other pods off it do not keep this one.
			"nodeName":                      node,
			"tolerations":                   []map[string]string{{"operator": "Exists"}},
			"restartPolicy":                 "Never",
			"activeDeadlineSeconds":         netCheckDeadline,
			"terminationGracePeriodSeconds": 0,
			"automountServiceAccountToken":  false,
			"enableServiceLinks":            false,
			"imagePullSecrets":              secrets,
			"securityContext": map[string]any{
				"runAsNonRoot":   true,
				"runAsUser":      65532,
				"seccompProfile": map[string]string{"type": "RuntimeDefault"},
			},
			"containers": []map[string]any{{
				"name":            "check",
				"image":           place.image,
				"imagePullPolicy": "IfNotPresent",
				"command":         []string{AgentBinary, "net-check"},
				"args":            targets,
				"resources": map[string]any{
					"requests": map[string]string{"cpu": "10m", "memory": "16Mi"},
					"limits":   map[string]string{"cpu": "100m", "memory": "64Mi"},
				},
				"securityContext": map[string]any{
					"allowPrivilegeEscalation": false,
					"readOnlyRootFilesystem":   true,
					"capabilities":             map[string]any{"drop": []string{"ALL"}},
				},
			}},
		},
	}
}

// sweepNetChecks removes the pods of checks that nobody finished reading.
func (e *Executor) sweepNetChecks(ctx context.Context, ns string) {
	pods, err := kube.ListAll[kube.Pod](ctx, e.Kube, "/api/v1/namespaces/"+kube.Seg(ns)+"/pods",
		url.Values{"labelSelector": {"app.kubernetes.io/name=" + netCheckApp}})
	if err != nil {
		return
	}
	for _, p := range pods {
		if e.now().Sub(p.Metadata.CreationTimestamp) > netCheckKeep {
			e.removePod(ctx, ns, p.Metadata.Name)
		}
	}
}

func (e *Executor) removePod(ctx context.Context, ns, name string) {
	e.Kube.Send(ctx, http.MethodDelete, "/api/v1/namespaces/"+kube.Seg(ns)+"/pods/"+kube.Seg(name), "", nil, 1<<20)
}

// netCheckStatus reports where a check's pods are and what the finished
// ones found; once all have finished, it removes them.
func (e *Executor) netCheckStatus(ctx context.Context, id string) (string, error) {
	if !checkIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid check %q", id)
	}
	place, err := e.netCheckPlace(ctx)
	if err != nil {
		return "", err
	}
	e.sweepNetChecks(ctx, place.namespace)
	ns := kube.Seg(place.namespace)
	pods, err := kube.ListAll[kube.Pod](ctx, e.Kube, "/api/v1/namespaces/"+ns+"/pods",
		url.Values{"labelSelector": {netCheckLabel + "=" + id}})
	if err != nil {
		return "", err
	}
	st := protocol.NetCheckStatus{Nodes: []protocol.NodeReach{}, Done: true}
	for _, p := range pods {
		r := protocol.NodeReach{Node: p.Spec.NodeName}
		switch p.Status.Phase {
		case "Succeeded":
			text, err := e.Kube.GetText(ctx, "/api/v1/namespaces/"+ns+"/pods/"+kube.Seg(p.Metadata.Name)+"/log", 1<<20)
			r.State = "done"
			if err == nil {
				err = json.Unmarshal([]byte(lastLine(text)), &r.Results)
			}
			if err != nil {
				r.State, r.Detail = "failed", "the results could not be read: "+err.Error()
			}
		case "Failed":
			r.State, r.Detail = "failed", podTrouble(p)
		default:
			r.State, r.Detail = "waiting", podTrouble(p)
			// A pod that never started (its node is down, say) is past its
			// deadline only once it starts: it is given up here instead.
			if e.now().Sub(p.Metadata.CreationTimestamp) > netCheckDeadline*time.Second+time.Minute {
				r.State, r.Detail = "failed", "did not start: "+r.Detail
			} else {
				st.Done = false
			}
		}
		st.Nodes = append(st.Nodes, r)
	}
	sort.Slice(st.Nodes, func(i, j int) bool { return st.Nodes[i].Node < st.Nodes[j].Node })
	if st.Done {
		for _, p := range pods {
			e.removePod(ctx, place.namespace, p.Metadata.Name)
		}
	}
	return marshal(st)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// podTrouble says what a check pod waits for, or why it stopped.
func podTrouble(p kube.Pod) string {
	parts := []string{}
	if p.Status.Reason != "" {
		parts = append(parts, p.Status.Reason)
	}
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			parts = append(parts, strings.TrimSpace(w.Reason+" "+w.Message))
		}
		if t := cs.State.Terminated; t != nil {
			parts = append(parts, fmt.Sprintf("%s (exit code %d)", t.Reason, t.ExitCode))
		}
	}
	if len(parts) == 0 {
		return p.Status.Phase
	}
	return strings.Join(parts, "; ")
}
