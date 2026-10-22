package fakekube

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// The pods of network checks: created by POST, listed by their labels, their
// results in their logs, removed by DELETE. Each "runs" for NetCheckDelay.
// What they find is made up from the target: a host with "blocked" in its
// name drops connections, one with "closed" refuses them, one with "nosuch"
// does not exist, and node cp1 cannot reach port 1521 at all.

type netPod struct {
	ns, name, node string
	labels         map[string]string
	args           []string
	created        time.Time
}

func (f *Server) createPod(w http.ResponseWriter, p string, body []byte) {
	var spec struct {
		Metadata struct {
			GenerateName string            `json:"generateName"`
			Labels       map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			NodeName   string `json:"nodeName"`
			Containers []struct {
				Args []string `json:"args"`
			} `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &spec); err != nil || len(spec.Spec.Containers) == 0 {
		writeStatus(w, http.StatusBadRequest, "BadRequest", "invalid pod")
		return
	}
	ns := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/namespaces/"), "/pods")
	f.mu.Lock()
	f.netSeq++
	pod := &netPod{ns: ns, name: fmt.Sprintf("%s%05d", spec.Metadata.GenerateName, f.netSeq), node: spec.Spec.NodeName,
		labels: spec.Metadata.Labels, args: spec.Spec.Containers[0].Args, created: time.Now()}
	if f.netPods == nil {
		f.netPods = map[string]*netPod{}
	}
	f.netPods[ns+"/"+pod.name] = pod
	f.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(f.netPodObject(pod))
}

func (f *Server) netPodObject(pod *netPod) map[string]any {
	status := map[string]any{"phase": "Succeeded"}
	if time.Since(pod.created) < f.NetCheckDelay {
		status = map[string]any{"phase": "Pending", "containerStatuses": []any{map[string]any{
			"name": "check", "state": map[string]any{"waiting": map[string]any{"reason": "ContainerCreating"}}}}}
	}
	return map[string]any{
		"metadata": map[string]any{"name": pod.name, "namespace": pod.ns, "labels": pod.labels,
			"creationTimestamp": pod.created.UTC().Format(time.RFC3339)},
		"spec":   map[string]any{"nodeName": pod.node, "containers": []any{map[string]any{"name": "check"}}},
		"status": status,
	}
}

// serveNetPods answers the lists, logs and removals of the check pods.
func (f *Server) serveNetPods(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	f.mu.Lock()
	defer f.mu.Unlock()
	if ns, pod, ok := logPath(p); ok {
		np := f.netPods[ns+"/"+pod]
		if np == nil {
			return false
		}
		b, _ := json.Marshal(fakeReach(np.node, np.args))
		w.Header().Set("Content-Type", "text/plain")
		w.Write(append(b, '\n'))
		return true
	}
	if r.Method == http.MethodDelete {
		parts := strings.Split(strings.TrimPrefix(p, "/api/v1/namespaces/"), "/")
		if len(parts) != 3 || parts[1] != "pods" || f.netPods[parts[0]+"/"+parts[2]] == nil {
			return false
		}
		delete(f.netPods, parts[0]+"/"+parts[2])
		io.WriteString(w, "{}")
		return true
	}
	sel := r.URL.Query().Get("labelSelector")
	if !strings.HasPrefix(p, "/api/v1/namespaces/") || !strings.HasSuffix(p, "/pods") ||
		!strings.Contains(sel, "net-check") {
		return false
	}
	key, value, _ := strings.Cut(sel, "=")
	ns := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/namespaces/"), "/pods")
	var items []string
	names := make([]string, 0, len(f.netPods))
	for k := range f.netPods {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		np := f.netPods[k]
		if np.ns == ns && np.labels[key] == value {
			b, _ := json.Marshal(f.netPodObject(np))
			items = append(items, string(b))
		}
	}
	io.WriteString(w, list(items...))
	return true
}

type reach struct {
	Target  string `json:"target"`
	Result  string `json:"result"`
	Address string `json:"address,omitempty"`
	Millis  int64  `json:"millis"`
	Error   string `json:"error,omitempty"`
}

func fakeReach(node string, targets []string) []reach {
	out := []reach{}
	for i, t := range targets {
		host, port, _ := net.SplitHostPort(t)
		ip := host
		if net.ParseIP(host) == nil {
			ip = fmt.Sprintf("10.20.%d.%d", 30+len(host)%20, 10+i)
		}
		addr := net.JoinHostPort(ip, port)
		r := reach{Target: t, Address: addr, Millis: int64(1 + (len(host)+i)%7)}
		switch {
		case strings.Contains(host, "nosuch"):
			r = reach{Target: t, Result: "dns", Error: "lookup " + host + ": no such host"}
		case strings.Contains(host, "blocked") || (node == "cp1" && port == "1521"):
			r.Result, r.Millis, r.Error = "timeout", 3000, "dial tcp "+addr+": i/o timeout"
		case strings.Contains(host, "closed"):
			r.Result, r.Error = "refused", "dial tcp "+addr+": connect: connection refused"
		default:
			r.Result = "ok"
		}
		out = append(out, r)
	}
	return out
}

// networkPolicies are the policies of a namespace: every team allows only
// pods to reach its pods, on the metrics port, the way some charts do.
func networkPolicies(ns string) []string {
	if !strings.HasPrefix(ns, "team-") {
		return nil
	}
	return []string{fmt.Sprintf(`{"metadata":{"name":"allow-from-pods","namespace":%q},
		"spec":{"podSelector":{},"policyTypes":["Ingress"],
			"ingress":[{"from":[{"namespaceSelector":{}}],"ports":[{"port":9100},{"port":"http"}]}]}}`, ns)}
}
