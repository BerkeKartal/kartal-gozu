package agent

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// networkPolicies tells whether the NetworkPolicies of a pod's namespace let
// connections reach one of its ports from outside the pods. The API server
// proxies to pods from the nodes' network, which a rule naming only pods or
// namespaces does not admit: such a rule is behind most "context deadline
// exceeded" when metrics are read through the API server.
func (e *Executor) networkPolicies(ctx context.Context, cmd protocol.Command) (string, error) {
	port, err := strconv.Atoi(cmd.Port)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %q: it must be a port number", cmd.Port)
	}
	ns := kube.Seg(cmd.Namespace)
	var pod kube.Pod
	if err := e.Kube.Get(ctx, "/api/v1/namespaces/"+ns+"/pods/"+kube.Seg(cmd.Name), &pod); err != nil {
		return "", err
	}
	policies, err := kube.ListAll[kube.NetworkPolicy](ctx, e.Kube, "/apis/networking.k8s.io/v1/namespaces/"+ns+"/networkpolicies", nil)
	if err != nil {
		return "", err
	}
	return marshal(policyReport(pod, policies, port))
}

// admitRank orders what policies admit, from nothing to every source.
var admitRank = map[string]int{"nothing": 0, "pods": 1, "ranges": 2, "all": 3}

func policyReport(pod kube.Pod, policies []kube.NetworkPolicy, port int) protocol.PolicyReport {
	rep := protocol.PolicyReport{Pod: pod.Metadata.Name, Port: strconv.Itoa(port), Verdict: "none", Policies: []protocol.PolicyMatch{}}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Metadata.Name < policies[j].Metadata.Name })
	most := "nothing"
	for _, np := range policies {
		if !limitsIngress(np) || !selects(&np.Spec.PodSelector, pod.Metadata.Labels) {
			continue
		}
		m := protocol.PolicyMatch{Name: np.Metadata.Name, Rules: []string{}, Admits: "nothing"}
		for _, rule := range np.Spec.Ingress {
			m.Rules = append(m.Rules, describeRule(rule))
			if coversPort(rule.Ports, port, pod) && admitRank[ruleAdmits(rule)] > admitRank[m.Admits] {
				m.Admits = ruleAdmits(rule)
			}
		}
		if admitRank[m.Admits] > admitRank[most] {
			most = m.Admits
		}
		rep.Policies = append(rep.Policies, m)
	}
	if len(rep.Policies) == 0 {
		return rep
	}
	switch most {
	case "all":
		rep.Verdict = "open"
	case "ranges":
		rep.Verdict = "maybe"
	default:
		rep.Verdict = "blocked"
	}
	if rep.Verdict != "open" {
		rep.Suggestion = suggestPolicy(pod, port)
	}
	return rep
}

// limitsIngress: a policy without policyTypes limits incoming connections;
// one with them, only when they say Ingress.
func limitsIngress(np kube.NetworkPolicy) bool {
	return len(np.Spec.PolicyTypes) == 0 || slices.Contains(np.Spec.PolicyTypes, "Ingress")
}

// selects applies a label selector; an empty one selects everything.
func selects(sel *kube.LabelSelector, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if have, ok := labels[k]; !ok || have != v {
			return false
		}
	}
	for _, r := range sel.MatchExpressions {
		have, ok := labels[r.Key]
		switch r.Operator {
		case "In":
			if !ok || !slices.Contains(r.Values, have) {
				return false
			}
		case "NotIn":
			if ok && slices.Contains(r.Values, have) {
				return false
			}
		case "Exists":
			if !ok {
				return false
			}
		case "DoesNotExist":
			if ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// coversPort tells whether a rule's ports include port (over TCP); a named
// port is looked up among the pod's containers.
func coversPort(ports []kube.NetworkPolicyPort, port int, pod kube.Pod) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p.Protocol != "" && p.Protocol != "TCP" {
			continue
		}
		if p.Port == nil {
			return true
		}
		if n, err := strconv.Atoi(string(*p.Port)); err == nil {
			if n == port || (p.EndPort != nil && n <= port && port <= int(*p.EndPort)) {
				return true
			}
			continue
		}
		for _, c := range pod.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name == string(*p.Port) && int(cp.ContainerPort) == port {
					return true
				}
			}
		}
	}
	return false
}

// ruleAdmits is what a rule lets in: every source when it names none,
// address ranges, or only pods.
func ruleAdmits(rule kube.NetworkPolicyRule) string {
	if len(rule.From) == 0 {
		return "all"
	}
	for _, p := range rule.From {
		if p.IPBlock != nil {
			return "ranges"
		}
	}
	return "pods"
}

func describeRule(rule kube.NetworkPolicyRule) string {
	from := "from any source"
	if len(rule.From) > 0 {
		var peers []string
		for _, p := range rule.From {
			peers = append(peers, describePeer(p))
		}
		from = "from " + strings.Join(peers, "; ")
	}
	on := "on every port"
	if len(rule.Ports) > 0 {
		var ports []string
		for _, p := range rule.Ports {
			s := "every port"
			if p.Port != nil {
				s = string(*p.Port)
				if p.EndPort != nil {
					s += "-" + strconv.Itoa(int(*p.EndPort))
				}
			}
			if p.Protocol != "" && p.Protocol != "TCP" {
				s += "/" + p.Protocol
			}
			ports = append(ports, s)
		}
		on = "on " + strings.Join(ports, ", ")
	}
	return from + " " + on
}

func describePeer(p kube.NetworkPolicyPeer) string {
	switch {
	case p.IPBlock != nil:
		s := "addresses " + p.IPBlock.CIDR
		if len(p.IPBlock.Except) > 0 {
			s += " except " + strings.Join(p.IPBlock.Except, ", ")
		}
		return s
	case p.PodSelector != nil && p.NamespaceSelector != nil:
		return "pods " + describeSelector(p.PodSelector) + " in namespaces " + describeSelector(p.NamespaceSelector)
	case p.NamespaceSelector != nil:
		return "pods in namespaces " + describeSelector(p.NamespaceSelector)
	case p.PodSelector != nil:
		return "pods " + describeSelector(p.PodSelector) + " of this namespace"
	}
	return "nothing"
}

func describeSelector(sel *kube.LabelSelector) string {
	var parts []string
	for k, v := range sel.MatchLabels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	for _, r := range sel.MatchExpressions {
		switch r.Operator {
		case "Exists":
			parts = append(parts, r.Key)
		case "DoesNotExist":
			parts = append(parts, "!"+r.Key)
		default:
			parts = append(parts, r.Key+" "+strings.ToLower(r.Operator)+" ("+strings.Join(r.Values, ", ")+")")
		}
	}
	if len(parts) == 0 {
		return "{all}"
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// volatileLabels change from one pod of a workload to the next; a policy
// for the workload must not select by them.
var volatileLabels = []string{"pod-template-hash", "controller-revision-hash", "statefulset.kubernetes.io/pod-name",
	"apps.kubernetes.io/pod-index", "pod-template-generation", "batch.kubernetes.io/controller-uid",
	"batch.kubernetes.io/job-name", "controller-uid", "job-name"}

// suggestPolicy writes a NetworkPolicy that admits every source on port,
// for the pods of the workload, next to the policies already there
// (policies add up: a connection any one of them admits is let in).
func suggestPolicy(pod kube.Pod, port int) string {
	keep := map[string]string{}
	for _, k := range []string{"app.kubernetes.io/name", "app"} {
		if v, ok := pod.Metadata.Labels[k]; ok {
			keep[k] = v
			break
		}
	}
	if len(keep) == 0 {
		for k, v := range pod.Metadata.Labels {
			if !slices.Contains(volatileLabels, k) {
				keep[k] = v
			}
		}
	}
	keys := make([]string, 0, len(keep))
	for k := range keep {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: allow-port-%d\n  namespace: %s\nspec:\n  podSelector:\n", port, pod.Metadata.Namespace)
	if len(keys) == 0 {
		b.WriteString("    matchLabels: {}\n")
	} else {
		b.WriteString("    matchLabels:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "      %s: %s\n", k, strconv.Quote(keep[k]))
		}
	}
	fmt.Fprintf(&b, "  policyTypes: [Ingress]\n  ingress:\n    - ports:\n        - port: %d\n", port)
	return b.String()
}
