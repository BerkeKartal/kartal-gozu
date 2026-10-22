package agent

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/fakekube"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func decodeAs[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode %s: %v", s, err)
	}
	return v
}

func TestPolicyReport(t *testing.T) {
	pod := decodeAs[kube.Pod](t, `{"metadata":{"name":"ctl-0","namespace":"ops",
		"labels":{"app.kubernetes.io/name":"ctl","statefulset.kubernetes.io/pod-name":"ctl-0"}},
		"spec":{"containers":[{"name":"c","ports":[{"name":"metrics","containerPort":8082}]}]}}`)
	policy := func(s string) kube.NetworkPolicy { return decodeAs[kube.NetworkPolicy](t, s) }
	podsOnly := policy(`{"metadata":{"name":"ctl-policy"},"spec":{
		"podSelector":{"matchLabels":{"app.kubernetes.io/name":"ctl"}},"policyTypes":["Ingress"],
		"ingress":[{"from":[{"namespaceSelector":{}}],"ports":[{"port":8082}]}]}}`)
	other := policy(`{"metadata":{"name":"other"},"spec":{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[]}}`)
	egress := policy(`{"metadata":{"name":"egress"},"spec":{"podSelector":{},"policyTypes":["Egress"]}}`)
	open := policy(`{"metadata":{"name":"open"},"spec":{"podSelector":{"matchExpressions":[{"key":"app.kubernetes.io/name","operator":"In","values":["ctl","x"]}]},
		"ingress":[{"ports":[{"port":"metrics"}]}]}}`)
	ranges := policy(`{"metadata":{"name":"ranges"},"spec":{"podSelector":{},
		"ingress":[{"from":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.9.0.0/16"]}}],"ports":[{"port":8000,"endPort":8100}]}]}}`)
	elsewhere := policy(`{"metadata":{"name":"elsewhere"},"spec":{"podSelector":{},
		"ingress":[{"ports":[{"port":9090}]},{"ports":[{"port":8082,"protocol":"UDP"}]}]}}`)

	cases := []struct {
		name     string
		policies []kube.NetworkPolicy
		verdict  string
		admits   []string
	}{
		{"no policy", nil, "none", nil},
		{"policies for others only", []kube.NetworkPolicy{other, egress}, "none", nil},
		{"pods only", []kube.NetworkPolicy{podsOnly, other}, "blocked", []string{"pods"}},
		{"another policy opens it", []kube.NetworkPolicy{podsOnly, open}, "open", []string{"pods", "all"}},
		{"address ranges", []kube.NetworkPolicy{podsOnly, ranges}, "maybe", []string{"pods", "ranges"}},
		{"open on other ports", []kube.NetworkPolicy{elsewhere}, "blocked", []string{"nothing"}},
	}
	for _, c := range cases {
		rep := policyReport(pod, c.policies, 8082)
		var admits []string
		for _, m := range rep.Policies {
			admits = append(admits, m.Admits)
		}
		if rep.Verdict != c.verdict || strings.Join(admits, ",") != strings.Join(c.admits, ",") {
			t.Errorf("%s: verdict %s, admits %v; want %s, %v", c.name, rep.Verdict, admits, c.verdict, c.admits)
		}
		if (rep.Suggestion != "") != (c.verdict == "blocked" || c.verdict == "maybe") {
			t.Errorf("%s: suggestion %q", c.name, rep.Suggestion)
		}
	}

	rep := policyReport(pod, []kube.NetworkPolicy{podsOnly, ranges}, 8082)
	if got := rep.Policies[0].Rules; len(got) != 1 || got[0] != "from pods in namespaces {all} on 8082" {
		t.Errorf("rules of ctl-policy: %q", got)
	}
	if got := rep.Policies[1].Rules[0]; got != "from addresses 10.0.0.0/8 except 10.9.0.0/16 on 8000-8100" {
		t.Errorf("rules of ranges: %q", got)
	}
	want := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-port-8082
  namespace: ops
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: "ctl"
  policyTypes: [Ingress]
  ingress:
    - ports:
        - port: 8082
`
	if rep.Suggestion != want {
		t.Errorf("suggestion:\n%s\nwant:\n%s", rep.Suggestion, want)
	}
}

func TestSelects(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	yes := []string{`{}`, `{"matchLabels":{"app":"web"}}`,
		`{"matchExpressions":[{"key":"tier","operator":"NotIn","values":["back"]},{"key":"app","operator":"Exists"},{"key":"x","operator":"DoesNotExist"}]}`}
	no := []string{`{"matchLabels":{"app":"api"}}`, `{"matchLabels":{"zone":"a"}}`,
		`{"matchExpressions":[{"key":"tier","operator":"In","values":["back"]}]}`,
		`{"matchExpressions":[{"key":"app","operator":"DoesNotExist"}]}`,
		`{"matchExpressions":[{"key":"app","operator":"Gt","values":["1"]}]}`}
	for _, s := range yes {
		sel := decodeAs[kube.LabelSelector](t, s)
		if !selects(&sel, labels) {
			t.Errorf("%s should select %v", s, labels)
		}
	}
	for _, s := range no {
		sel := decodeAs[kube.LabelSelector](t, s)
		if selects(&sel, labels) {
			t.Errorf("%s should not select %v", s, labels)
		}
	}
}

func TestNetworkPoliciesCommand(t *testing.T) {
	srv := httptest.NewServer(&fakekube.Server{Extra: 2})
	t.Cleanup(srv.Close)
	e := &Executor{Kube: kube.New(srv.URL, fakekube.Token, false)}
	res := run(t, e, protocol.Command{Type: protocol.CommandNetworkPolicies, Namespace: "team-01", Name: "web-5d8c-011", Port: "9100"})
	if !res.OK {
		t.Fatal(res.Error)
	}
	rep := decodeAs[protocol.PolicyReport](t, res.Output)
	if rep.Verdict != "blocked" || len(rep.Policies) != 1 || rep.Policies[0].Name != "allow-from-pods" ||
		!strings.Contains(rep.Suggestion, `app: "web"`) {
		t.Errorf("report: %+v", rep)
	}
	for _, bad := range []protocol.Command{
		{Type: protocol.CommandNetworkPolicies, Namespace: "team-01", Name: "web-5d8c-011", Port: "http"},
		{Type: protocol.CommandNetworkPolicies, Namespace: "../x", Name: "web", Port: "80"},
		{Type: protocol.CommandNetworkPolicies, Namespace: "team-01", Name: "missing", Port: "80"},
	} {
		if res := run(t, e, bad); res.OK {
			t.Errorf("%+v should fail", bad)
		}
	}
}
