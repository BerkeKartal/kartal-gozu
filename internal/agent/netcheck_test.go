package agent

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

type refusing struct{}

func (refusing) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

func netCheckCmd(t *testing.T, id string, req protocol.NetCheckRequest) protocol.Command {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{ID: id, Type: protocol.CommandNetCheck, Body: string(b)}
}

func TestNetCheckNeedsOptIn(t *testing.T) {
	_, kc := NewFakeKube(t)
	e := &Executor{Kube: kc}
	res := run(t, e, netCheckCmd(t, "abcdef0123456789", protocol.NetCheckRequest{Targets: []string{"db:5432"}, Agent: true}))
	if res.OK || !strings.Contains(res.Error, "KARTAL_NETWORK_CHECKS") {
		t.Errorf("checks must be off by default: %+v", res)
	}
	if strings.Contains(strings.Join(e.Capabilities(), ","), "netcheck") {
		t.Error("the capability must not be offered")
	}
}

func TestNetCheckFromNodes(t *testing.T) {
	f, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowNetCheck: true, NetCheckNamespace: "kartal", NetCheckImage: "registry.example.org/kartal-gozu:1", Dialer: refusing{}}
	res := run(t, e, netCheckCmd(t, "abcdef0123456789abcdef01", protocol.NetCheckRequest{
		Targets: []string{"db.example.org:1521", "web.example.org:443", "db.example.org:1521"}, Agent: true, Nodes: []string{"cp1", "worker1", "nope", "cp1"}}))
	if !res.OK {
		t.Fatal(res.Error)
	}
	started := decodeAs[protocol.NetCheckStarted](t, res.Output)
	if started.ID != "abcdef0123456789" || strings.Join(started.Nodes, ",") != "cp1,worker1" || started.Errors["nope"] != "no such node" ||
		strings.Join(started.Targets, " ") != "db.example.org:1521 web.example.org:443" {
		t.Errorf("started: %+v", started)
	}
	if len(started.Agent) != 2 || started.Agent[0].Result != "refused" || started.Agent[1].Target != "web.example.org:443" {
		t.Errorf("the agent's own attempts: %+v", started.Agent)
	}

	var pods []map[string]any
	for _, p := range f.Patches() {
		if p.Method == "POST" {
			if p.Path != "/api/v1/namespaces/kartal/pods" {
				t.Errorf("pod created at %s", p.Path)
			}
			var pod map[string]any
			json.Unmarshal([]byte(p.Body), &pod)
			pods = append(pods, pod)
		}
	}
	if len(pods) != 2 {
		t.Fatalf("want a pod per node, got %d", len(pods))
	}
	spec := pods[0]["spec"].(map[string]any)
	c := spec["containers"].([]any)[0].(map[string]any)
	if spec["nodeName"] != "cp1" || spec["automountServiceAccountToken"] != false || c["image"] != "registry.example.org/kartal-gozu:1" ||
		strings.Join(toStrings(c["command"]), " ") != AgentBinary+" net-check" ||
		strings.Join(toStrings(c["args"]), " ") != "db.example.org:1521 web.example.org:443" {
		t.Errorf("pod: %+v", pods[0])
	}

	status := run(t, e, protocol.Command{Type: protocol.CommandNetCheckStatus, Name: started.ID})
	if !status.OK {
		t.Fatal(status.Error)
	}
	st := decodeAs[protocol.NetCheckStatus](t, status.Output)
	if !st.Done || len(st.Nodes) != 2 || st.Nodes[0].Node != "cp1" || st.Nodes[0].State != "done" {
		t.Fatalf("status: %+v", st)
	}
	if r := st.Nodes[0].Results; len(r) != 2 || r[0].Result != "timeout" || r[1].Result != "ok" {
		t.Errorf("cp1 should not reach port 1521: %+v", r)
	}
	if r := st.Nodes[1].Results; len(r) != 2 || r[0].Result != "ok" {
		t.Errorf("worker1 should: %+v", r)
	}
	// Finished, the pods are gone.
	again := decodeAs[protocol.NetCheckStatus](t, run(t, e, protocol.Command{Type: protocol.CommandNetCheckStatus, Name: started.ID}).Output)
	if len(again.Nodes) != 0 {
		t.Errorf("the pods should have been removed: %+v", again)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestNetCheckRefuses(t *testing.T) {
	_, kc := NewFakeKube(t)
	e := &Executor{Kube: kc, AllowNetCheck: true, NetCheckNamespace: "kartal", NetCheckImage: "img", Dialer: refusing{}}
	for name, req := range map[string]protocol.NetCheckRequest{
		"no targets":   {Agent: true},
		"bad target":   {Targets: []string{"db"}, Agent: true},
		"from nowhere": {Targets: []string{"db:1"}},
	} {
		if res := run(t, e, netCheckCmd(t, "abcdef0123456789", req)); res.OK {
			t.Errorf("%s: should fail", name)
		}
	}
	if res := run(t, e, protocol.Command{Type: protocol.CommandNetCheckStatus, Name: "x=y"}); res.OK {
		t.Error("an invalid check id must be refused")
	}
	limited := &Executor{Kube: kc, AllowNetCheck: true, NetCheckNamespace: "kartal", NetCheckImage: "img", Dialer: refusing{}, Namespaces: []string{"demo"}}
	res := run(t, limited, netCheckCmd(t, "abcdef0123456789", protocol.NetCheckRequest{Targets: []string{"db:1"}, Nodes: []string{"cp1"}}))
	if res.OK || !strings.Contains(res.Error, "namespaces") {
		t.Errorf("a namespaced agent must not start pods on nodes: %+v", res)
	}
	// Outside a cluster, the nodes' part fails and the agent's still counts.
	outside := &Executor{Kube: kc, AllowNetCheck: true, Dialer: refusing{}}
	res = run(t, outside, netCheckCmd(t, "abcdef0123456789", protocol.NetCheckRequest{Targets: []string{"db:1"}, Agent: true, Nodes: []string{"cp1"}}))
	started := decodeAs[protocol.NetCheckStarted](t, res.Output)
	if !res.OK || len(started.Agent) != 1 || started.ID != "" || started.Errors["cp1"] == "" {
		t.Errorf("outside a cluster: %+v %+v", res, started)
	}
}
