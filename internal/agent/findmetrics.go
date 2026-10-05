package agent

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	// Looking for metrics asks at most maxFindWorkloads workloads, each at
	// up to maxFindPorts of its ports, for findTimeout each, all within
	// findBudget (before the server stops waiting).
	maxFindWorkloads = 300
	maxFindPorts     = 4
	findTimeout      = 3 * time.Second
	findBudget       = 15 * time.Second
)

var (
	// notHTTP are the usual ports of servers that do not speak HTTP. Asking
	// them for /metrics would only fill their logs with errors.
	notHTTP = map[int32]bool{
		22: true, 25: true, 53: true, 389: true, 587: true, 636: true, 1433: true, 1521: true, 2181: true, 2379: true,
		2380: true, 3306: true, 4222: true, 5432: true, 5672: true, 6379: true, 9042: true, 9092: true, 11211: true, 27017: true,
	}
	notHTTPName  = regexp.MustCompile(`(?i)grpc|postgres|mysql|maria|redis|mongo|kafka|amqp|ldap|smtp|dns|sql|tcp|udp|ssh|nats|memcache|etcd|zookeeper`)
	metricsNamed = regexp.MustCompile(`(?i)metric|prom`)
)

// metricsPod is the part of a pod that says where it may expose metrics.
type metricsPod struct {
	Metadata struct {
		kube.Meta
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Ports []struct {
				Name          string `json:"name"`
				ContainerPort int32  `json:"containerPort"`
				Protocol      string `json:"protocol"`
			} `json:"ports"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

// metricsPorts are the ports worth asking for metrics: the one the
// prometheus.io/port annotation names, then ports named like metrics, then
// the other TCP ports, leaving out those of servers that do not speak HTTP.
func metricsPorts(p metricsPod) []string {
	var named, other []string
	seen := map[string]bool{}
	add := func(list *[]string, port string) {
		if !seen[port] && protocol.CheckEndpoint(port, "/") == nil {
			seen[port] = true
			*list = append(*list, port)
		}
	}
	if a := p.Metadata.Annotations["prometheus.io/port"]; a != "" {
		add(&named, a)
	}
	for _, c := range p.Spec.Containers {
		for _, port := range c.Ports {
			if (port.Protocol != "" && port.Protocol != "TCP") || notHTTP[port.ContainerPort] || notHTTPName.MatchString(port.Name) {
				continue
			}
			if metricsNamed.MatchString(port.Name) {
				add(&named, strconv.Itoa(int(port.ContainerPort)))
			} else {
				add(&other, strconv.Itoa(int(port.ContainerPort)))
			}
		}
	}
	out := append(named, other...)
	return out[:min(len(out), maxFindPorts)]
}

type findCandidate struct {
	ns, workload, pod, path string
	ports                   []string
}

// findMetrics asks one running pod of each workload whether it exposes
// metrics, at its likely ports. Only where they are and how many are
// returned; nothing a pod answered is repeated.
func (e *Executor) findMetrics(ctx context.Context, cmd protocol.Command) (string, error) {
	var lists []string
	switch {
	case cmd.Namespace != "":
		if err := checkNamespace(cmd.Namespace); err != nil {
			return "", err
		}
		if !e.namespaceAllowed(cmd.Namespace) {
			return "", fmt.Errorf("namespace %q is outside this agent's scope", cmd.Namespace)
		}
		lists = []string{"/api/v1/namespaces/" + kube.Seg(cmd.Namespace) + "/pods"}
	case len(e.Namespaces) > 0:
		for _, ns := range e.Namespaces {
			lists = append(lists, "/api/v1/namespaces/"+kube.Seg(ns)+"/pods")
		}
	default:
		lists = []string{"/api/v1/pods"}
	}
	var pods []metricsPod
	for _, path := range lists {
		items, err := kube.ListAll[metricsPod](ctx, e.Kube, path, nil)
		if err != nil {
			return "", err
		}
		pods = append(pods, items...)
	}
	sort.Slice(pods, func(i, j int) bool {
		a, b := pods[i].Metadata, pods[j].Metadata
		return a.Namespace < b.Namespace || (a.Namespace == b.Namespace && a.Name < b.Name)
	})
	var cands []findCandidate
	seen := map[string]bool{}
	for _, p := range pods {
		m := p.Metadata
		if p.Status.Phase != "Running" || m.Annotations["prometheus.io/scrape"] == "false" {
			continue
		}
		workload := ownerOf(m.Meta)
		if workload == "" {
			workload = "Pod/" + m.Name
		}
		key := m.Namespace + "/" + workload
		if seen[key] {
			continue
		}
		seen[key] = true
		path := m.Annotations["prometheus.io/path"]
		if path == "" || protocol.CheckEndpoint("1", path) != nil {
			path = "/metrics"
		}
		if ports := metricsPorts(p); len(ports) > 0 {
			cands = append(cands, findCandidate{ns: m.Namespace, workload: workload, pod: m.Name, path: path, ports: ports})
		}
	}
	out := protocol.MetricsSources{Sources: []protocol.MetricsSource{}, Tried: len(cands)}
	if len(cands) > maxFindWorkloads {
		cands, out.Unfinished = cands[:maxFindWorkloads], true
	}
	ctx, cancel := context.WithTimeout(ctx, findBudget)
	defer cancel()
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, sampleConcurrency)
	for _, c := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			for _, port := range c.ports {
				pctx, cancel := context.WithTimeout(ctx, findTimeout)
				fams, _, err := e.readMetrics(pctx, c.ns, c.pod, port, c.path, math.MaxInt)
				cancel()
				if err == nil && len(fams) > 0 {
					mu.Lock()
					out.Sources = append(out.Sources, protocol.MetricsSource{Namespace: c.ns, Workload: c.workload, Pod: c.pod,
						Port: port, Path: c.path, Metrics: len(fams)})
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		out.Unfinished = true
	}
	sort.Slice(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		return a.Namespace < b.Namespace || (a.Namespace == b.Namespace && a.Workload < b.Workload)
	})
	return marshal(out)
}
