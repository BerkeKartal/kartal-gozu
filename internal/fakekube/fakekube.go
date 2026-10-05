// Package fakekube imitates the parts of the Kubernetes API that
// kartal-agent uses. It backs the tests and the kartal-demo command.
package fakekube

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Token is the bearer token the fake API expects.
const Token = "fake-kube-token"

// Patch records a request that changed something: PATCH, POST, PUT or DELETE.
type Patch struct {
	Method      string
	Path        string
	ContentType string
	Body        string
}

type Server struct {
	// Forbid makes the listed path suffixes answer 403, like missing RBAC.
	Forbid []string
	// NoMetrics simulates a cluster without metrics-server.
	NoMetrics bool
	// Extra adds that many generated namespaces with workloads, pods and
	// events on top of the fixed fixtures, to make demos look lived-in.
	Extra int
	// Live makes usage figures drift over time, so history charts have
	// something to show.
	Live bool
	// Variant is added to the image tags of every other generated team, so
	// a second cluster can run other versions than the first.
	Variant string

	mu       sync.Mutex
	patches  []Patch
	logQuery url.Values
}

func (f *Server) Patches() []Patch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Patch(nil), f.patches...)
}

func (f *Server) LogQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logQuery
}

const (
	nsDemo       = `{"metadata":{"name":"demo"},"status":{"phase":"Active"}}`
	nsKubeSystem = `{"metadata":{"name":"kube-system"},"status":{"phase":"Active"}}`
	nodeCP       = `{"metadata":{"name":"cp1","labels":{"node-role.kubernetes.io/control-plane":""}},
		"spec":{"taints":[{"key":"node-role.kubernetes.io/control-plane","effect":"NoSchedule"}]},
		"status":{"capacity":{"cpu":"4","memory":"8Gi","pods":"110"},"allocatable":{"cpu":"3800m","memory":"7Gi","pods":"110"},
			"conditions":[{"type":"MemoryPressure","status":"False"},{"type":"Ready","status":"True"}],
			"addresses":[{"type":"Hostname","address":"cp1"},{"type":"InternalIP","address":"10.0.0.1"}],
			"nodeInfo":{"kubeletVersion":"v1.30.14","osImage":"Ubuntu 22.04","containerRuntimeVersion":"containerd://1.7"}}}`
	nodeWorker = `{"metadata":{"name":"worker1"},"spec":{},
		"status":{"capacity":{"cpu":"8","memory":"16Gi","pods":"110"},"allocatable":{"cpu":"8","memory":"15Gi","pods":"110"},
			"conditions":[{"type":"MemoryPressure","status":"True"},{"type":"Ready","status":"False"}]}}`
	deployAPI = `{"metadata":{"name":"api","namespace":"demo","uid":"uid-deploy-api","creationTimestamp":"2026-09-01T10:00:00Z",
			"annotations":{"deployment.kubernetes.io/revision":"2",
				"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{},\"name\":\"api\",\"namespace\":\"demo\"},\"spec\":{\"replicas\":3,\"selector\":{\"matchLabels\":{\"app\":\"api\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"api\"}},\"spec\":{\"containers\":[{\"image\":\"registry.example.org/demo/api:abc123\",\"name\":\"app\"}]}}}}"}},
		"spec":{"replicas":2,"selector":{"matchLabels":{"app":"api"}},
			"template":{"metadata":{"labels":{"app":"api"}},"spec":{"containers":[{"name":"app","image":"registry.example.org/demo/api:abc123"}]}}},
		"status":{"readyReplicas":1,"updatedReplicas":2}}`
	dsExporter = `{"metadata":{"name":"node-exporter","namespace":"kube-system"},
		"spec":{"template":{"spec":{"containers":[{"name":"exporter","image":"exporter:1"}]}}},
		"status":{"desiredNumberScheduled":3,"numberReady":3,"updatedNumberScheduled":3}}`
	podAPI = `{"metadata":{"name":"api-7c9f-abcde","namespace":"demo","labels":{"pod-template-hash":"7c9f"},
			"ownerReferences":[{"kind":"ReplicaSet","name":"api-7c9f","controller":true}]},
		"spec":{"nodeName":"worker1","containers":[{"name":"app","image":"x",
				"resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"500m","memory":"256Mi"}}}],
			"initContainers":[{"name":"migrate","image":"x","resources":{"requests":{"cpu":"200m","memory":"64Mi"}}}]},
		"status":{"phase":"Running","podIP":"10.0.0.5","startTime":"2026-09-29T08:00:00Z",
			"containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`
	podExporter = `{"metadata":{"name":"node-exporter-x1","namespace":"kube-system",
			"ownerReferences":[{"kind":"DaemonSet","name":"node-exporter","controller":true}]},
		"spec":{"nodeName":"cp1","containers":[{"name":"exporter","image":"exporter:1"}]},
		"status":{"phase":"Running","containerStatuses":[{"name":"exporter","ready":true,"restartCount":0,"state":{"running":{}}}]}}`
	svcAPI = `{"metadata":{"name":"api","namespace":"demo"},
		"spec":{"type":"ClusterIP","clusterIP":"10.96.0.10","selector":{"app":"api"},
			"ports":[{"name":"http","port":80,"targetPort":"http","protocol":"TCP"},{"name":"https","port":443,"targetPort":8443,"protocol":"TCP"}]}}`
	ingAPI = `{"metadata":{"name":"api","namespace":"demo"},
		"spec":{"ingressClassName":"traefik","tls":[{"hosts":["demo.example.org"]}],
			"rules":[{"host":"demo.example.org","http":{"paths":[{"path":"/","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}}`
	pvcData = `{"metadata":{"name":"data","namespace":"demo"},
		"spec":{"storageClassName":"local","volumeName":"pv-1","accessModes":["ReadWriteOnce"]},
		"status":{"phase":"Bound","capacity":{"storage":"10Gi"}}}`
	jobBackup = `{"metadata":{"name":"backup-2912","namespace":"demo","ownerReferences":[{"kind":"CronJob","name":"backup","controller":true}]},
		"spec":{"completions":1},"status":{"succeeded":1,"startTime":"2026-09-29T03:00:00Z","completionTime":"2026-09-29T03:01:00Z",
			"conditions":[{"type":"Complete","status":"True"}]}}`
	cronBackup   = `{"metadata":{"name":"backup","namespace":"demo"},"spec":{"schedule":"0 3 * * *"},"status":{"lastScheduleTime":"2026-09-29T03:00:00Z"}}`
	eventBackoff = `{"metadata":{"namespace":"demo","creationTimestamp":"2026-09-29T08:00:00Z"},
		"involvedObject":{"kind":"Pod","name":"api-7c9f-abcde","namespace":"demo"},
		"reason":"BackOff","message":"Back-off restarting failed container","type":"Warning","count":12,
		"lastTimestamp":"2026-09-29T09:00:00Z"}`
	secretDB = `{"kind":"Secret","apiVersion":"v1",
		"metadata":{"name":"db","namespace":"demo","managedFields":[{"manager":"kubectl"}],
			"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"data\":{\"password\":\"c3VwZXItc2VjcmV0\"}}","team":"payments"}},
		"type":"Opaque","data":{"password":"c3VwZXItc2VjcmV0"}}`
	configApp = `{"kind":"ConfigMap","apiVersion":"v1",
		"metadata":{"name":"app-config","namespace":"demo","managedFields":[{"manager":"kubectl"}]},
		"data":{"LOG_LEVEL":"debug"}}`
	coreResources = `{"groupVersion":"v1","resources":[
		{"name":"pods","namespaced":true,"kind":"Pod","verbs":["get","list"]},
		{"name":"pods/log","namespaced":true,"kind":"Pod","verbs":["get"]},
		{"name":"bindings","namespaced":true,"kind":"Binding","verbs":["create"]},
		{"name":"configmaps","namespaced":true,"kind":"ConfigMap","verbs":["get","list"]},
		{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["get","list"]},
		{"name":"nodes","namespaced":false,"kind":"Node","verbs":["get","list"]}]}`
	apiGroups = `{"groups":[
		{"name":"apps","preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},
		{"name":"traefik.io","preferredVersion":{"groupVersion":"traefik.io/v1alpha1","version":"v1alpha1"}},
		{"name":"broken.example.org","preferredVersion":{"groupVersion":"broken.example.org/v1","version":"v1"}}]}`
	appsResources    = `{"groupVersion":"apps/v1","resources":[{"name":"deployments","namespaced":true,"kind":"Deployment","verbs":["get","list"]}]}`
	traefikResources = `{"groupVersion":"traefik.io/v1alpha1","resources":[{"name":"ingressroutes","namespaced":true,"kind":"IngressRoute","verbs":["get","list"]}]}`
)

func list(items ...string) string { return `{"items":[` + strings.Join(items, ",") + `]}` }

func page(cont string, items ...string) string {
	return `{"metadata":{"continue":"` + cont + `"},"items":[` + strings.Join(items, ",") + `]}`
}

// metaItem is what the API server returns for a metadata-only list.
func metaItem(ns, name string) string {
	return `{"metadata":{"name":"` + name + `","namespace":"` + ns + `","creationTimestamp":"2026-09-20T10:00:00Z"}}`
}

// extra generates the demo namespaces: every team runs a three-replica
// "web" deployment; every third one has a crash-looping replica.
type extra struct {
	namespaces, deployments, pods, podMetrics, events, pvcs []string
	volumes                                                 []volumeUse
}

func (f *Server) extra() extra {
	var e extra
	for i := 1; i <= f.Extra; i++ {
		ns := fmt.Sprintf("team-%02d", i)
		broken := i%3 == 0
		ready := 3
		if broken {
			ready = 2
		}
		e.namespaces = append(e.namespaces, fmt.Sprintf(`{"metadata":{"name":%q},"status":{"phase":"Active"}}`, ns))
		// Every fourth team keeps data on a volume; team-08's is nearly full.
		if i%4 == 0 {
			e.pvcs = append(e.pvcs, fmt.Sprintf(`{"metadata":{"name":"data","namespace":%q,"creationTimestamp":"2026-09-%02dT10:00:00Z"},
				"spec":{"storageClassName":"local","volumeName":"pv-%s","accessModes":["ReadWriteOnce"]},
				"status":{"phase":"Bound","capacity":{"storage":"20Gi"}}}`, ns, 1+i%28, ns))
			pct := int64(20 + (i*13)%60)
			if i == 8 {
				pct = 91
			}
			e.volumes = append(e.volumes, volumeUse{ns: ns, claim: "data", node: "cp1", used: 20 * gib * pct / 100, capacity: 20 * gib,
				inodesUsed: 12_000 * int64(i), inodes: 1_310_720})
		}
		tag := fmt.Sprintf("1.%d", i)
		switch {
		case f.Variant != "" && i%2 == 1:
			tag += f.Variant
		case f.Live && i == 2:
			// team-02 rolls out a new build every two minutes, so the
			// demo's timeline has something to show.
			tag += fmt.Sprintf(".%d", time.Now().Unix()/120%100)
		}
		e.deployments = append(e.deployments, fmt.Sprintf(`{"metadata":{"name":"web","namespace":%q,"creationTimestamp":"2026-09-%02dT10:00:00Z"},
			"spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"registry.example.org/%s/web:%s"}]}}},
			"status":{"readyReplicas":%d,"updatedReplicas":3}}`, ns, 1+i%28, ns, tag, ready))
		for r := 1; r <= 3; r++ {
			name := fmt.Sprintf("web-5d8c-%02d%d", i, r)
			node := []string{"cp1", "worker1"}[r%2]
			state, isReady, restarts := `{"running":{}}`, true, 0
			if broken && r == 3 {
				state, isReady, restarts = `{"waiting":{"reason":"CrashLoopBackOff"}}`, false, 7+i
				e.events = append(e.events, fmt.Sprintf(`{"metadata":{"namespace":%q},
					"involvedObject":{"kind":"Pod","name":%q,"namespace":%q},
					"reason":"BackOff","message":"Back-off restarting failed container web","type":"Warning","count":%d,
					"lastTimestamp":"2026-09-29T08:%02d:00Z"}`, ns, name, ns, restarts, i%60))
			}
			e.pods = append(e.pods, fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,"labels":{"pod-template-hash":"5d8c"},
				"annotations":{"prometheus.io/scrape":"true","prometheus.io/port":"9100"},
				"ownerReferences":[{"kind":"ReplicaSet","name":"web-5d8c","controller":true}]},
				"spec":{"nodeName":%q,"containers":[
					{"name":"web","image":"x","ports":[{"name":"http","containerPort":8080},{"name":"metrics","containerPort":9100}],"resources":{"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"cpu":"250m","memory":"256Mi"}}},
					{"name":"proxy","image":"y","resources":{"requests":{"cpu":"10m","memory":"32Mi"}}}]},
				"status":{"phase":"Running","podIP":"10.1.%d.%d","startTime":"2026-09-2%dT08:00:00Z",
				"containerStatuses":[{"name":"web","ready":%t,"restartCount":%d,"state":%s},{"name":"proxy","ready":true,"restartCount":0,"state":{"running":{}}}]}}`,
				name, ns, node, i, r, r, isReady, restarts, state))
			e.podMetrics = append(e.podMetrics, fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q},
				"containers":[{"usage":{"cpu":"%dm","memory":"%dMi"}}]}`, name, ns, f.drift(20+i*7+r*3, i*3+r), f.drift(90+i*11+r*5, i*5+r)))
		}
		// Every fifth team still lists a pod that was evicted when worker1
		// ran short of disk; its Deployment has long replaced it.
		if i%5 == 0 {
			e.pods = append(e.pods, fmt.Sprintf(`{"metadata":{"name":"web-5d8c-%02dx","namespace":%q,"labels":{"pod-template-hash":"5d8c"},
				"ownerReferences":[{"kind":"ReplicaSet","name":"web-5d8c","controller":true}]},
				"spec":{"nodeName":"worker1","containers":[{"name":"web","image":"x"},{"name":"proxy","image":"y"}]},
				"status":{"phase":"Failed","reason":"Evicted","message":"The node was low on resource: ephemeral-storage.",
				"startTime":"2026-09-20T08:00:00Z"}}`, i, ns))
		}
	}
	return e
}

func writeStatus(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "code": code, "reason": reason, "message": msg})
}

func (f *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+Token {
		writeStatus(w, http.StatusUnauthorized, "Unauthorized", "bad token")
		return
	}
	p := r.URL.Path
	for _, suffix := range f.Forbid {
		if strings.HasSuffix(p, suffix) {
			writeStatus(w, http.StatusForbidden, "Forbidden", "cannot list "+suffix)
			return
		}
	}
	if strings.HasSuffix(p, "/exec") {
		f.serveExec(w, r)
		return
	}
	if r.Method != http.MethodGet {
		f.serveChange(w, r)
		return
	}
	if strings.HasPrefix(p, "/apis/metrics.k8s.io/") && f.NoMetrics {
		writeStatus(w, http.StatusNotFound, "NotFound", "the server could not find the requested resource")
		return
	}
	// Names-only lists must never pull object contents.
	metaOnly := strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList")
	requireMeta := func() bool {
		if !metaOnly {
			writeStatus(w, http.StatusBadRequest, "BadRequest", "full objects requested where names were enough")
		}
		return metaOnly
	}
	x := f.extra()

	if f.serveMore(w, r, x, metaOnly) || f.serveStorage(w, r, x, metaOnly) || f.servePodMetrics(w, r) || serveTeamPods(w, p, x) {
		return
	}
	if ns, pod, ok := logPath(p); ok {
		f.mu.Lock()
		f.logQuery = r.URL.Query()
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if pod == "api-7c9f-abcde" {
			if r.URL.Query().Get("previous") == "true" {
				io.WriteString(w, "2026-09-29T07:59:58Z panic: cannot reach db:5432: connection refused\n")
				return
			}
			io.WriteString(w, "line1\nline2\n")
			return
		}
		for i := 1; i <= 40; i++ {
			fmt.Fprintf(w, "2026-09-29T09:%02d:%02dZ INFO %s/%s handled request id=%04d status=200\n", i/60, i%60, ns, pod, i)
		}
		return
	}

	switch p {
	case "/version":
		io.WriteString(w, `{"gitVersion":"v1.30.14"}`)
	case "/api/v1/namespaces":
		io.WriteString(w, list(append([]string{nsDemo, nsKubeSystem}, x.namespaces...)...))
	case "/api/v1/namespaces/demo":
		io.WriteString(w, nsDemo)
	case "/api/v1/nodes":
		io.WriteString(w, list(nodeCP, nodeWorker))
	case "/apis/apps/v1/deployments":
		io.WriteString(w, list(append([]string{deployAPI}, x.deployments...)...))
	case "/apis/apps/v1/namespaces/demo/deployments":
		io.WriteString(w, list(deployAPI))
	case "/apis/apps/v1/statefulsets", "/apis/apps/v1/namespaces/demo/statefulsets":
		io.WriteString(w, list())
	case "/apis/apps/v1/daemonsets":
		io.WriteString(w, list(dsExporter))
	case "/apis/apps/v1/namespaces/demo/daemonsets":
		io.WriteString(w, list())
	case "/api/v1/pods":
		// Two pages, to exercise pagination.
		if r.URL.Query().Get("continue") == "" {
			io.WriteString(w, page("page-2", podAPI))
		} else {
			io.WriteString(w, page("", append([]string{podExporter}, x.pods...)...))
		}
	case "/api/v1/namespaces/demo/pods":
		io.WriteString(w, list(podAPI))
	case "/api/v1/services", "/api/v1/namespaces/demo/services":
		io.WriteString(w, list(svcAPI))
	case "/apis/networking.k8s.io/v1/ingresses", "/apis/networking.k8s.io/v1/namespaces/demo/ingresses":
		io.WriteString(w, list(ingAPI))
	case "/api/v1/configmaps", "/api/v1/namespaces/demo/configmaps":
		if requireMeta() {
			io.WriteString(w, list(metaItem("demo", "app-config")))
		}
	case "/api/v1/secrets", "/api/v1/namespaces/demo/secrets":
		if requireMeta() {
			io.WriteString(w, list(metaItem("demo", "db")))
		}
	case "/api/v1/persistentvolumeclaims":
		io.WriteString(w, list(append([]string{pvcData}, x.pvcs...)...))
	case "/api/v1/namespaces/demo/persistentvolumeclaims":
		io.WriteString(w, list(pvcData))
	case "/apis/batch/v1/jobs", "/apis/batch/v1/namespaces/demo/jobs":
		io.WriteString(w, list(jobBackup))
	case "/apis/batch/v1/cronjobs", "/apis/batch/v1/namespaces/demo/cronjobs":
		io.WriteString(w, list(cronBackup))
	case "/api/v1/events", "/api/v1/namespaces/demo/events":
		if r.URL.Query().Get("fieldSelector") != "type=Warning" {
			writeStatus(w, http.StatusBadRequest, "BadRequest", "expected warning selector")
			return
		}
		events := []string{eventBackoff}
		if p == "/api/v1/events" {
			events = append(events, x.events...)
		}
		io.WriteString(w, list(events...))
	case "/apis/metrics.k8s.io/v1beta1/nodes":
		io.WriteString(w, list(fmt.Sprintf(`{"metadata":{"name":"cp1"},"usage":{"cpu":"%dm","memory":"%dMi"}}`, f.drift(250, 1), f.drift(1024, 2))))
	case "/apis/metrics.k8s.io/v1beta1/pods", "/apis/metrics.k8s.io/v1beta1/namespaces/demo/pods":
		metrics := []string{`{"metadata":{"name":"api-7c9f-abcde","namespace":"demo"},
			"containers":[{"usage":{"cpu":"` + strconv.Itoa(f.drift(100, 7)) + `m","memory":"64Mi"}},{"usage":{"cpu":"20m","memory":"16Mi"}}]}`}
		if p == "/apis/metrics.k8s.io/v1beta1/pods" {
			metrics = append(metrics, x.podMetrics...)
		}
		io.WriteString(w, list(metrics...))
	case "/api/v1":
		io.WriteString(w, coreResources)
	case "/apis":
		io.WriteString(w, apiGroups)
	case "/apis/apps/v1":
		io.WriteString(w, appsResources)
	case "/apis/traefik.io/v1alpha1":
		io.WriteString(w, traefikResources)
	case "/apis/broken.example.org/v1":
		writeStatus(w, http.StatusServiceUnavailable, "ServiceUnavailable", "aggregated API is down")
	case "/apis/traefik.io/v1alpha1/namespaces/demo/ingressroutes", "/apis/traefik.io/v1alpha1/ingressroutes":
		if requireMeta() {
			io.WriteString(w, list(metaItem("demo", "web"), metaItem("demo", "admin")))
		}
	case "/api/v1/namespaces/demo/secrets/db":
		io.WriteString(w, secretDB)
	case "/api/v1/namespaces/demo/configmaps/app-config":
		io.WriteString(w, configApp)
	default:
		if obj := f.find(p, x); obj != nil {
			json.NewEncoder(w).Encode(obj)
			return
		}
		writeStatus(w, http.StatusNotFound, "NotFound", p+" not found")
	}
}

// collections lists every fixture by the path of its cluster-wide list.
func (f *Server) collections(x extra) map[string][]string {
	return map[string][]string{
		"/api/v1/namespaces":                   append([]string{nsDemo, nsKubeSystem}, x.namespaces...),
		"/api/v1/nodes":                        {nodeCP, nodeWorker},
		"/api/v1/pods":                         append([]string{podAPI, podExporter}, x.pods...),
		"/api/v1/services":                     {svcAPI},
		"/api/v1/persistentvolumeclaims":       append([]string{pvcData}, x.pvcs...),
		"/apis/apps/v1/deployments":            append([]string{deployAPI}, x.deployments...),
		"/apis/apps/v1/daemonsets":             {dsExporter},
		"/apis/networking.k8s.io/v1/ingresses": {ingAPI},
		"/apis/batch/v1/jobs":                  {jobBackup},
		"/apis/batch/v1/cronjobs":              {cronBackup},
		"/apis/apps/v1/replicasets":            {rsAPICurrent, rsAPIPrevious},
		"/api/v1/secrets":                      helmSecrets(),
		"/api/v1/configmaps":                   {configApp},
	}
}

var kinds = map[string]string{
	"namespaces": "Namespace", "nodes": "Node", "pods": "Pod", "services": "Service",
	"persistentvolumeclaims": "PersistentVolumeClaim", "deployments": "Deployment", "daemonsets": "DaemonSet",
	"replicasets": "ReplicaSet", "secrets": "Secret", "configmaps": "ConfigMap",
	"ingresses": "Ingress", "jobs": "Job", "cronjobs": "CronJob",
}

// find returns the fixture a single-object path such as
// /apis/apps/v1/namespaces/demo/deployments/api names, or nil.
func (f *Server) find(p string, x extra) map[string]any {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	var prefix, ns string
	switch {
	case len(parts) == 4 && parts[0] == "api": // /api/v1/{resource}/{name}
		prefix = "/api/" + parts[1]
	case len(parts) == 6 && parts[0] == "api" && parts[2] == "namespaces":
		prefix, ns, parts = "/api/"+parts[1], parts[3], parts[2:]
	case len(parts) == 5 && parts[0] == "apis":
		prefix, parts = "/apis/"+parts[1]+"/"+parts[2], parts[1:]
	case len(parts) == 7 && parts[0] == "apis" && parts[3] == "namespaces":
		prefix, ns, parts = "/apis/"+parts[1]+"/"+parts[2], parts[4], parts[3:]
	default:
		return nil
	}
	resource, name := parts[len(parts)-2], parts[len(parts)-1]
	for _, item := range f.collections(x)[prefix+"/"+resource] {
		var obj map[string]any
		if json.Unmarshal([]byte(item), &obj) != nil {
			continue
		}
		md, _ := obj["metadata"].(map[string]any)
		if itemNS, _ := md["namespace"].(string); md["name"] != name || itemNS != ns {
			continue
		}
		obj["kind"] = kinds[resource]
		obj["apiVersion"] = strings.TrimPrefix(strings.TrimPrefix(prefix, "/apis/"), "/api/")
		return obj
	}
	return nil
}

// logPath matches /api/v1/namespaces/{ns}/pods/{pod}/log.
func logPath(p string) (ns, pod string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) == 7 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "namespaces" && parts[4] == "pods" && parts[6] == "log" {
		return parts[3], parts[5], true
	}
	return "", "", false
}
