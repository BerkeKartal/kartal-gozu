package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
)

type recordedPatch struct {
	Path        string
	ContentType string
	Body        string
}

// FakeKube imitates the parts of the Kubernetes API the agent uses.
type FakeKube struct {
	mu       sync.Mutex
	Patches  []recordedPatch
	LogQuery url.Values
	// Forbid makes the listed path suffixes answer 403, like missing RBAC.
	Forbid []string
	// NoMetrics simulates a cluster without metrics-server.
	NoMetrics bool
}

const fakeKubeToken = "fake-kube-token"

// NewFakeKube starts the fake API and returns a client pointed at it.
func NewFakeKube(t *testing.T) (*FakeKube, *kube.Client) {
	t.Helper()
	f := &FakeKube{}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, kube.New(srv.URL, fakeKubeToken, false)
}

func (f *FakeKube) logQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.LogQuery
}

func (f *FakeKube) patches() []recordedPatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedPatch(nil), f.Patches...)
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
	deployAPI = `{"metadata":{"name":"api","namespace":"demo","creationTimestamp":"2026-09-01T10:00:00Z"},
		"spec":{"replicas":2,"template":{"spec":{"containers":[{"name":"app","image":"registry.example.org/demo/api:abc123"}]}}},
		"status":{"readyReplicas":1,"updatedReplicas":2}}`
	dsExporter = `{"metadata":{"name":"node-exporter","namespace":"kube-system"},
		"spec":{"template":{"spec":{"containers":[{"name":"exporter","image":"exporter:1"}]}}},
		"status":{"desiredNumberScheduled":3,"numberReady":3,"updatedNumberScheduled":3}}`
	podAPI = `{"metadata":{"name":"api-7c9f-abcde","namespace":"demo","labels":{"pod-template-hash":"7c9f"},
			"ownerReferences":[{"kind":"ReplicaSet","name":"api-7c9f","controller":true}]},
		"spec":{"nodeName":"worker1","containers":[{"name":"app","image":"x"}]},
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
		"spec":{"completions":1},"status":{"succeeded":1,"startTime":"2026-09-29T03:00:00Z","completionTime":"2026-09-29T03:01:00Z"}}`
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

func (f *FakeKube) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+fakeKubeToken {
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
	if r.Method == http.MethodPatch {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.Patches = append(f.Patches, recordedPatch{Path: p, ContentType: r.Header.Get("Content-Type"), Body: string(b)})
		f.mu.Unlock()
		if p == "/apis/apps/v1/namespaces/demo/deployments/api" {
			io.WriteString(w, "{}")
			return
		}
		writeStatus(w, http.StatusNotFound, "NotFound", "not found")
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

	switch p {
	case "/version":
		io.WriteString(w, `{"gitVersion":"v1.30.14"}`)
	case "/api/v1/namespaces":
		io.WriteString(w, list(nsDemo, nsKubeSystem))
	case "/api/v1/namespaces/demo":
		io.WriteString(w, nsDemo)
	case "/api/v1/nodes":
		io.WriteString(w, list(nodeCP, nodeWorker))
	case "/apis/apps/v1/deployments", "/apis/apps/v1/namespaces/demo/deployments":
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
			io.WriteString(w, page("", podExporter))
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
	case "/api/v1/persistentvolumeclaims", "/api/v1/namespaces/demo/persistentvolumeclaims":
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
		io.WriteString(w, list(eventBackoff))
	case "/apis/metrics.k8s.io/v1beta1/nodes":
		io.WriteString(w, list(`{"metadata":{"name":"cp1"},"usage":{"cpu":"250m","memory":"1Gi"}}`))
	case "/apis/metrics.k8s.io/v1beta1/pods", "/apis/metrics.k8s.io/v1beta1/namespaces/demo/pods":
		io.WriteString(w, list(`{"metadata":{"name":"api-7c9f-abcde","namespace":"demo"},
			"containers":[{"usage":{"cpu":"100m","memory":"64Mi"}},{"usage":{"cpu":"20m","memory":"16Mi"}}]}`))
	case "/api/v1/namespaces/demo/pods/api-7c9f-abcde/log":
		f.mu.Lock()
		f.LogQuery = r.URL.Query()
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "line1\nline2\n")
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
	case "/apis/traefik.io/v1alpha1/namespaces/demo/ingressroutes":
		if requireMeta() {
			io.WriteString(w, list(metaItem("demo", "web"), metaItem("demo", "admin")))
		}
	case "/api/v1/namespaces/demo/secrets/db":
		io.WriteString(w, secretDB)
	case "/api/v1/namespaces/demo/configmaps/app-config":
		io.WriteString(w, configApp)
	default:
		writeStatus(w, http.StatusNotFound, "NotFound", p+" not found")
	}
}

func writeStatus(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "code": code, "reason": reason, "message": msg})
}
