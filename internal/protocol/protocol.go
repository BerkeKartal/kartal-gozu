// Package protocol holds the wire types shared by the server and the agent.
package protocol

import "time"

// Snapshot is the periodic summary an agent sends about its cluster. It
// carries names and status only; object contents are fetched on demand.
type Snapshot struct {
	Cluster          string        `json:"cluster"`
	AgentVersion     string        `json:"agentVersion"`
	KubeVersion      string        `json:"kubeVersion"`
	CollectedAt      time.Time     `json:"collectedAt"`
	MetricsAvailable bool          `json:"metricsAvailable"`
	Nodes            []Node        `json:"nodes"`
	Namespaces       []Namespace   `json:"namespaces"`
	Workloads        []Workload    `json:"workloads"`
	Pods             []Pod         `json:"pods"`
	Services         []Service     `json:"services"`
	Ingresses        []Ingress     `json:"ingresses"`
	ConfigMaps       []ObjectRef   `json:"configMaps"`
	Secrets          []ObjectRef   `json:"secrets,omitempty"`
	VolumeClaims     []VolumeClaim `json:"volumeClaims"`
	Jobs             []Job         `json:"jobs"`
	CronJobs         []CronJob     `json:"cronJobs"`
	Events           []Event       `json:"events"`
	// Errors lists parts that could not be collected (e.g. missing RBAC);
	// the rest of the snapshot is still valid.
	Errors []string `json:"errors,omitempty"`
}

// Resources is an amount of CPU (millicores), memory (bytes) and pod slots.
type Resources struct {
	CPUMilli    int64 `json:"cpuMilli"`
	MemoryBytes int64 `json:"memoryBytes"`
	Pods        int64 `json:"pods,omitempty"`
}

type Node struct {
	Name             string     `json:"name"`
	Ready            bool       `json:"ready"`
	Unschedulable    bool       `json:"unschedulable"`
	Roles            []string   `json:"roles"`
	InternalIP       string     `json:"internalIP"`
	KubeletVersion   string     `json:"kubeletVersion"`
	OSImage          string     `json:"osImage"`
	ContainerRuntime string     `json:"containerRuntime"`
	Capacity         Resources  `json:"capacity"`
	Allocatable      Resources  `json:"allocatable"`
	Usage            *Resources `json:"usage,omitempty"`
	Pressure         []string   `json:"pressure,omitempty"`
	Taints           []string   `json:"taints,omitempty"`
	PodCount         int        `json:"podCount"`
	CreatedAt        time.Time  `json:"createdAt"`
}

type Namespace struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Workload struct {
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Desired   int32     `json:"desired"`
	Ready     int32     `json:"ready"`
	Updated   int32     `json:"updated"`
	Images    []string  `json:"images"`
	CreatedAt time.Time `json:"createdAt"`
}

// Degraded reports whether fewer replicas are ready than desired.
func (w Workload) Degraded() bool { return w.Ready < w.Desired }

type Pod struct {
	Namespace  string     `json:"namespace"`
	Name       string     `json:"name"`
	Phase      string     `json:"phase"`
	Reason     string     `json:"reason,omitempty"`
	Node       string     `json:"node"`
	IP         string     `json:"ip"`
	Ready      int        `json:"ready"`
	Total      int        `json:"total"`
	Restarts   int32      `json:"restarts"`
	Owner      string     `json:"owner,omitempty"`
	Containers []string   `json:"containers"`
	Usage      *Resources `json:"usage,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
}

// Healthy reports whether the pod is running with all containers ready, or
// finished successfully.
func (p Pod) Healthy() bool {
	if p.Phase == "Succeeded" {
		return true
	}
	return p.Phase == "Running" && p.Ready == p.Total && p.Reason == ""
}

type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort,omitempty"`
	NodePort   int32  `json:"nodePort,omitempty"`
	Protocol   string `json:"protocol"`
}

type Service struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	ClusterIP string            `json:"clusterIP"`
	Ports     []ServicePort     `json:"ports"`
	Selector  map[string]string `json:"selector,omitempty"`
	CreatedAt time.Time         `json:"createdAt"`
}

type IngressRule struct {
	Host    string `json:"host"`
	Path    string `json:"path"`
	Backend string `json:"backend"`
}

type Ingress struct {
	Namespace string        `json:"namespace"`
	Name      string        `json:"name"`
	Class     string        `json:"class,omitempty"`
	TLS       bool          `json:"tls"`
	Rules     []IngressRule `json:"rules"`
	CreatedAt time.Time     `json:"createdAt"`
}

// ObjectRef identifies an object without any of its contents.
type ObjectRef struct {
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

type VolumeClaim struct {
	Namespace    string    `json:"namespace"`
	Name         string    `json:"name"`
	Phase        string    `json:"phase"`
	StorageClass string    `json:"storageClass,omitempty"`
	Capacity     string    `json:"capacity,omitempty"`
	VolumeName   string    `json:"volumeName,omitempty"`
	AccessModes  []string  `json:"accessModes"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Job struct {
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	Owner       string     `json:"owner,omitempty"`
	Completions int32      `json:"completions"`
	Succeeded   int32      `json:"succeeded"`
	Failed      int32      `json:"failed"`
	Active      int32      `json:"active"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

type CronJob struct {
	Namespace    string     `json:"namespace"`
	Name         string     `json:"name"`
	Schedule     string     `json:"schedule"`
	Suspended    bool       `json:"suspended"`
	Active       int        `json:"active"`
	LastSchedule *time.Time `json:"lastSchedule,omitempty"`
	LastSuccess  *time.Time `json:"lastSuccess,omitempty"`
}

type Event struct {
	Namespace string    `json:"namespace"`
	Object    string    `json:"object"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	Count     int32     `json:"count"`
	LastSeen  time.Time `json:"lastSeen"`
}

// APIResource is one listable resource type of a cluster, CRDs included.
type APIResource struct {
	Group      string `json:"group"`
	Version    string `json:"version"`
	Resource   string `json:"resource"`
	Kind       string `json:"kind"`
	Namespaced bool   `json:"namespaced"`
}

const (
	CommandLogs      = "logs"
	CommandRestart   = "restart"
	CommandScale     = "scale"
	CommandResources = "resources"
	CommandList      = "list"
	CommandGet       = "get"
)

// Command is an action the server asks an agent to perform.
type Command struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
	// Group, Version and Resource address any resource type for list/get;
	// Group is empty for the core API.
	Group     string `json:"group,omitempty"`
	Version   string `json:"version,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	Container string `json:"container,omitempty"`
	TailLines int    `json:"tailLines,omitempty"`
	Replicas  *int32 `json:"replicas,omitempty"`
}

type Result struct {
	CommandID string `json:"commandId"`
	OK        bool   `json:"ok"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}
