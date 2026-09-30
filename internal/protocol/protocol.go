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
	// Capabilities lists what this agent was allowed to do beyond reading:
	// CapabilityWrite, CapabilityExec, CapabilityEdit.
	Capabilities []string `json:"capabilities,omitempty"`
}

const (
	// CapabilityWrite covers restart, scale, pod delete, cordon, CronJob
	// suspend/trigger and rollback.
	CapabilityWrite = "write"
	// CapabilityExec covers running commands in containers.
	CapabilityExec = "exec"
	// CapabilityEdit covers changing objects from their YAML.
	CapabilityEdit = "edit"
)

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
	// Requests and Limits are summed over the node's running pods: how much
	// of Allocatable has been promised, as the scheduler sees it.
	Requests  *Resources `json:"requests,omitempty"`
	Limits    *Resources `json:"limits,omitempty"`
	Pressure  []string   `json:"pressure,omitempty"`
	Taints    []string   `json:"taints,omitempty"`
	PodCount  int        `json:"podCount"`
	CreatedAt time.Time  `json:"createdAt"`
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
	// Usage is the sum over the workload's pods; it needs metrics-server.
	Usage *Resources `json:"usage,omitempty"`
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
	// Requests and Limits are the pod's effective values, as the scheduler
	// counts them: the containers' sum, or the largest init container's.
	Requests  *Resources `json:"requests,omitempty"`
	Limits    *Resources `json:"limits,omitempty"`
	StartedAt time.Time  `json:"startedAt"`
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
	// Condition is how the Job ended: "Complete" or "Failed"; empty while it runs.
	Condition string `json:"condition,omitempty"`
}

// HasFailed reports whether the Job gave up (its Failed condition). A Job
// that failed some pods but is still retrying has not.
func (j Job) HasFailed() bool { return j.Condition == "Failed" }

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

// ObjectEvent is one event about a single object, of any type.
type ObjectEvent struct {
	Type      string    `json:"type"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	Count     int32     `json:"count"`
	Source    string    `json:"source,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Revision is one entry of a Deployment's rollout history.
type Revision struct {
	Revision    int64     `json:"revision"`
	ReplicaSet  string    `json:"replicaSet"`
	Images      []string  `json:"images"`
	ChangeCause string    `json:"changeCause,omitempty"`
	Replicas    int32     `json:"replicas"`
	Ready       int32     `json:"ready"`
	CreatedAt   time.Time `json:"createdAt"`
}

// History is a Deployment's rollout history, newest revision first.
type History struct {
	Current   int64      `json:"current"`
	Revisions []Revision `json:"revisions"`
}

// ExecResult is the outcome of a command run in a container.
type ExecResult struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exitCode"`
	Truncated bool   `json:"truncated,omitempty"`
}

// HelmRelease is the latest revision of one Helm release. Its values are
// never read.
type HelmRelease struct {
	Namespace    string    `json:"namespace"`
	Name         string    `json:"name"`
	Revision     int       `json:"revision"`
	Status       string    `json:"status"`
	Chart        string    `json:"chart,omitempty"`
	ChartVersion string    `json:"chartVersion,omitempty"`
	AppVersion   string    `json:"appVersion,omitempty"`
	Description  string    `json:"description,omitempty"`
	Updated      time.Time `json:"updated"`
}

const (
	CommandLogs      = "logs"
	CommandRestart   = "restart"
	CommandScale     = "scale"
	CommandResources = "resources"
	CommandList      = "list"
	CommandGet       = "get"
	// CommandEvents lists the events of one object (Kind, Namespace, Name).
	CommandEvents = "events"
	// CommandDelete deletes a pod, which its controller then replaces.
	CommandDelete = "delete"
	// CommandCordon sets a node's unschedulable flag to Flag.
	CommandCordon = "cordon"
	// CommandSuspend sets a CronJob's suspend flag to Flag.
	CommandSuspend = "suspend"
	// CommandTrigger starts a Job from a CronJob right away.
	CommandTrigger = "trigger"
	// CommandHistory returns a Deployment's rollout History.
	CommandHistory = "history"
	// CommandRollback rolls a Deployment back to Revision.
	CommandRollback = "rollback"
	// CommandExec runs Exec in a container and returns an ExecResult.
	CommandExec = "exec"
	// CommandApply replaces an object with the YAML in Body (DryRun only
	// shows the result) and returns the object as the API server saved it.
	CommandApply = "apply"
	// CommandHelm lists Helm releases.
	CommandHelm = "helm"
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
	// Previous asks for the logs of the container's previous instance.
	Previous bool   `json:"previous,omitempty"`
	Replicas *int32 `json:"replicas,omitempty"`
	// Flag is the new value for cordon and suspend.
	Flag     *bool    `json:"flag,omitempty"`
	Revision int64    `json:"revision,omitempty"`
	Exec     []string `json:"exec,omitempty"`
	Body     string   `json:"body,omitempty"`
	DryRun   bool     `json:"dryRun,omitempty"`
}

type Result struct {
	CommandID string `json:"commandId"`
	OK        bool   `json:"ok"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}
