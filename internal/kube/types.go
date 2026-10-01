package kube

import (
	"encoding/json"
	"strconv"
	"time"
)

// Only the fields the agent reads are declared; the JSON decoder skips the rest.

// IntOrString decodes fields that may hold a number or a name, like a
// Service targetPort.
type IntOrString string

func (v *IntOrString) UnmarshalJSON(b []byte) error {
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		*v = IntOrString(strconv.FormatInt(n, 10))
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*v = IntOrString(s)
	return nil
}

type Node struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Unschedulable bool `json:"unschedulable"`
		Taints        []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Effect string `json:"effect"`
		} `json:"taints"`
	} `json:"spec"`
	Status struct {
		Capacity    map[string]string `json:"capacity"`
		Allocatable map[string]string `json:"allocatable"`
		Conditions  []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		Addresses []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"addresses"`
		NodeInfo struct {
			KubeletVersion          string `json:"kubeletVersion"`
			OSImage                 string `json:"osImage"`
			ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

type Service struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Type      string            `json:"type"`
		ClusterIP string            `json:"clusterIP"`
		Selector  map[string]string `json:"selector"`
		Ports     []struct {
			Name       string      `json:"name"`
			Port       int32       `json:"port"`
			TargetPort IntOrString `json:"targetPort"`
			NodePort   int32       `json:"nodePort"`
			Protocol   string      `json:"protocol"`
		} `json:"ports"`
	} `json:"spec"`
}

type Ingress struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		IngressClassName *string `json:"ingressClassName"`
		TLS              []struct {
			Hosts []string `json:"hosts"`
		} `json:"tls"`
		Rules []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Path    string `json:"path"`
					Backend struct {
						Service *struct {
							Name string `json:"name"`
							Port struct {
								Number int32  `json:"number"`
								Name   string `json:"name"`
							} `json:"port"`
						} `json:"service"`
					} `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

type PersistentVolumeClaim struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		StorageClassName *string  `json:"storageClassName"`
		VolumeName       string   `json:"volumeName"`
		AccessModes      []string `json:"accessModes"`
	} `json:"spec"`
	Status struct {
		Phase    string            `json:"phase"`
		Capacity map[string]string `json:"capacity"`
	} `json:"status"`
}

type Job struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Completions *int32 `json:"completions"`
	} `json:"spec"`
	Status struct {
		Succeeded      int32      `json:"succeeded"`
		Failed         int32      `json:"failed"`
		Active         int32      `json:"active"`
		StartTime      *time.Time `json:"startTime"`
		CompletionTime *time.Time `json:"completionTime"`
		Conditions     []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

type CronJob struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Schedule string `json:"schedule"`
		Suspend  *bool  `json:"suspend"`
	} `json:"spec"`
	Status struct {
		Active []struct {
			Name string `json:"name"`
		} `json:"active"`
		LastScheduleTime   *time.Time `json:"lastScheduleTime"`
		LastSuccessfulTime *time.Time `json:"lastSuccessfulTime"`
	} `json:"status"`
}

type NodeMetrics struct {
	Metadata Meta              `json:"metadata"`
	Usage    map[string]string `json:"usage"`
}

type PodMetrics struct {
	Metadata   Meta `json:"metadata"`
	Containers []struct {
		Usage map[string]string `json:"usage"`
	} `json:"containers"`
}

type APIResourceList struct {
	GroupVersion string `json:"groupVersion"`
	Resources    []struct {
		Name       string   `json:"name"`
		Namespaced bool     `json:"namespaced"`
		Kind       string   `json:"kind"`
		Verbs      []string `json:"verbs"`
	} `json:"resources"`
}

type APIGroupList struct {
	Groups []struct {
		Name             string `json:"name"`
		PreferredVersion struct {
			Version string `json:"version"`
		} `json:"preferredVersion"`
	} `json:"groups"`
}

type Meta struct {
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	CreationTimestamp time.Time `json:"creationTimestamp"`
	// Generation counts the changes to an object's spec.
	Generation      int64             `json:"generation"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []OwnerReference  `json:"ownerReferences"`
}

type OwnerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller"`
}

type Namespace struct {
	Metadata Meta `json:"metadata"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type Container struct {
	Name      string `json:"name"`
	Image     string `json:"image"`
	Resources struct {
		Requests map[string]string `json:"requests"`
		Limits   map[string]string `json:"limits"`
	} `json:"resources"`
	// RestartPolicy "Always" on an init container makes it a sidecar.
	RestartPolicy string `json:"restartPolicy"`
}

type PodTemplate struct {
	Spec struct {
		Containers []Container `json:"containers"`
	} `json:"spec"`
}

// Replicated covers Deployments and StatefulSets, which share these fields.
type Replicated struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Replicas *int32      `json:"replicas"`
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas   int32 `json:"readyReplicas"`
		UpdatedReplicas int32 `json:"updatedReplicas"`
	} `json:"status"`
}

type DaemonSet struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
		NumberReady            int32 `json:"numberReady"`
		UpdatedNumberScheduled int32 `json:"updatedNumberScheduled"`
	} `json:"status"`
}

type ContainerState struct {
	Waiting *struct {
		Reason string `json:"reason"`
	} `json:"waiting"`
	Terminated *struct {
		Reason   string `json:"reason"`
		ExitCode int32  `json:"exitCode"`
	} `json:"terminated"`
}

type ContainerStatus struct {
	Name         string         `json:"name"`
	Ready        bool           `json:"ready"`
	RestartCount int32          `json:"restartCount"`
	State        ContainerState `json:"state"`
}

type Pod struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		NodeName       string      `json:"nodeName"`
		Containers     []Container `json:"containers"`
		InitContainers []Container `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		Phase                 string            `json:"phase"`
		Reason                string            `json:"reason"`
		PodIP                 string            `json:"podIP"`
		StartTime             *time.Time        `json:"startTime"`
		ContainerStatuses     []ContainerStatus `json:"containerStatuses"`
		InitContainerStatuses []ContainerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type Event struct {
	Metadata       Meta `json:"metadata"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"involvedObject"`
	Reason         string    `json:"reason"`
	Message        string    `json:"message"`
	Type           string    `json:"type"`
	Count          int32     `json:"count"`
	FirstTimestamp time.Time `json:"firstTimestamp"`
	LastTimestamp  time.Time `json:"lastTimestamp"`
	EventTime      time.Time `json:"eventTime"`
	Source         struct {
		Component string `json:"component"`
		Host      string `json:"host"`
	} `json:"source"`
	ReportingController string `json:"reportingComponent"`
}

// ReplicaSet carries what a Deployment's rollout history needs.
type ReplicaSet struct {
	Metadata struct {
		Meta
		UID         string            `json:"uid"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32      `json:"replicas"`
		Template PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas int32 `json:"readyReplicas"`
	} `json:"status"`
}
