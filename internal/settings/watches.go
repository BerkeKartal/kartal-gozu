package settings

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/BerkeKartal/kartal-gozu/internal/promtext"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Watch is a metric that pods expose, which the server reads regularly
// through the cluster's agent, to keep its history and, given a limit, to
// raise an alert.
type Watch struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	// Target is whose pods are read: a workload ("Deployment/web": each of
	// its running pods) or one pod ("Pod/web-1").
	Target string `json:"target"`
	Port   string `json:"port"`
	Path   string `json:"path"`
	// Metric is a sample's name, such as http_requests_total. Labels, when
	// set, must all match a sample for it to count.
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels,omitempty"`
	// Rate shows how fast a counter grows, per second, instead of its value.
	Rate bool `json:"rate,omitempty"`
	// Aggregate joins the matching series of all the pods: sum, avg, max
	// or min.
	Aggregate string `json:"aggregate"`
	// Above and Below raise an alert while the value is past them.
	Above *float64 `json:"above,omitempty"`
	Below *float64 `json:"below,omitempty"`
}

const (
	// MaxWatches bounds the work of reading them: each is read every 30
	// seconds.
	MaxWatches     = 100
	maxWatchLabels = 10
)

var (
	watchKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Pod": true}
	aggregates = map[string]bool{"sum": true, "avg": true, "max": true, "min": true}
	dnsLabel   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// Normalize trims a watch and fills in the defaults, then validates it.
func (w *Watch) Normalize() error {
	w.Name, w.Cluster, w.Namespace = strings.TrimSpace(w.Name), strings.TrimSpace(w.Cluster), strings.TrimSpace(w.Namespace)
	w.Target, w.Port, w.Path, w.Metric = strings.TrimSpace(w.Target), strings.TrimSpace(w.Port), strings.TrimSpace(w.Path), strings.TrimSpace(w.Metric)
	if w.Path == "" {
		w.Path = "/metrics"
	}
	if w.Aggregate == "" {
		w.Aggregate = "sum"
	}
	if w.Name == "" {
		w.Name = w.Metric
	}
	labels := map[string]string{}
	for k, v := range w.Labels {
		if k = strings.TrimSpace(k); k != "" {
			labels[k] = v
		}
	}
	w.Labels = nil
	if len(labels) > 0 {
		w.Labels = labels
	}
	return w.Validate()
}

// Validate tells what is wrong with a watch, if anything.
func (w Watch) Validate() error {
	if w.Name == "" || len(w.Name) > 100 || strings.IndexFunc(w.Name, unicode.IsControl) >= 0 {
		return errors.New("the name must be 1 to 100 characters on one line")
	}
	if w.Cluster == "" || len(w.Cluster) > 100 || strings.ContainsAny(w.Cluster, "/%") || strings.IndexFunc(w.Cluster, unicode.IsControl) >= 0 {
		return fmt.Errorf("invalid cluster %q", w.Cluster)
	}
	if len(w.Namespace) > 63 || !dnsLabel.MatchString(w.Namespace) {
		return fmt.Errorf("invalid namespace %q", w.Namespace)
	}
	kind, name, _ := strings.Cut(w.Target, "/")
	if !watchKinds[kind] || name == "" || len(name) > 253 || strings.ContainsAny(name, "/%") || name == "." || name == ".." {
		return fmt.Errorf("the target must be a Deployment, StatefulSet, DaemonSet or Pod, such as Deployment/web, not %q", w.Target)
	}
	if err := protocol.CheckEndpoint(w.Port, w.Path); err != nil {
		return err
	}
	if !promtext.ValidName(w.Metric) {
		return fmt.Errorf("%q is not a metric name", w.Metric)
	}
	if len(w.Labels) > maxWatchLabels {
		return fmt.Errorf("at most %d labels", maxWatchLabels)
	}
	for k, v := range w.Labels {
		if !promtext.ValidLabel(k) {
			return fmt.Errorf("%q is not a label name", k)
		}
		if len(v) > 200 {
			return fmt.Errorf("the value of label %s is longer than 200 characters", k)
		}
	}
	if !aggregates[w.Aggregate] {
		return fmt.Errorf("the pods' values are joined by sum, avg, max or min, not %q", w.Aggregate)
	}
	for _, limit := range []*float64{w.Above, w.Below} {
		if limit != nil && (math.IsNaN(*limit) || math.IsInf(*limit, 0)) {
			return errors.New("a limit must be a number")
		}
	}
	return nil
}

// Reads is what a watch reads and how it joins it: when it changes, the
// history the watch had no longer fits.
func (w Watch) Reads() string {
	return fmt.Sprint(w.Cluster, "|", w.Namespace, "|", w.Target, "|", w.Port, "|", w.Path, "|", w.Metric, "|",
		labelString(w.Labels), "|", w.Rate, "|", w.Aggregate)
}

// labelString writes labels in a fixed order.
func labelString(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%q,", k, labels[k])
	}
	return b.String()
}

// clone copies a watch, so that its labels and limits are not shared.
func (w Watch) clone() Watch {
	w.Labels = maps.Clone(w.Labels)
	if w.Above != nil {
		v := *w.Above
		w.Above = &v
	}
	if w.Below != nil {
		v := *w.Below
		w.Below = &v
	}
	return w
}
