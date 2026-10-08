package settings

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Collect is what the server keeps in its metric store: every metric of
// the targets' pods, read every Interval seconds and kept until someone
// deletes a range (or, with RetentionDays, for that many days).
type Collect struct {
	Interval      int             `json:"interval,omitempty"`
	RetentionDays int             `json:"retentionDays,omitempty"`
	Targets       []CollectTarget `json:"targets,omitempty"`
}

// CollectTarget is a workload or pod whose metrics are collected.
type CollectTarget struct {
	ID        string `json:"id"`
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	// Target is "Deployment/web" (each of its running pods) or "Pod/web-1".
	Target string `json:"target"`
	Port   string `json:"port"`
	Path   string `json:"path"`
	// Include and Exclude, when set, are regular expressions that metric
	// names must and must not match, to keep the store small.
	Include string `json:"include,omitempty"`
	Exclude string `json:"exclude,omitempty"`
}

const (
	// DefaultCollectInterval is how often targets are read, in seconds.
	DefaultCollectInterval = 30
	minCollectInterval     = 10
	maxCollectInterval     = 3600
	// MaxCollectTargets bounds the work of a round.
	MaxCollectTargets = 200
)

// EffectiveInterval is the interval in seconds, the default when unset.
func (c Collect) EffectiveInterval() int {
	if c.Interval == 0 {
		return DefaultCollectInterval
	}
	return c.Interval
}

// Validate tells what is wrong with the collection settings, targets apart.
func (c Collect) Validate() error {
	if c.Interval != 0 && (c.Interval < minCollectInterval || c.Interval > maxCollectInterval) {
		return fmt.Errorf("the interval must be %d to %d seconds", minCollectInterval, maxCollectInterval)
	}
	if c.RetentionDays < 0 || c.RetentionDays > 36500 {
		return errors.New("keep data for 0 (forever) to 36500 days")
	}
	return nil
}

// Normalize trims a target, fills in the default path and validates it.
func (t *CollectTarget) Normalize() error {
	t.Cluster, t.Namespace, t.Target = strings.TrimSpace(t.Cluster), strings.TrimSpace(t.Namespace), strings.TrimSpace(t.Target)
	t.Port, t.Path = strings.TrimSpace(t.Port), strings.TrimSpace(t.Path)
	t.Include, t.Exclude = strings.TrimSpace(t.Include), strings.TrimSpace(t.Exclude)
	if t.Path == "" {
		t.Path = "/metrics"
	}
	return t.Validate()
}

// Validate tells what is wrong with a target, if anything.
func (t CollectTarget) Validate() error {
	if t.Cluster == "" || len(t.Cluster) > 100 || strings.ContainsAny(t.Cluster, "/%") || strings.IndexFunc(t.Cluster, unicode.IsControl) >= 0 {
		return fmt.Errorf("invalid cluster %q", t.Cluster)
	}
	if len(t.Namespace) > 63 || !dnsLabel.MatchString(t.Namespace) {
		return fmt.Errorf("invalid namespace %q", t.Namespace)
	}
	kind, name, _ := strings.Cut(t.Target, "/")
	if !watchKinds[kind] || name == "" || len(name) > 253 || strings.ContainsAny(name, "/%") || name == "." || name == ".." {
		return fmt.Errorf("the target must be a Deployment, StatefulSet, DaemonSet or Pod, such as Deployment/web, not %q", t.Target)
	}
	if err := protocol.CheckEndpoint(t.Port, t.Path); err != nil {
		return err
	}
	for what, re := range map[string]string{"include": t.Include, "exclude": t.Exclude} {
		if len(re) > 500 {
			return fmt.Errorf("the %s pattern is longer than 500 characters", what)
		}
		// Alone, so that a pattern such as a)|(b cannot change what the
		// collector wraps it in to match whole names.
		if _, err := regexp.Compile(re); err != nil {
			return fmt.Errorf("the %s pattern is not a regular expression: %v", what, err)
		}
	}
	return nil
}

// Same tells whether two targets read the same pods at the same address.
func (t CollectTarget) Same(o CollectTarget) bool {
	return t.Cluster == o.Cluster && t.Namespace == o.Namespace && t.Target == o.Target && t.Port == o.Port && t.Path == o.Path
}
