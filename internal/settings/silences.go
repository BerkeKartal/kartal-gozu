package settings

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Silence keeps alerts from being notified for a while: a maintenance
// window over a namespace, or a problem someone is already on. The alerts
// it covers still show; when it ends, those still there are notified.
type Silence struct {
	ID string `json:"id"`
	// Cluster is the cluster it covers; empty, every cluster and the
	// server's own checks.
	Cluster string `json:"cluster,omitempty"`
	// Namespace, Object and Kind narrow it, empty meaning any; a namespace
	// or an object ending in * covers the names it starts. A namespace
	// leaves out the alerts of no namespace, such as a node's.
	Namespace string `json:"namespace,omitempty"`
	Object    string `json:"object,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Comment   string `json:"comment,omitempty"`
	// It covers alerts from Starts until Ends.
	Starts time.Time `json:"starts"`
	Ends   time.Time `json:"ends"`
	By     string    `json:"by"`
}

const (
	// MaxSilences bounds the silences not over yet.
	MaxSilences = 200
	// MaxSilenceLength is how long one may last, and maxSilenceAhead how
	// far ahead one may start: a maintenance window, not a way to turn
	// alerts off for good.
	MaxSilenceLength = 31 * 24 * time.Hour
	maxSilenceAhead  = 90 * 24 * time.Hour
)

// Validate tells what is wrong with a silence set at now, if anything.
func (s Silence) Validate(now time.Time) error {
	for _, f := range []struct {
		name, value string
		most        int
	}{{"cluster", s.Cluster, 100}, {"namespace", s.Namespace, 100}, {"object", s.Object, 300}, {"kind", s.Kind, 50}} {
		if len(f.value) > f.most || strings.IndexFunc(f.value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return fmt.Errorf("the %s may be up to %d characters, without spaces", f.name, f.most)
		}
		if strings.Contains(strings.TrimSuffix(f.value, "*"), "*") || (f.name != "namespace" && f.name != "object" && strings.Contains(f.value, "*")) {
			return fmt.Errorf("only a namespace or an object may end in *, not the %s %q", f.name, f.value)
		}
	}
	if len(s.Comment) > 500 || strings.IndexFunc(s.Comment, unicode.IsControl) >= 0 {
		return errors.New("the comment may be up to 500 characters on one line")
	}
	switch {
	case !s.Ends.After(s.Starts):
		return errors.New("a silence must end after it starts")
	case s.Ends.Sub(s.Starts) > MaxSilenceLength:
		return fmt.Errorf("a silence may last at most %d days", int(MaxSilenceLength.Hours()/24))
	case !s.Ends.After(now):
		return errors.New("this silence would be over already")
	case s.Starts.After(now.Add(maxSilenceAhead)):
		return fmt.Errorf("a silence must start within %d days", int(maxSilenceAhead.Hours()/24))
	}
	return nil
}

// Covers tells whether the silence is on at now for an alert of a kind
// about an object in a namespace (empty for none) of a cluster (empty for
// the server's own checks).
func (s Silence) Covers(cluster, kind, namespace, object string, now time.Time) bool {
	switch {
	case now.Before(s.Starts) || !now.Before(s.Ends):
		return false
	case s.Cluster != "" && s.Cluster != cluster, s.Kind != "" && s.Kind != kind:
		return false
	case s.Namespace != "" && (namespace == "" || !startsOrIs(s.Namespace, namespace)):
		return false
	}
	return s.Object == "" || startsOrIs(s.Object, object)
}

// startsOrIs matches a name to a pattern: the name itself, or with a
// trailing *, the names it starts.
func startsOrIs(pattern, name string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return pattern == name
}
