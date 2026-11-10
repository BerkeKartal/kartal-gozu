package settings

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// LogRule counts the log lines of an Elasticsearch data source that match
// a query, over the last while, and is an alert when there are more than
// it allows: what goes wrong while the pods keep running, such as database
// errors.
type LogRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Source is the ID of an Elasticsearch data source; Index, an index
	// pattern other than the source's.
	Source string `json:"source"`
	Index  string `json:"index,omitempty"`
	// Query is in Lucene syntax, as in Explore.
	Query string `json:"query"`
	// Window is how far back lines are counted, in seconds; more than
	// Above of them make the alert.
	Window int   `json:"window"`
	Above  int64 `json:"above"`
	// Severity is warning or critical.
	Severity string `json:"severity"`
}

const (
	// MaxLogRules keeps the server from loading the Elasticsearch: every
	// rule is counted every minute.
	MaxLogRules      = 50
	defaultLogWindow = 300
)

// Normalize trims a rule and fills in the defaults, then validates it.
func (r *LogRule) Normalize() error {
	r.Name, r.Source, r.Index, r.Query = strings.TrimSpace(r.Name), strings.TrimSpace(r.Source), strings.TrimSpace(r.Index), strings.TrimSpace(r.Query)
	r.Severity = strings.TrimSpace(r.Severity)
	if r.Window == 0 {
		r.Window = defaultLogWindow
	}
	if r.Severity == "" {
		r.Severity = "warning"
	}
	return r.Validate()
}

// Validate tells what is wrong with a rule, if anything.
func (r LogRule) Validate() error {
	control := func(s string) bool { return strings.IndexFunc(s, unicode.IsControl) >= 0 }
	switch {
	case r.Name == "" || len(r.Name) > 100 || control(r.Name):
		return errors.New("the name must be 1 to 100 characters on one line")
	case r.Source == "" || len(r.Source) > 64:
		return errors.New("choose the Elasticsearch data source to count in")
	case r.Index != "" && (len(r.Index) > 255 || !indexPattern.MatchString(r.Index)):
		return fmt.Errorf("%q is not an index pattern", r.Index)
	case r.Query == "" || r.Query == "*" || len(r.Query) > 2000 || control(r.Query):
		return errors.New("give the query that picks the lines, such as log.level:ERROR, in up to 2000 characters on one line")
	case r.Window < 60 || r.Window > 86400:
		return errors.New("count over the last 60 to 86400 seconds")
	case r.Above < 0 || r.Above > 1_000_000_000:
		return errors.New("the limit must be 0 (any line) to 1000000000")
	case r.Severity != "warning" && r.Severity != "critical":
		return fmt.Errorf("the severity must be warning or critical, not %q", r.Severity)
	}
	return nil
}
