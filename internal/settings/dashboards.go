package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Dashboard is a saved page of panels: charts, numbers, tables and logs of
// the metric store and the data sources, over a range of time, with
// variables people pick values of.
type Dashboard struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Range is the time it shows when opened, such as 6h; Refresh how often
	// it reads its panels again, in seconds (0: never).
	Range   string `json:"range,omitempty"`
	Refresh int    `json:"refresh,omitempty"`
	// Variables are values people pick, used in the queries as $name.
	Variables []Variable `json:"variables,omitempty"`
	Panels    []Panel    `json:"panels"`
	// Owner made it; Version counts its saves, so that one person's save
	// does not undo another's made meanwhile.
	Owner     string    `json:"owner"`
	Version   int       `json:"version"`
	Updated   time.Time `json:"updated"`
	UpdatedBy string    `json:"updatedBy"`
}

// Variable is a value picked among a label's values.
type Variable struct {
	Name  string `json:"name"`
	Title string `json:"title,omitempty"`
	// Source is a data source's ID (a Prometheus), empty for the store;
	// Label is the label whose values are offered, among the series Match
	// picks, if given.
	Source string `json:"source,omitempty"`
	Label  string `json:"label"`
	Match  string `json:"match,omitempty"`
	// Multi lets several values be picked; All offers all of them at once.
	Multi bool `json:"multi,omitempty"`
	All   bool `json:"all,omitempty"`
}

// Panel is one piece of a dashboard.
type Panel struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	// Type is graph, stat, table, logs or text.
	Type string `json:"type"`
	// W is its width in twelfths of the page, H its height in rows.
	W int `json:"w"`
	H int `json:"h"`
	// Queries are as Explore keeps them in its address: the query, its
	// legend, whether it is hidden, its source and an Elasticsearch query.
	Queries []json.RawMessage `json:"queries,omitempty"`
	Unit    string            `json:"unit,omitempty"`
	Mode    string            `json:"mode,omitempty"` // lines, area or stacked
	// Reduce makes a series one number for stat panels: last, mean, max,
	// min or sum; Warn and Crit color it.
	Reduce string   `json:"reduce,omitempty"`
	Warn   *float64 `json:"warn,omitempty"`
	Crit   *float64 `json:"crit,omitempty"`
	// Text is what a text panel says.
	Text string `json:"text,omitempty"`
}

const (
	// MaxDashboards bounds how many there are; MaxDashboardBytes how much
	// they take in all, as they are kept with the other settings, in a
	// Secret of at most a megabyte.
	MaxDashboards     = 100
	MaxDashboardBytes = 600 << 10
	maxPanels         = 60
	maxPanelQueries   = 10
	maxQueryBytes     = 20 << 10
)

var (
	variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,40}$`)
	labelName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,99}$`)
	rangeName    = regexp.MustCompile(`^[0-9]{1,3}[mhd]$`)
	panelTypes   = map[string]bool{"graph": true, "stat": true, "table": true, "logs": true, "text": true}
	reducers     = map[string]bool{"": true, "last": true, "mean": true, "max": true, "min": true, "sum": true}
	modes        = map[string]bool{"": true, "lines": true, "area": true, "stacked": true}
)

func plain(s string, most int) bool {
	return len(s) <= most && strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) < 0
}

// Normalize trims a dashboard, fills in its defaults and validates it.
func (d *Dashboard) Normalize() error {
	d.Title, d.Description, d.Range = strings.TrimSpace(d.Title), strings.TrimSpace(d.Description), strings.TrimSpace(d.Range)
	if d.Range == "" {
		d.Range = "6h"
	}
	if d.Panels == nil {
		d.Panels = []Panel{}
	}
	for i := range d.Panels {
		p := &d.Panels[i]
		p.Title = strings.TrimSpace(p.Title)
		if p.W == 0 {
			p.W = 6
		}
		if p.H == 0 {
			p.H = 4
		}
		if p.ID == "" {
			p.ID = NewCheckID()
		}
	}
	return d.Validate()
}

// Validate tells what is wrong with a dashboard, if anything.
func (d Dashboard) Validate() error {
	if d.Title == "" || !plain(d.Title, 120) || strings.Contains(d.Title, "\n") {
		return errors.New("give the dashboard a title of up to 120 characters")
	}
	if !plain(d.Description, 2000) {
		return errors.New("the description may be up to 2000 characters")
	}
	if !rangeName.MatchString(d.Range) {
		return fmt.Errorf("the range must look like 30m, 6h or 7d, not %q", d.Range)
	}
	if d.Refresh < 0 || d.Refresh > 86400 {
		return errors.New("refresh every 0 (never) to 86400 seconds")
	}
	if len(d.Variables) > 20 {
		return errors.New("at most 20 variables")
	}
	seen := map[string]bool{}
	for _, v := range d.Variables {
		// $__interval and the like are filled in by the queries' range.
		if !variableName.MatchString(v.Name) || strings.HasPrefix(v.Name, "__") || seen[v.Name] {
			return fmt.Errorf("variable names must be letters, digits and _, each once, not starting with __: %q", v.Name)
		}
		seen[v.Name] = true
		if !labelName.MatchString(v.Label) {
			return fmt.Errorf("the variable %s needs a label name, not %q", v.Name, v.Label)
		}
		if !plain(v.Title, 100) || !plain(v.Match, 2000) || len(v.Source) > 64 {
			return fmt.Errorf("the variable %s is too long", v.Name)
		}
	}
	if len(d.Panels) > maxPanels {
		return fmt.Errorf("at most %d panels", maxPanels)
	}
	ids := map[string]bool{}
	for i, p := range d.Panels {
		what := fmt.Sprintf("panel %d", i+1)
		if p.Title != "" {
			what = "the panel " + p.Title
		}
		switch {
		case ids[p.ID] || len(p.ID) > 64:
			return fmt.Errorf("%s has an ID another has", what)
		case !panelTypes[p.Type]:
			return fmt.Errorf("%s must be a graph, stat, table, logs or text panel", what)
		case !plain(p.Title, 120):
			return fmt.Errorf("%s has a title longer than 120 characters", what)
		case p.W < 1 || p.W > 12 || p.H < 1 || p.H > 24:
			return fmt.Errorf("%s must be 1 to 12 columns wide and 1 to 24 rows high", what)
		case len(p.Queries) > maxPanelQueries:
			return fmt.Errorf("%s has more than %d queries", what, maxPanelQueries)
		case !reducers[p.Reduce] || !modes[p.Mode] || len(p.Unit) > 20:
			return fmt.Errorf("%s has an unknown statistic, drawing or unit", what)
		case !plain(p.Text, 10000):
			return fmt.Errorf("%s has a text longer than 10000 characters", what)
		}
		ids[p.ID] = true
		for _, q := range p.Queries {
			var entry []any
			if len(q) > maxQueryBytes || json.Unmarshal(q, &entry) != nil || len(entry) == 0 {
				return fmt.Errorf("%s has a query that is not one", what)
			}
		}
	}
	return nil
}
