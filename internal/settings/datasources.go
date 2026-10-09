package settings

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// DataSource is a Prometheus or Elasticsearch server that Explore queries,
// next to the server's own metric store.
type DataSource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // prometheus or elasticsearch
	// URL is the base the API paths go under: http://prometheus:9090.
	URL string `json:"url"`
	// Via is a cluster whose agent makes the requests, for a source only the
	// cluster reaches; the agent must allow its URL (KARTAL_DATASOURCE_URLS).
	// Empty: the server makes them.
	Via string `json:"via,omitempty"`
	// Cluster is the cluster whose namespaces the source's data belongs to.
	// People who see only some of them get only those namespaces' data,
	// told apart by NamespaceLabel (a label, or an Elasticsearch field).
	// Without it, only people who see everything may query the source.
	Cluster        string `json:"cluster,omitempty"`
	NamespaceLabel string `json:"namespaceLabel,omitempty"`
	// Auth is none, basic (Username and Password), bearer or apikey (Token).
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	// Insecure skips verifying the server's certificate.
	Insecure bool `json:"insecure,omitempty"`
	// Interval is how often a Prometheus scrapes, in seconds (30 when 0):
	// $__rate_interval goes by it.
	Interval int `json:"interval,omitempty"`
	// Index, TimeField and MessageField are where an Elasticsearch keeps
	// its documents' time and text: filebeat-*, @timestamp and message.
	Index        string `json:"index,omitempty"`
	TimeField    string `json:"timeField,omitempty"`
	MessageField string `json:"messageField,omitempty"`
}

const (
	SourcePrometheus    = "prometheus"
	SourceElasticsearch = "elasticsearch"
	// MaxDataSources bounds the list.
	MaxDataSources = 50
)

var (
	fieldName = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_.@-]*$`)
	promLabel = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// An index pattern: no spaces or characters a path would take apart.
	indexPattern = regexp.MustCompile(`^[^\s/\\?#"<>|]+$`)
)

// EffectiveInterval is the scrape interval in seconds, 30 when unset.
func (d DataSource) EffectiveInterval() int {
	if d.Interval == 0 {
		return 30
	}
	return d.Interval
}

// Normalize trims a source, fills in the defaults of its type and
// validates it.
func (d *DataSource) Normalize() error {
	for _, s := range []*string{&d.Name, &d.Type, &d.URL, &d.Via, &d.Cluster, &d.NamespaceLabel, &d.Auth, &d.Username, &d.Index, &d.TimeField, &d.MessageField} {
		*s = strings.TrimSpace(*s)
	}
	d.URL = strings.TrimSuffix(d.URL, "/")
	if d.Auth == "" || d.Auth == "none" {
		d.Auth, d.Username, d.Password, d.Token = "none", "", "", ""
	}
	switch d.Type {
	case SourcePrometheus:
		if d.NamespaceLabel == "" {
			d.NamespaceLabel = "namespace"
		}
		d.Index, d.TimeField, d.MessageField = "", "", ""
	case SourceElasticsearch:
		if d.NamespaceLabel == "" {
			d.NamespaceLabel = "kubernetes.namespace"
		}
		if d.TimeField == "" {
			d.TimeField = "@timestamp"
		}
		if d.MessageField == "" {
			d.MessageField = "message"
		}
		d.Interval = 0
	}
	return d.Validate()
}

// Validate tells what is wrong with a source, if anything.
func (d DataSource) Validate() error {
	if d.Name == "" || len(d.Name) > 100 || strings.IndexFunc(d.Name, unicode.IsControl) >= 0 {
		return errors.New("give the source a name of up to 100 characters")
	}
	if d.Type != SourcePrometheus && d.Type != SourceElasticsearch {
		return fmt.Errorf("the type must be %s or %s", SourcePrometheus, SourceElasticsearch)
	}
	u, err := url.Parse(d.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("the address must look like http://prometheus.monitoring.svc:9090, not %q", d.URL)
	}
	for what, c := range map[string]string{"cluster to go through": d.Via, "cluster": d.Cluster} {
		if len(c) > 100 || strings.ContainsAny(c, "/%") || strings.IndexFunc(c, unicode.IsControl) >= 0 {
			return fmt.Errorf("invalid %s %q", what, c)
		}
	}
	if !fieldName.MatchString(d.NamespaceLabel) || len(d.NamespaceLabel) > 200 || (d.Type == SourcePrometheus && !promLabel.MatchString(d.NamespaceLabel)) {
		return fmt.Errorf("invalid namespace label or field %q", d.NamespaceLabel)
	}
	switch d.Auth {
	case "none":
	case "basic":
		if d.Username == "" {
			return errors.New("basic authentication needs a user name")
		}
	case "bearer", "apikey":
	default:
		return errors.New("authentication must be none, basic, bearer or apikey")
	}
	if strings.ContainsAny(d.Username+d.Password+d.Token, "\r\n") {
		return errors.New("the user name, password and token may not contain line breaks")
	}
	if d.Interval < 0 || d.Interval > 3600 {
		return errors.New("the scrape interval must be 1 to 3600 seconds")
	}
	if d.Type == SourceElasticsearch {
		if d.Index == "" || len(d.Index) > 255 || !indexPattern.MatchString(d.Index) {
			return fmt.Errorf("give the index pattern to search, such as filebeat-*, not %q", d.Index)
		}
		for _, f := range []string{d.TimeField, d.MessageField} {
			if !fieldName.MatchString(f) || len(f) > 200 {
				return fmt.Errorf("invalid field name %q", f)
			}
		}
	}
	return nil
}
