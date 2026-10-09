package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	// maxDataSourceBody bounds an answer: it travels to the server in a
	// result, base64 encoded, under the server's limit for results (8 MiB).
	maxDataSourceBody = 5 << 20
	// dataSourceTimeout ends a request before the server stops waiting.
	dataSourceTimeout = 15 * time.Second
)

var errDataSourcesOff = errors.New("this agent reaches no data source; list the ones it may in KARTAL_DATASOURCE_URLS")

// ParseDataSourceURLs reads the base URLs of the data sources an agent may
// reach, such as http://prometheus-server.monitoring.svc:9090.
func ParseDataSourceURLs(list []string) ([]*url.URL, error) {
	var out []*url.URL
	for _, s := range list {
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("%q is not a base URL such as http://prometheus.monitoring.svc:9090", s)
		}
		u.Path = strings.TrimSuffix(u.Path, "/")
		out = append(out, u)
	}
	return out, nil
}

// hostPort is a URL's host with its port, the scheme's when it has none.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

// dataSourceAllowed tells whether a URL is under one the agent allows: the
// same scheme, host and port, and a path at or below the allowed one.
func (e *Executor) dataSourceAllowed(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	// The path must be plain, as written and decoded: no dot segments to
	// climb out of a base, not even escaped ones.
	for _, p := range []string{u.EscapedPath(), u.Path} {
		if p != "" && path.Clean(p) != p && path.Clean(p)+"/" != p {
			return fmt.Errorf("invalid URL path %q", u.EscapedPath())
		}
	}
	for _, a := range e.DataSourceURLs {
		if a.Scheme == u.Scheme && hostPort(a) == hostPort(u) && (a.Path == "" || u.Path == a.Path || strings.HasPrefix(u.Path, a.Path+"/")) {
			return nil
		}
	}
	return fmt.Errorf("%s://%s%s is not among the data sources this agent may reach (KARTAL_DATASOURCE_URLS)", u.Scheme, u.Host, u.Path)
}

var (
	dsClients    [2]*http.Client
	dsClientsMu  sync.Mutex
	allowedHeads = map[string]bool{"Authorization": true, "Content-Type": true, "Accept": true}
)

// dataSourceClient follows no redirects: one could lead anywhere.
func dataSourceClient(insecure bool) *http.Client {
	dsClientsMu.Lock()
	defer dsClientsMu.Unlock()
	i := 0
	if insecure {
		i = 1
	}
	if dsClients[i] == nil {
		dsClients[i] = &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure},
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return dsClients[i]
}

// dataSourceRequest makes the request of a CommandHTTP.
func (e *Executor) dataSourceRequest(ctx context.Context, cmd protocol.Command) (string, error) {
	r := cmd.HTTP
	if r == nil {
		return "", errors.New("the command has no request")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return "", fmt.Errorf("method %q is not allowed; only GET and POST", r.Method)
	}
	if err := e.dataSourceAllowed(r.URL); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, dataSourceTimeout)
	defer cancel()
	var body io.Reader
	if len(r.Body) > 0 {
		body = strings.NewReader(string(r.Body))
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
	if err != nil {
		return "", err
	}
	for k, v := range r.Header {
		k = http.CanonicalHeaderKey(k)
		if !allowedHeads[k] || strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("header %q is not allowed", k)
		}
		req.Header.Set(k, v)
	}
	resp, err := dataSourceClient(r.Insecure).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDataSourceBody+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxDataSourceBody {
		return "", fmt.Errorf("the answer is larger than %d MiB; narrow the query down", maxDataSourceBody>>20)
	}
	return marshal(protocol.HTTPResponse{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: b})
}
