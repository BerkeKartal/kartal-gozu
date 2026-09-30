// Package kube is a deliberately small Kubernetes REST client built on the
// standard library. It only knows what the agent needs: authenticated GET,
// PATCH, paginated lists and raw text (logs).
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type Client struct {
	base      string
	hc        *http.Client
	tls       *tls.Config // for the WebSocket connections of Exec
	tokenFile string
	token     string
}

// InCluster builds a client from the pod's service account.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running inside a cluster: KUBERNETES_SERVICE_HOST/PORT unset")
	}
	caPEM, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("service account CA contains no certificates")
	}
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &Client{
		base:      "https://" + net.JoinHostPort(host, port),
		hc:        newHTTPClient(tc),
		tls:       tc,
		tokenFile: filepath.Join(serviceAccountDir, "token"),
	}, nil
}

// InClusterNamespace is the namespace the pod runs in.
func InClusterNamespace() (string, error) {
	b, err := os.ReadFile(filepath.Join(serviceAccountDir, "namespace"))
	if err != nil {
		return "", fmt.Errorf("read service account namespace: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// New builds a client for an explicit API URL, mainly for local development.
func New(apiURL, token string, insecureSkipVerify bool) *Client {
	tc := &tls.Config{InsecureSkipVerify: insecureSkipVerify, MinVersion: tls.VersionTLS12}
	return &Client{
		base:  strings.TrimRight(apiURL, "/"),
		hc:    newHTTPClient(tc),
		tls:   tc,
		token: token,
	}
}

func newHTTPClient(tc *tls.Config) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     tc,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// APIError carries the status returned by the Kubernetes API server.
type APIError struct {
	Status  int
	Reason  string
	Message string
}

func (e *APIError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("kubernetes api %d %s: %s", e.Status, e.Reason, e.Message)
	}
	return fmt.Sprintf("kubernetes api %d: %s", e.Status, e.Message)
}

// bearer re-reads the projected token on every call: kubelet rotates it.
func (c *Client) bearer() (string, error) {
	if c.tokenFile == "" {
		return c.token, nil
	}
	b, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", fmt.Errorf("read service account token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) do(ctx context.Context, method, path, accept, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	tok, err := c.bearer()
	if err != nil {
		return nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", accept)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, readAPIError(resp)
	}
	return resp, nil
}

func readAPIError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &APIError{Status: resp.StatusCode}
	var st struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &st) == nil && st.Message != "" {
		e.Reason, e.Message = st.Reason, st.Message
	} else {
		e.Message = strings.TrimSpace(string(b))
	}
	return e
}

// Get decodes the JSON response of path into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.getAs(ctx, path, "application/json", out)
}

func (c *Client) getAs(ctx context.Context, path, accept string, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, accept, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// GetRaw returns the raw JSON body of path, refusing bodies above limit.
func (c *Client) GetRaw(ctx context.Context, path string, limit int64) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, path, "application/json", "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("object is larger than %d bytes", limit)
	}
	return b, nil
}

// IsNotFound reports whether err is a 404 from the API server.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// GetText returns a plain-text response (such as pod logs) capped at limit bytes.
func (c *Client) GetText(ctx context.Context, path string, limit int64) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, path, "*/*", "", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return string(b), err
}

// Patch sends body (marshalled to JSON) with the given patch content type.
func (c *Client) Patch(ctx context.Context, path, patchType string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPatch, path, "application/json", patchType, bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Send makes a request with a raw body of the given content type and returns
// the response body, refusing one above limit bytes.
func (c *Client) Send(ctx context.Context, method, path, contentType string, body []byte, limit int64) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	resp, err := c.do(ctx, method, path, "application/json", contentType, rd)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response is larger than %d bytes", limit)
	}
	return b, nil
}

func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := c.Get(ctx, "/version", &v); err != nil {
		return "", err
	}
	return v.GitVersion, nil
}

// ListAll follows the API server's pagination until every item is read.
func ListAll[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	return listAll[T](ctx, c, path, query, "application/json", 0)
}

// metadataOnly asks the API server for names and metadata without object
// contents, so listing ConfigMaps or Secrets never transfers their data.
const metadataOnly = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1,application/json"

// ListMeta lists only the metadata of any resource, stopping after maxItems items
// (0 means no limit).
func ListMeta(ctx context.Context, c *Client, path string, maxItems int) ([]Meta, error) {
	return ListMetaWith(ctx, c, path, nil, maxItems)
}

// ListMetaWith is ListMeta with extra query parameters, such as a labelSelector.
func ListMetaWith(ctx context.Context, c *Client, path string, query url.Values, maxItems int) ([]Meta, error) {
	items, err := listAll[struct {
		Metadata Meta `json:"metadata"`
	}](ctx, c, path, query, metadataOnly, maxItems)
	if err != nil {
		return nil, err
	}
	out := make([]Meta, len(items))
	for i, it := range items {
		out[i] = it.Metadata
	}
	return out, nil
}

func listAll[T any](ctx context.Context, c *Client, path string, query url.Values, accept string, maxItems int) ([]T, error) {
	var all []T
	next := ""
	for {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("limit", "500")
		if next != "" {
			q.Set("continue", next)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := c.getAs(ctx, path+"?"+q.Encode(), accept, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if maxItems > 0 && len(all) >= maxItems {
			return all[:maxItems], nil
		}
		if page.Metadata.Continue == "" {
			return all, nil
		}
		next = page.Metadata.Continue
	}
}

// Seg escapes a single path segment such as a namespace or object name.
func Seg(s string) string { return url.PathEscape(s) }
