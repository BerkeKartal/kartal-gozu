// Package remote reads another registry as a client does: the OCI
// Distribution API, signing in with the tokens it asks for, and the
// listings of Harbor and Nexus, which tell more than the API does (push
// times, projects). Replication copies from it.
package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options say how to reach a registry.
type Options struct {
	// URL is where its /v2/ is below: https://harbor.example.org, or a
	// Nexus repository's https://nexus.example.org/repository/docker-hosted.
	URL      string
	Username string
	Password string
	// CA is a PEM bundle of the authorities its certificate may come from,
	// besides the system's; Insecure skips checking it (testing only).
	CA       string
	Insecure bool
	// HTTP replaces the client the options make, for tests.
	HTTP *http.Client
}

// Client reads one registry.
type Client struct {
	base       *url.URL
	user, pass string
	http       *http.Client

	mu     sync.Mutex
	tokens map[string]string // by scope
	basic  bool              // the registry asked for Basic
}

// ErrNotFound is what the registry does not have.
var ErrNotFound = errors.New("not found")

// final is an error that trying again does not change: a refusal.
type final struct{ error }

func (f final) Unwrap() error { return f.error }

// New makes a client.
func New(o Options) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(strings.TrimSpace(o.URL), "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%q is not an http(s) address", o.URL)
	}
	c := &Client{base: u, user: o.Username, pass: o.Password, tokens: map[string]string{}, http: o.HTTP}
	if c.http == nil {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.Insecure} //nolint:gosec // asked for
		if strings.TrimSpace(o.CA) != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM([]byte(o.CA)) {
				return nil, errors.New("the CA is not a PEM certificate")
			}
			tc.RootCAs = pool
		}
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment, TLSClientConfig: tc,
			DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 60 * time.Second,
			MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second,
		}
		c.http = &http.Client{Transport: tr}
	}
	return c, nil
}

// URL is where the client reads below.
func (c *Client) URL() string { return c.base.String() }

// endpoint is a path below the base.
func (c *Client) endpoint(p string) string { return c.base.String() + p }

// retryable tells whether a request may succeed if made again.
func retryable(status int) bool { return status == http.StatusTooManyRequests || status >= 500 }

// Do makes a request, signing in as the registry asks: a Bearer token for
// scope from its token service, or Basic. Failures of the network and of
// the registry (5xx, 429) are tried again, three times in all.
func (c *Client) Do(ctx context.Context, method, rawURL, scope string, header http.Header) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		resp, err := c.signed(ctx, method, rawURL, scope, header)
		if err != nil {
			var f final
			if errors.As(err, &f) {
				return nil, f.error
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		if retryable(resp.StatusCode) {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s %s: %s", method, rawURL, resp.Status)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func (c *Client) signed(ctx context.Context, method, rawURL, scope string, header http.Header) (*http.Response, error) {
	send := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("User-Agent", "kartal-registry")
		c.mu.Lock()
		tok, basic := c.tokens[scope], c.basic
		c.mu.Unlock()
		switch {
		case tok != "":
			req.Header.Set("Authorization", "Bearer "+tok)
		case basic && c.user != "":
			req.SetBasicAuth(c.user, c.pass)
		}
		return c.http.Do(req)
	}
	resp, err := send()
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	scheme, params := parseChallenge(challenge)
	switch scheme {
	case "bearer":
		if params["scope"] == "" {
			params["scope"] = scope
		}
		tok, err := c.token(ctx, params)
		if err != nil {
			return nil, err
		}
		if tok == "" {
			return nil, final{errors.New("the registry refused the user name and password")}
		}
		c.mu.Lock()
		c.tokens[scope] = tok
		c.mu.Unlock()
	case "basic":
		if c.user == "" {
			return nil, final{errors.New("the registry asks for a user name and password, and the source has none")}
		}
		c.mu.Lock()
		c.basic = true
		c.mu.Unlock()
	default:
		return nil, final{fmt.Errorf("the registry refused: %s", strings.TrimSpace(challenge))}
	}
	resp, err = send()
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, final{errors.New("the registry refused the user name and password")}
	}
	return resp, err
}

// parseChallenge reads a WWW-Authenticate header: its scheme, lower case,
// and its parameters.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, ", ")
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		var val string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				val, rest = after[1:], ""
			} else {
				val, rest = after[1:1+end], after[2+end:]
			}
		} else {
			val, rest, _ = strings.Cut(after, ",")
		}
		params[key] = val
	}
	return strings.ToLower(scheme), params
}

// token gets a Bearer token from the registry's token service.
func (c *Client) token(ctx context.Context, params map[string]string) (string, error) {
	realm, err := url.Parse(params["realm"])
	if err != nil || (realm.Scheme != "https" && realm.Scheme != "http") {
		return "", fmt.Errorf("the registry's token service %q cannot be reached", params["realm"])
	}
	q := realm.Query()
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	if params["scope"] != "" {
		q.Set("scope", params["scope"])
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "kartal-registry")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", final{errors.New("the registry refused the user name and password")}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the registry's token service answered %s", resp.Status)
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		out.Token = out.AccessToken
	}
	if out.Token == "" {
		return "", errors.New("the registry's token service gave no token")
	}
	return out.Token, nil
}

// check turns an answer that is not ok into an error; what is not found
// is ErrNotFound.
func check(resp *http.Response, what string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	msg := strings.TrimSpace(string(b))
	var e struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(b, &e) == nil && len(e.Errors) > 0 {
		msg = e.Errors[0].Message
	}
	return fmt.Errorf("%s: %s %s", what, resp.Status, msg)
}

func repoScope(repo string) string { return "repository:" + repo + ":pull" }

// Ping checks that the registry answers and lets the source in.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.Do(ctx, http.MethodGet, c.endpoint("/v2/"), "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return check(resp, "the registry")
}

// next is where a paged list goes on (its Link header), or "".
func next(resp *http.Response) string {
	link := resp.Header.Get("Link")
	start, end := strings.Index(link, "<"), strings.Index(link, ">")
	if start < 0 || end < start || !strings.Contains(link, `rel="next"`) {
		return ""
	}
	u, err := resp.Request.URL.Parse(link[start+1 : end])
	if err != nil {
		return ""
	}
	return u.String()
}

// list reads a paged list of names: the catalog's repositories, or a
// repository's tags.
func (c *Client) list(ctx context.Context, first, scope, field string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for u := first; u != "" && len(out) < 100000; {
		resp, err := c.Do(ctx, http.MethodGet, u, scope, nil)
		if err != nil {
			return nil, err
		}
		if err := check(resp, "listing"); err != nil {
			return nil, err
		}
		var page map[string]json.RawMessage
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var names []string
		if raw := page[field]; len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &names); err != nil {
				return nil, fmt.Errorf("listing: %w", err)
			}
		}
		for _, v := range names {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		u = next(resp)
	}
	return out, nil
}

// Catalog lists the repositories; registries that do not (Docker Hub)
// answer an error.
func (c *Client) Catalog(ctx context.Context) ([]string, error) {
	return c.list(ctx, c.endpoint("/v2/_catalog?n=1000"), "registry:catalog:*", "repositories")
}

// Tags lists a repository's tags.
func (c *Client) Tags(ctx context.Context, repo string) ([]string, error) {
	return c.list(ctx, c.endpoint("/v2/"+repo+"/tags/list?n=1000"), repoScope(repo), "tags")
}

// Accepted are the manifests asked for, the newest kinds first.
var Accepted = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// MaxManifest is the largest manifest read.
const MaxManifest = 4 << 20

// Manifest reads a manifest by tag or digest: its content, media type and
// digest, which is checked when asked for by it.
func (c *Client) Manifest(ctx context.Context, repo, ref string) ([]byte, string, string, error) {
	h := http.Header{"Accept": {strings.Join(Accepted, ", ")}}
	resp, err := c.Do(ctx, http.MethodGet, c.endpoint("/v2/"+repo+"/manifests/"+ref), repoScope(repo), h)
	if err != nil {
		return nil, "", "", err
	}
	if err := check(resp, repo+":"+ref); err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifest+1))
	if err != nil {
		return nil, "", "", err
	}
	if len(b) > MaxManifest {
		return nil, "", "", fmt.Errorf("%s:%s: the manifest is larger than %d bytes", repo, ref, MaxManifest)
	}
	sum := sha256.Sum256(b)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(ref, "sha256:") && ref != digest {
		return nil, "", "", fmt.Errorf("%s@%s: the manifest's content is %s", repo, ref, digest)
	}
	mt := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = mt[:i]
	}
	if mt == "" || mt == "application/json" || mt == "text/plain" {
		var probe struct {
			MediaType string `json:"mediaType"`
		}
		_ = json.Unmarshal(b, &probe)
		mt = probe.MediaType
	}
	return b, strings.TrimSpace(mt), digest, nil
}

// Blob reads a blob; the reader does not check its digest, which the
// store does as it takes it.
func (c *Client) Blob(ctx context.Context, repo, digest string) (io.ReadCloser, int64, error) {
	resp, err := c.Do(ctx, http.MethodGet, c.endpoint("/v2/"+repo+"/blobs/"+digest), repoScope(repo), nil)
	if err != nil {
		return nil, 0, err
	}
	if err := check(resp, repo+"@"+digest); err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// Referrer is an artifact about another, as the referrers API lists it.
type Referrer struct {
	MediaType    string `json:"mediaType"`
	Digest       string `json:"digest"`
	ArtifactType string `json:"artifactType,omitempty"`
}

// Referrers lists the artifacts about one: its signatures, SBOMs. A
// registry without the referrers API has none.
func (c *Client) Referrers(ctx context.Context, repo, digest string) ([]Referrer, error) {
	resp, err := c.Do(ctx, http.MethodGet, c.endpoint("/v2/"+repo+"/referrers/"+digest), repoScope(repo),
		http.Header{"Accept": {"application/vnd.oci.image.index.v1+json"}})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusBadRequest {
		resp.Body.Close()
		return nil, nil
	}
	if err := check(resp, "the referrers of "+repo+"@"+digest); err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var idx struct {
		Manifests []Referrer `json:"manifests"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxManifest)).Decode(&idx); err != nil {
		return nil, err
	}
	return idx.Manifests, nil
}

// getJSON reads an API's JSON with the source's user name and password,
// as Harbor's and Nexus's own APIs take them.
func (c *Client) getJSON(ctx context.Context, rawURL string, v any) (http.Header, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "kartal-registry")
		if c.user != "" {
			req.SetBasicAuth(c.user, c.pass)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		if retryable(resp.StatusCode) {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: %s", rawURL, resp.Status)
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, errors.New("the API refused the user name and password")
		}
		if err := check(resp, "the API"); err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(bytes.TrimSpace(b), v); err != nil {
			return nil, fmt.Errorf("the API's answer is not what was expected: %w", err)
		}
		return resp.Header, nil
	}
	return nil, lastErr
}
