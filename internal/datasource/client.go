// Package datasource queries Prometheus and Elasticsearch servers for
// Explore: directly from the server, or through a cluster's agent when only
// the cluster reaches them. Answers come back in the shape of the metric
// store's, so the page draws them alike.
package datasource

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

const (
	// maxBody bounds an answer read directly; one through an agent is
	// bounded by the agent.
	maxBody = 16 << 20
	timeout = 30 * time.Second
)

// Client makes the requests.
type Client struct {
	// Ask sends a cluster's agent a command and waits for its result, for
	// the sources reached through an agent.
	Ask func(ctx context.Context, cluster string, cmd protocol.Command) (protocol.Result, error)

	direct, insecure *http.Client
}

// New returns a client whose direct requests honour HTTPS_PROXY and
// NO_PROXY, and follow no redirects.
func New(ask func(context.Context, string, protocol.Command) (protocol.Result, error)) *Client {
	mk := func(insecure bool) *http.Client {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure},
				IdleConnTimeout: 90 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Client{Ask: ask, direct: mk(false), insecure: mk(true)}
}

// request is a call to a source's API.
type request struct {
	method      string
	path        string // below the source's URL
	query       url.Values
	body        []byte
	contentType string
}

// Error is what a source answered with a failing status.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("the source answered %d: %s", e.Status, e.Message)
}

// do makes a request and returns the answer's body; a failing status
// becomes an Error with what the source said.
func (c *Client) do(ctx context.Context, src settings.DataSource, r request) ([]byte, error) {
	u := src.URL + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	header := map[string]string{"Accept": "application/json"}
	if r.contentType != "" {
		header["Content-Type"] = r.contentType
	}
	switch src.Auth {
	case "basic":
		header["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(src.Username+":"+src.Password))
	case "bearer":
		header["Authorization"] = "Bearer " + src.Token
	case "apikey":
		header["Authorization"] = "ApiKey " + src.Token
	}
	var status int
	var body []byte
	if src.Via != "" {
		if c.Ask == nil {
			return nil, errors.New("no agent can be asked")
		}
		res, err := c.Ask(ctx, src.Via, protocol.Command{Type: protocol.CommandHTTP, HTTP: &protocol.HTTPRequest{
			Method: r.method, URL: u, Header: header, Body: r.body, Insecure: src.Insecure,
		}})
		if err != nil {
			if strings.Contains(err.Error(), "unsupported command") {
				return nil, fmt.Errorf("the agent of %s is too old to reach data sources; update it", src.Via)
			}
			return nil, err
		}
		var answer protocol.HTTPResponse
		if err := json.Unmarshal([]byte(res.Output), &answer); err != nil {
			return nil, err
		}
		status, body = answer.Status, answer.Body
	} else {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, r.method, u, bytes.NewReader(r.body))
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		client := c.direct
		if src.Insecure {
			client = c.insecure
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody+1)); err != nil {
			return nil, err
		}
		if len(body) > maxBody {
			return nil, fmt.Errorf("the answer is larger than %d MiB; narrow the query down", maxBody>>20)
		}
		status = resp.StatusCode
	}
	if status >= 300 {
		return nil, &Error{Status: status, Message: errorText(status, body)}
	}
	return body, nil
}

// errorText finds the reason in a failing answer: Prometheus says it in
// "error", Elasticsearch in "error.reason" or its root causes.
func errorText(status int, body []byte) string {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Error) > 0 {
		var s string
		if json.Unmarshal(e.Error, &s) == nil {
			return s
		}
		var es struct {
			Reason    string `json:"reason"`
			RootCause []struct {
				Reason string `json:"reason"`
			} `json:"root_cause"`
			CausedBy struct {
				Reason string `json:"reason"`
			} `json:"caused_by"`
		}
		if json.Unmarshal(e.Error, &es) == nil {
			reason := es.Reason
			if len(es.RootCause) > 0 && es.RootCause[0].Reason != "" && es.RootCause[0].Reason != reason {
				reason += ": " + es.RootCause[0].Reason
			}
			if es.CausedBy.Reason != "" {
				reason += ": " + es.CausedBy.Reason
			}
			if reason != "" {
				return reason
			}
		}
	}
	if status/100 == 3 {
		return "a redirect, which is not followed; give the address it leads to"
	}
	text := strings.TrimSpace(string(body))
	if r := []rune(text); len(r) > 300 {
		text = string(r[:300]) + "…"
	}
	if text == "" {
		text = http.StatusText(status)
	}
	return text
}
