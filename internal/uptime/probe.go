// Package uptime requests the addresses admins list (URL checks) from the
// server itself, at regular intervals: whether they answer, how fast, and
// when their certificates expire. Problems become alerts of no cluster.
package uptime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// Result is one request of a check.
type Result struct {
	Time   time.Time `json:"time"`
	OK     bool      `json:"ok"`
	Status int       `json:"status,omitempty"`
	Millis int64     `json:"ms"`
	Error  string    `json:"error,omitempty"`
	// Cert describes the certificate the address answered with over https.
	Cert *Cert `json:"cert,omitempty"`
}

// Cert is a server's certificate as a check saw it.
type Cert struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"notAfter"`
}

const (
	maxRedirects = 5
	// maxBody bounds what is searched for a check's text.
	maxBody = 1 << 20
)

// Probe requests a check's address once. The certificate is recorded before
// it is verified, so an expired or untrusted one is still described.
func Probe(ctx context.Context, c settings.Check) Result {
	start := time.Now()
	res := Result{Time: start.UTC()}
	var (
		mu   sync.Mutex
		peer *x509.Certificate
	)
	conf := &tls.Config{
		// Verified in VerifyConnection, after the certificate is recorded.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server sent no certificate")
			}
			mu.Lock()
			if peer == nil { // the address's own, not that of a redirect
				peer = cs.PeerCertificates[0]
			}
			mu.Unlock()
			if c.Insecure {
				return nil
			}
			opts := x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
			for _, ic := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(ic)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
	timeout := time.Duration(c.Timeout) * time.Second
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
			TLSClientConfig:   conf,
			ForceAttemptHTTP2: true,
			// Every request opens its own connection: a check measures
			// what a new visitor gets.
			DisableKeepAlives: true,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("more than %d redirects", maxRedirects)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "kartal-gozu-check/1")
	resp, err := client.Do(req)
	res.Millis = time.Since(start).Milliseconds()
	mu.Lock()
	if peer != nil {
		res.Cert = &Cert{Subject: certName(peer.Subject.CommonName, peer.DNSNames), NotAfter: peer.NotAfter.UTC(), Issuer: peer.Issuer.CommonName}
	}
	mu.Unlock()
	if err != nil {
		res.Error = describe(err, timeout)
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	switch {
	case c.Status != 0 && resp.StatusCode != c.Status:
		res.Error = fmt.Sprintf("answered %s, expected %d", resp.Status, c.Status)
	case c.Status == 0 && resp.StatusCode >= 400:
		res.Error = "answered " + resp.Status
	case c.Contains != "":
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			res.Error = "the answer broke off: " + describe(err, timeout)
		} else if !strings.Contains(string(body), c.Contains) {
			res.Error = fmt.Sprintf("the answer does not contain %q", c.Contains)
		}
	}
	res.OK = res.Error == ""
	return res
}

func certName(cn string, dns []string) string {
	if cn == "" && len(dns) > 0 {
		return dns[0]
	}
	return cn
}

// describe turns a request's error into a line for people: without the
// method and address, which the check already shows.
func describe(err error, timeout time.Duration) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("no answer within %s", timeout)
	}
	var (
		unknown x509.UnknownAuthorityError
		invalid x509.CertificateInvalidError
		host    x509.HostnameError
		dns     *net.DNSError
		op      *net.OpError
	)
	switch {
	case errors.As(err, &unknown):
		return "the certificate is not signed by a trusted authority"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "the certificate has expired"
	case errors.As(err, &invalid):
		return "the certificate is not valid: " + invalid.Error()
	case errors.As(err, &host):
		return "the certificate is not for this host: " + host.Error()
	case errors.As(err, &dns):
		return "the name " + dns.Name + " could not be resolved"
	case errors.Is(err, http.ErrSchemeMismatch):
		return "the address answers over http, not https"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused: nothing listens there"
	case errors.Is(err, syscall.ECONNRESET):
		return "the connection was reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "the host cannot be reached"
	case errors.As(err, &op) && op.Err != nil:
		return op.Err.Error()
	}
	return err.Error()
}
