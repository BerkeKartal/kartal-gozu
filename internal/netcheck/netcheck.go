// Package netcheck tries TCP connections, to tell whether a place in the
// cluster reaches an address: a database, another service, a firewall's
// other side. It only connects and closes; nothing is sent.
package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Timeout is how long one attempt may take: long enough for a slow link,
// short enough that a dropped one does not hold the whole check up.
const Timeout = 3 * time.Second

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)

// ParseTarget checks one "host:port" (or "[IPv6]:port") and returns it in
// its usual spelling: names in lower case, as DNS does not tell cases apart.
func ParseTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("%q is not host:port", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q: the port must be 1 to 65535", s)
	}
	if net.ParseIP(host) == nil && !hostPattern.MatchString(host) {
		return "", fmt.Errorf("%q: invalid host name", s)
	}
	host = strings.ToLower(host)
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// ParseTargets checks a list of targets, dropping repeats.
func ParseTargets(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		t, err := ParseTarget(s)
		if err != nil {
			return nil, err
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no targets: give host:port, such as db.example.org:5432")
	}
	if len(out) > protocol.MaxNetCheckTargets {
		return nil, fmt.Errorf("at most %d targets at once", protocol.MaxNetCheckTargets)
	}
	return out, nil
}

// Dialer is what Run connects with; tests replace it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Run tries every target at once and returns the results in their order.
func Run(ctx context.Context, d Dialer, targets []string) []protocol.Reach {
	if d == nil {
		d = &net.Dialer{}
	}
	out := make([]protocol.Reach, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = try(ctx, d, target)
		}()
	}
	wg.Wait()
	return out
}

func try(ctx context.Context, d Dialer, target string) protocol.Reach {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", target)
	r := protocol.Reach{Target: target, Millis: time.Since(start).Milliseconds()}
	if err != nil {
		r.Result, r.Error = Classify(err), err.Error()
		var op *net.OpError
		if errors.As(err, &op) && op.Addr != nil {
			r.Address = op.Addr.String()
		}
		return r
	}
	r.Result = "ok"
	r.Address = conn.RemoteAddr().String()
	conn.Close()
	return r
}

// Classify names why a connection failed, in the words of protocol.Reach.
func Classify(err error) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns):
		if dns.IsTimeout {
			return "timeout"
		}
		return "dns"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "error"
}
