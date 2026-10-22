package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestParseTarget(t *testing.T) {
	good := map[string]string{
		"db.example.org:5432": "db.example.org:5432",
		" 10.0.0.1:1521 ":     "10.0.0.1:1521",
		"[fd00::1]:443":       "[fd00::1]:443",
		"DBHOST01:1433":       "dbhost01:1433",
		"[FD00::A]:443":       "[fd00::a]:443",
		"db:007":              "db:7",
	}
	for in, want := range good {
		if got, err := ParseTarget(in); err != nil || got != want {
			t.Errorf("ParseTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"db", "db:0", "db:70000", "db:http", "-db:80", "a b:80", "db/x:80", ":80", "db:80:90"} {
		if got, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseTargets(t *testing.T) {
	got, err := ParseTargets([]string{"a:1", "", "A:01", " b:2"})
	if err != nil || strings.Join(got, ",") != "a:1,b:2" {
		t.Errorf("repeats and blanks should go: %v %v", got, err)
	}
	if _, err := ParseTargets([]string{" "}); err == nil {
		t.Error("no targets should be an error")
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("h%d:80", i)
	}
	if _, err := ParseTargets(many); err == nil {
		t.Error("too many targets should be refused")
	}
}

func TestRunReal(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	open := l.Addr().String()
	// A port that was just freed is very likely closed.
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l2.Addr().String()
	l2.Close()
	defer l.Close()
	res := Run(context.Background(), nil, []string{open, closed})
	if res[0].Target != open || res[0].Result != "ok" || res[0].Address != open {
		t.Errorf("open port: %+v", res[0])
	}
	if res[1].Target != closed || res[1].Result != "refused" || res[1].Error == "" {
		t.Errorf("closed port: %+v", res[1])
	}
}

type failing struct{ err error }

func (f failing) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 1521}, Err: f.err}
}

func TestClassify(t *testing.T) {
	cases := map[string]error{
		"timeout":     os.ErrDeadlineExceeded,
		"refused":     syscall.ECONNREFUSED,
		"unreachable": syscall.EHOSTUNREACH,
		"error":       errors.New("something else"),
	}
	for want, err := range cases {
		r := Run(context.Background(), failing{err}, []string{"db:1521"})[0]
		if r.Result != want || r.Address != "10.0.0.9:1521" {
			t.Errorf("%v: got %+v, want %s", err, r, want)
		}
	}
	if got := Classify(&net.DNSError{Err: "no such host", Name: "nosuch", IsNotFound: true}); got != "dns" {
		t.Errorf("a missing name is %q, want dns", got)
	}
	if got := Classify(&net.DNSError{Err: "timeout", Name: "x", IsTimeout: true}); got != "timeout" {
		t.Errorf("a DNS timeout is %q, want timeout", got)
	}
	if got := Classify(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("a context deadline is %q, want timeout", got)
	}
}
