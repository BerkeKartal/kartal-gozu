package alert

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Errors are shown on the Alerts page, to viewers too: the secret part of a
// webhook URL must not be in them.
func TestNotifyErrorsHideTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	n := Notification{Cluster: "prod", Firing: []Alert{{Kind: "NodeNotReady", Object: "n1"}}}
	for _, target := range []string{srv.URL + "/workflows/1?sig=SECRET", "http://127.0.0.1:1/hook?sig=SECRET"} {
		err := Teams{URL: target}.Send(context.Background(), n)
		if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%s: %v", target, err)
		}
	}
}

func TestEmailGivesUpOnASilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // no greeting, ever
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = Email{Addr: ln.Addr().String(), From: "k@example.org", To: []string{"ops@example.org"}}.Send(ctx, Notification{Cluster: "prod"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}
}

// fakeSMTP answers one plain SMTP session and hands back the message.
func fakeSMTP(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { c.Write([]byte(s + "\r\n")) }
		say("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				say("250 ok")
			case cmd == "DATA":
				say("354 go on")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued")
				got <- data.String()
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("502 ?")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestEmail(t *testing.T) {
	addr, got := fakeSMTP(t)
	n := Notification{Cluster: "prod", URL: "https://panel.example.org/",
		Firing: []Alert{{Kind: "PodFailing", Namespace: "a", Object: "web-1", Detail: "CrashLoopBackOff"}}}
	err := Email{Addr: addr, From: "kartal@example.org", To: []string{"ops@example.org"}}.Send(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	msg := <-got
	for _, want := range []string{"From: kartal@example.org", "To: ops@example.org", "Subject: =?utf-8?q?Kartal_G=C3=B6z=C3=BC", "charset=utf-8",
		"Pod failing a/web-1: CrashLoopBackOff", "https://panel.example.org/"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the mail lacks %q:\n%s", want, msg)
		}
	}
}
