package kube

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// A server that accepts the connection but never answers must not hold an
// exec forever: the context ends the handshake too.
func TestExecHandshakeGivesUp(t *testing.T) {
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
			defer c.Close() // held open, silent
		}
	}()
	c := New("http://"+ln.Addr().String(), "", false)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Exec(ctx, "/api/v1/namespaces/a/pods/p/exec?command=ls", 1024)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the context's deadline", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

// fakeExecServer upgrades one connection and then writes frames as given.
func fakeExecServer(t *testing.T, frames [][]byte) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	fromClient := make(chan []byte, 8)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Protocol: v4.channel.k8s.io\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"))
		for _, f := range frames {
			conn.Write(f)
		}
		// Whatever the client sends back (a pong), frame by frame.
		fr := &frameReader{br: br}
		for {
			op, p, err := fr.next()
			if err != nil {
				return
			}
			fromClient <- append([]byte{op}, p...)
		}
	}()
	return "http://" + ln.Addr().String(), fromClient
}

func frame(fin bool, op byte, payload string) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	return append([]byte{b0, byte(len(payload))}, payload...)
}

// A ping between the frames of a message is answered, and the message still
// arrives whole.
func TestExecFragmentsAroundAPing(t *testing.T) {
	url, fromClient := fakeExecServer(t, [][]byte{
		frame(false, opBinary, "\x01hel"),
		frame(true, opPing, "p"),
		frame(false, 0, "lo "),
		frame(true, 0, "world"),
		frame(true, opBinary, "\x02oops"),
		frame(true, opBinary, "\x03"+`{"status":"Success"}`),
		frame(true, opClose, ""),
	})
	c := New(url, "", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := c.Exec(ctx, "/api/v1/namespaces/a/pods/p/exec?command=echo", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Stdout) != "hello world" || string(out.Stderr) != "oops" || out.ExitCode != 0 || out.Truncated {
		t.Errorf("got %+v (stdout %q)", out, out.Stdout)
	}
	select {
	case got := <-fromClient:
		if got[0] != opPong || string(got[1:]) != "p" {
			t.Errorf("answer to the ping: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Error("the ping was not answered")
	}
}

func TestExecExitCodeAndLimit(t *testing.T) {
	status := `{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}`
	url, _ := fakeExecServer(t, [][]byte{
		frame(true, opBinary, "\x01"+"0123456789"),
		frame(true, opBinary, "\x03"+status),
		frame(true, opClose, ""),
	})
	out, err := New(url, "", false).Exec(context.Background(), "/api/v1/namespaces/a/pods/p/exec?command=x", 4)
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 3 || string(out.Stdout) != "0123" || !out.Truncated {
		t.Errorf("got %+v", out)
	}
}
