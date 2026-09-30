package kube

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ExecOutput is what a command run in a container wrote, and how it ended.
type ExecOutput struct {
	Stdout, Stderr []byte
	ExitCode       int
	Truncated      bool
}

// Exec runs a command in a container through the API server's WebSocket
// exec endpoint. path is the full exec URL path with its query, e.g.
// /api/v1/namespaces/ns/pods/p/exec?command=ls&stdout=true&stderr=true.
//
// It speaks the "v4.channel.k8s.io" subprotocol: every binary message starts
// with a channel byte, 1 for stdout, 2 for stderr and 3 for the final status.
// Output beyond limit bytes per stream is dropped and reported as Truncated.
func (c *Client) Exec(ctx context.Context, path string, limit int) (ExecOutput, error) {
	var out ExecOutput
	u, err := url.Parse(c.base + path)
	if err != nil {
		return out, err
	}
	conn, br, err := c.dialWebSocket(ctx, u)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	// Closing the connection is what unblocks a read when ctx ends.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	fr := &frameReader{br: br}
	var status []byte
	for {
		op, payload, err := fr.next()
		if err != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			if errors.Is(err, io.EOF) && status != nil {
				break
			}
			return out, fmt.Errorf("exec stream: %w", err)
		}
		switch op {
		case opBinary, opText:
			if len(payload) == 0 {
				continue
			}
			data := payload[1:]
			switch payload[0] {
			case 1:
				out.Stdout = appendLimited(out.Stdout, data, limit, &out.Truncated)
			case 2:
				out.Stderr = appendLimited(out.Stderr, data, limit, &out.Truncated)
			case 3:
				status = append(status, data...)
			}
			continue
		case opPing:
			writeFrame(conn, opPong, payload)
			continue
		case opClose:
		default:
			continue
		}
		break
	}
	code, err := exitCode(status)
	out.ExitCode = code
	return out, err
}

func appendLimited(buf, data []byte, limit int, truncated *bool) []byte {
	if room := limit - len(buf); room < len(data) {
		*truncated = true
		if room <= 0 {
			return buf
		}
		data = data[:room]
	}
	return append(buf, data...)
}

// exitCode reads the status message of the exec stream.
func exitCode(status []byte) (int, error) {
	if len(status) == 0 {
		return 0, nil
	}
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
		Details struct {
			Causes []struct {
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"causes"`
		} `json:"details"`
	}
	if err := json.Unmarshal(status, &st); err != nil {
		return 0, fmt.Errorf("exec status: %w", err)
	}
	if st.Status == "Success" {
		return 0, nil
	}
	if st.Reason == "NonZeroExitCode" {
		for _, c := range st.Details.Causes {
			if c.Reason == "ExitCode" {
				if n, err := strconv.Atoi(c.Message); err == nil {
					return n, nil
				}
			}
		}
	}
	return -1, errors.New(st.Message)
}

// dialWebSocket opens the connection and completes the upgrade handshake.
func (c *Client) dialWebSocket(ctx context.Context, u *url.URL) (net.Conn, *bufio.Reader, error) {
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	var conn net.Conn
	var err error
	if u.Scheme == "https" {
		tc := c.tls.Clone()
		tc.NextProtos = []string{"http/1.1"} // an upgrade needs HTTP/1.1, not h2
		if tc.ServerName == "" {
			tc.ServerName = u.Hostname()
		}
		conn, err = (&tls.Dialer{Config: tc}).DialContext(ctx, "tcp", host)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, err
	}
	// The dial honours ctx by itself; the handshake needs this to give up on
	// a server that accepted the connection but never answers.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	fail := func(err error) (net.Conn, *bufio.Reader, error) {
		conn.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	tok, err := c.bearer()
	if err != nil {
		return fail(err)
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	key := base64.StdEncoding.EncodeToString(nonce)
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\n", u.RequestURI(), u.Host)
	req.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n", key)
	if tok != "" {
		fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", tok)
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return fail(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fail(readAPIError(resp))
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return fail(errors.New("exec: bad WebSocket handshake"))
	}
	return conn, br, nil
}

const (
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

// maxMessage bounds one message, however many frames it comes in.
const maxMessage = 16 << 20

// frameReader returns whole messages. Control frames may arrive between the
// frames of a message; they come back at once, and the part of the message
// read so far waits for the rest.
type frameReader struct {
	br      *bufio.Reader
	partial []byte
	op      byte
}

func (r *frameReader) next() (byte, []byte, error) {
	for {
		var h [2]byte
		if _, err := io.ReadFull(r.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(r.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(r.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > maxMessage || uint64(len(r.partial))+n > maxMessage {
			return 0, nil, errors.New("exec: message too large")
		}
		var mask [4]byte
		masked := h[1]&0x80 != 0
		if masked {
			if _, err := io.ReadFull(r.br, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(r.br, p); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= mask[i%4]
			}
		}
		if op >= opClose {
			return op, p, nil
		}
		if op != 0 {
			r.op = op
		}
		r.partial = append(r.partial, p...)
		if fin {
			msg, msgOp := r.partial, r.op
			r.partial, r.op = nil, 0
			return msgOp, msg, nil
		}
	}
}

// writeFrame sends one masked frame, as a client must.
func writeFrame(w io.Writer, op byte, payload []byte) error {
	hdr := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		hdr = append(hdr, byte(n)|0x80)
	case n < 65536:
		hdr = append(hdr, 126|0x80, byte(n>>8), byte(n))
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		hdr = append(append(hdr, 127|0x80), b[:]...)
	}
	var mask [4]byte
	rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	body := make([]byte, len(payload))
	for i := range payload {
		body[i] = payload[i] ^ mask[i%4]
	}
	_, err := w.Write(append(hdr, body...))
	return err
}
