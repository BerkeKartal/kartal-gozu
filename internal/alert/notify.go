package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// maxLines keeps a notification readable when a whole cluster breaks.
const maxLines = 25

// Webhook posts the notification as JSON to any URL.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (w Webhook) Name() string { return "webhook" }

func (w Webhook) Send(ctx context.Context, n Notification) error {
	body := map[string]any{
		"title": n.Title(), "cluster": n.Cluster, "url": n.URL,
		"firing": nonNil(n.Firing), "resolved": nonNil(n.Resolved),
	}
	return postJSON(ctx, w.Client, w.URL, body)
}

func nonNil(a []Alert) []Alert {
	if a == nil {
		return []Alert{}
	}
	return a
}

// Teams posts an Adaptive Card, which Teams "Workflows" webhooks (and the
// older incoming webhooks) accept.
type Teams struct {
	URL    string
	Client *http.Client
}

func (t Teams) Name() string { return "teams" }

func (t Teams) Send(ctx context.Context, n Notification) error {
	body := []map[string]any{
		{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": n.Title()},
		{"type": "TextBlock", "wrap": true, "text": "- " + strings.Join(n.Lines(maxLines), "\n- ")},
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
	}
	if n.URL != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Kartal Gözü", "url": n.URL}}
	}
	msg := map[string]any{
		"type":        "message",
		"attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	}
	return postJSON(ctx, t.Client, t.URL, msg)
}

// postJSON sends v to target. Errors name only the host: a Teams workflow
// URL carries its signature, and errors are shown on the Alerts page.
func postJSON(ctx context.Context, client *http.Client, target string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return errors.New("the notification URL is not valid")
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("posting to %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s answered %s: %s", req.URL.Host, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Email sends a plain-text mail through an SMTP relay. Port 465 speaks TLS
// from the start; elsewhere STARTTLS is used when the server offers it. A
// username turns on authentication, which Go allows only over TLS or to
// localhost.
type Email struct {
	Addr     string // host:port
	From     string
	To       []string
	Username string
	Password string
}

func (e Email) Name() string { return "email" }

func (e Email) Send(ctx context.Context, n Notification) error {
	host, _, err := net.SplitHostPort(e.Addr)
	if err != nil {
		return fmt.Errorf("SMTP address %q: %w", e.Addr, err)
	}
	var body strings.Builder
	for _, l := range n.Lines(maxLines * 4) {
		body.WriteString(l + "\r\n")
	}
	if n.URL != "" {
		body.WriteString("\r\n" + n.URL + "\r\n")
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n", e.From, strings.Join(e.To, ", "),
		mime.QEncoding.Encode("utf-8", n.Title()), time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	msg.WriteString(body.String())

	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, host)
	}
	err = e.send(ctx, host, auth, msg.Bytes())
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// send is smtp.SendMail bounded by ctx: a relay that stops answering must
// not keep a connection and a goroutine forever.
func (e Email) send(ctx context.Context, host string, auth smtp.Auth, msg []byte) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", e.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, port, _ := net.SplitHostPort(e.Addr); port == "465" {
		conn = tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("the SMTP server does not offer authentication")
		}
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(e.From); err != nil {
		return err
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
