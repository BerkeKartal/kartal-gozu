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
	"slices"
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
	// Mentions are the people a card names, so that Teams notifies them: a
	// post in a channel notifies nobody by itself. They are named when a
	// critical problem starts, or when any does with MentionAll; never for
	// what was resolved.
	Mentions   []Mention
	MentionAll bool
}

// Mention is a person of Teams: the sign-in name (such as
// ada@example.org) or the directory's object ID, and the name shown.
type Mention struct {
	ID   string
	Name string
}

// maxMentions keeps a card from paging a whole directory.
const maxMentions = 20

// ParseMentions reads people to mention, separated by commas: a sign-in
// name or an object ID, optionally as "Name <id>".
func ParseMentions(list string) ([]Mention, error) {
	var out []Mention
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		m := Mention{ID: item}
		if open := strings.LastIndex(item, "<"); open >= 0 && strings.HasSuffix(item, ">") {
			m.Name, m.ID = strings.TrimSpace(item[:open]), strings.TrimSpace(item[open+1:len(item)-1])
		}
		if m.ID == "" || len(m.ID) > 256 || strings.ContainsAny(m.ID, " 	<>\"") {
			return nil, fmt.Errorf("%q is not a person to mention: give a sign-in name or an object ID, optionally as \"Name <id>\"", item)
		}
		if m.Name == "" {
			m.Name, _, _ = strings.Cut(m.ID, "@")
		}
		// The name goes between <at> tags, in the card and in its entity.
		if len(m.Name) > 100 || strings.ContainsAny(m.Name, "<>") {
			return nil, fmt.Errorf("the name %q may be up to 100 characters, without < or >", m.Name)
		}
		// Each person once; Teams tells a card's mentions apart by their
		// text, so two people cannot go by one name.
		if slices.ContainsFunc(out, func(o Mention) bool { return strings.EqualFold(o.ID, m.ID) }) {
			continue
		}
		if slices.ContainsFunc(out, func(o Mention) bool { return o.Name == m.Name }) {
			return nil, fmt.Errorf("two people are named %q: give each a name of their own, as \"Name <id>\"", m.Name)
		}
		out = append(out, m)
	}
	if len(out) > maxMentions {
		return nil, fmt.Errorf("at most %d people can be mentioned", maxMentions)
	}
	return out, nil
}

// mentioned are the people a notification names.
func (t Teams) mentioned(n Notification) []Mention {
	for _, a := range n.Firing {
		if t.MentionAll || a.Severity == critical {
			return t.Mentions
		}
	}
	return nil
}

func (t Teams) Name() string { return "teams" }

func (t Teams) Send(ctx context.Context, n Notification) error {
	body := []map[string]any{
		{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": n.Title()},
		{"type": "TextBlock", "wrap": true, "text": "- " + strings.Join(n.Lines(maxLines), "\n- ")},
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4",
	}
	if people := t.mentioned(n); len(people) > 0 {
		// Teams makes a mention of each <at> text that an entity names.
		var tags []string
		var entities []map[string]any
		for _, p := range people {
			tag := "<at>" + p.Name + "</at>"
			tags = append(tags, tag)
			entities = append(entities, map[string]any{"type": "mention", "text": tag, "mentioned": map[string]string{"id": p.ID, "name": p.Name}})
		}
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "text": strings.Join(tags, " ")})
		card["msteams"] = map[string]any{"entities": entities}
	}
	card["body"] = body
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
