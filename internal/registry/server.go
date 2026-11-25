package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// ServerAuth asks kartal-server who signs in, and what they may do: the
// server knows the users, the robot accounts, the directory and the
// grants.
type ServerAuth struct {
	// URL is kartal-server's, such as http://kartal-server.kartal-gozu.svc:8080.
	URL    string
	Secret string
	HTTP   *http.Client
}

// AuthorizeRequest is what the registry asks kartal-server.
type AuthorizeRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Projects []string `json:"projects"`
}

// AuthorizeAnswer is what kartal-server answers: the roles by project, as
// "viewer", "operator" or "admin".
type AuthorizeAnswer struct {
	Subject string            `json:"subject"`
	Roles   map[string]string `json:"roles"`
	Admin   bool              `json:"admin"`
}

// Authorize implements Authorizer.
func (a *ServerAuth) Authorize(ctx context.Context, username, secret string, projects []string) (Identity, error) {
	body, _ := json.Marshal(AuthorizeRequest{Username: username, Password: secret, Projects: projects})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(a.URL, "/")+"/api/v1/registry/authorize", bytes.NewReader(body))
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Secret)
	resp, err := a.client().Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Identity{}, ErrBadCredentials
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Identity{}, fmt.Errorf("kartal-server answered %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var ans AuthorizeAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ans); err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: ans.Subject, Admin: ans.Admin, Roles: map[string]auth.Role{}}
	for p, r := range ans.Roles {
		if role, err := auth.ParseRole(r); err == nil {
			id.Roles[p] = role
		}
	}
	return id, nil
}

func (a *ServerAuth) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Forwarder hands the registry's events to kartal-server, which writes
// them to its audit log. It never holds the registry up: when the server
// cannot be reached, events wait in a queue a while and are dropped when
// it is full; the registry keeps its own log of them anyway.
type Forwarder struct {
	URL    string
	Secret string
	HTTP   *http.Client
	Log    *slog.Logger

	queue chan meta.Event
}

// NewForwarder makes a forwarder; Run sends what it is handed.
func NewForwarder(url, secret string, log *slog.Logger) *Forwarder {
	return &Forwarder{URL: url, Secret: secret, Log: log, HTTP: &http.Client{Timeout: 15 * time.Second}, queue: make(chan meta.Event, 1000)}
}

// Hand queues an event; it never waits.
func (f *Forwarder) Hand(e meta.Event) {
	select {
	case f.queue <- e:
	default:
		f.Log.Warn("registry: the event queue is full; an event is not forwarded", "action", e.Action, "repo", e.Repo)
	}
}

// Run sends the queued events in batches until ctx ends.
func (f *Forwarder) Run(ctx context.Context) {
	for {
		var batch []meta.Event
		select {
		case <-ctx.Done():
			return
		case e := <-f.queue:
			batch = append(batch, e)
		}
	more:
		for len(batch) < 100 {
			select {
			case e := <-f.queue:
				batch = append(batch, e)
			default:
				break more
			}
		}
		for try, wait := 0, time.Second; ; try, wait = try+1, wait*4 {
			err := f.send(ctx, batch)
			if err == nil {
				break
			}
			if try == 3 || ctx.Err() != nil {
				f.Log.Warn("registry: events could not be forwarded", "events", len(batch), "err", err)
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
}

func (f *Forwarder) send(ctx context.Context, batch []meta.Event) error {
	body, _ := json.Marshal(batch)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(f.URL, "/")+"/api/v1/registry/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.Secret)
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("kartal-server answered %s", resp.Status)
	}
	return nil
}
