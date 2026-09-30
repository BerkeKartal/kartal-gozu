// Package agent runs inside a managed cluster. It never keeps a long-lived
// connection open: it pushes snapshots and long-polls for commands with
// ordinary HTTPS requests, so proxies and load balancers that cut idle or
// upgraded connections (WebSocket) do not break it.
package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

type Agent struct {
	ServerURL string
	Token     string
	HTTP      *http.Client
	Collector *Collector
	Executor  *Executor
	Interval  time.Duration
	// PollWait is how long the server may hold a command poll open. Keep it
	// below the shortest request timeout of anything between agent and server.
	PollWait    time.Duration
	Concurrency int
	Log         *slog.Logger

	startedAt atomic.Int64
	// lastRound is when the report loop last finished a round, whether the
	// report got through or not.
	lastRound atomic.Int64
}

// Run blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	a.startedAt.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.reportLoop(ctx) }()
	go func() { defer wg.Done(); a.commandLoop(ctx) }()
	wg.Wait()
}

// Healthy is false when the report loop has not finished a round for a long
// time, i.e. the agent is stuck. An unreachable server does not count: every
// request has a timeout, so rounds keep finishing, and restarting the agent
// would not bring the server back.
func (a *Agent) Healthy(now time.Time) bool {
	last := a.lastRound.Load()
	if last == 0 {
		last = a.startedAt.Load()
	}
	if last == 0 {
		return true // not started yet
	}
	return now.Sub(time.Unix(0, last)) < max(5*a.Interval, 5*time.Minute)
}

func (a *Agent) endpoint(path string) string {
	return strings.TrimRight(a.ServerURL, "/") + path
}

func (a *Agent) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.endpoint(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("User-Agent", "kartal-agent/"+a.Collector.Version)
	return req, nil
}

func (a *Agent) reportLoop(ctx context.Context) {
	for {
		start := time.Now()
		if err := a.reportOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.Log.Warn("report failed", "err", err)
		} else {
			a.Log.Debug("report sent", "took", time.Since(start))
		}
		a.lastRound.Store(time.Now().UnixNano())
		if !sleep(ctx, a.Interval) {
			return
		}
	}
}

func (a *Agent) reportOnce(ctx context.Context) error {
	snap := a.Collector.Collect(ctx)
	snap.Capabilities = a.Executor.Capabilities()
	for _, e := range snap.Errors {
		a.Log.Warn("partial collection", "err", e)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err := json.NewEncoder(zw).Encode(snap); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := a.newRequest(ctx, http.MethodPost, "/agent/v1/report", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode/100 != 2 {
		return statusError(resp)
	}
	return nil
}

func (a *Agent) commandLoop(ctx context.Context) {
	sem := make(chan struct{}, max(a.Concurrency, 1))
	failures := 0
	for ctx.Err() == nil {
		start := time.Now()
		cmds, err := a.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			backoff := min(time.Second<<min(failures, 5), 30*time.Second)
			a.Log.Warn("command poll failed", "err", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return
			}
			continue
		}
		failures = 0
		if len(cmds) == 0 {
			// A server or proxy that answers at once instead of holding the
			// poll open must not turn this loop into a busy loop.
			if rest := time.Second - time.Since(start); rest > 0 && !sleep(ctx, rest) {
				return
			}
			continue
		}
		for _, cmd := range cmds {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			go func(cmd protocol.Command) {
				defer func() { <-sem }()
				// Changes are worth a line each; reads (logs, lists, a "follow"
				// every few seconds) would drown them.
				level := slog.LevelDebug
				if changes[cmd.Type] && !cmd.DryRun {
					level = slog.LevelInfo
				}
				a.Log.Log(ctx, level, "running command", "id", cmd.ID, "type", cmd.Type, "namespace", cmd.Namespace, "kind", cmd.Kind, "name", cmd.Name)
				res := a.Executor.Run(ctx, cmd)
				if err := a.sendResult(ctx, res); err != nil {
					a.Log.Warn("sending result failed", "id", cmd.ID, "err", err)
				}
			}(cmd)
		}
	}
}

// changes are the commands that alter the cluster or run something in it.
var changes = map[string]bool{
	protocol.CommandRestart: true, protocol.CommandScale: true, protocol.CommandDelete: true,
	protocol.CommandCordon: true, protocol.CommandSuspend: true, protocol.CommandTrigger: true,
	protocol.CommandRollback: true, protocol.CommandExec: true, protocol.CommandApply: true,
}

func (a *Agent) poll(ctx context.Context) ([]protocol.Command, error) {
	wait := strconv.Itoa(int(a.PollWait / time.Second))
	req, err := a.newRequest(ctx, http.MethodGet, "/agent/v1/commands?wait="+wait, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	switch {
	case resp.StatusCode == http.StatusNoContent:
		return nil, nil
	case resp.StatusCode/100 != 2:
		return nil, statusError(resp)
	}
	var cmds []protocol.Command
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		return nil, fmt.Errorf("decode commands: %w", err)
	}
	return cmds, nil
}

func (a *Agent) sendResult(ctx context.Context, res protocol.Result) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	req, err := a.newRequest(ctx, http.MethodPost, "/agent/v1/results", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode/100 != 2 {
		return statusError(resp)
	}
	return nil
}

func statusError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
}

// drain lets the connection be reused for the next request.
func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
