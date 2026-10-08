package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/promtext"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	// A page of metrics larger than this is refused; a pod is asked for at
	// most scrapeTimeout.
	maxScrapeBytes = 10 << 20
	scrapeTimeout  = 10 * time.Second
	// What one pod's page may return to the UI.
	maxScrapeSamples = 10000
	// One sample command reads at most this many pods and metrics, a few
	// pods at a time.
	maxSamplePods     = 50
	maxSampleMetrics  = 20
	sampleConcurrency = 8
	// sampleBudget ends a sample command before the server stops waiting
	// for it (KARTAL_COMMAND_TIMEOUT, 20 seconds by default): the pods that
	// answered in time count, the others say they did not.
	sampleBudget = 15 * time.Second
	// acceptText asks for the classic text format, which every client
	// library serves.
	acceptText = "text/plain;version=0.0.4;q=1,*/*;q=0.1"
)

var errScrapeDisabled = errors.New("reading the metrics of pods is disabled on this agent (KARTAL_POD_METRICS=false)")

// checkPods validates the namespace and pods of a sample or collect command.
func (e *Executor) checkPods(cmd protocol.Command) error {
	if err := checkNamespace(cmd.Namespace); err != nil {
		return err
	}
	if !e.namespaceAllowed(cmd.Namespace) {
		return fmt.Errorf("namespace %q is outside this agent's scope", cmd.Namespace)
	}
	if len(cmd.Pods) == 0 || len(cmd.Pods) > maxSamplePods {
		return fmt.Errorf("give 1 to %d pods", maxSamplePods)
	}
	for _, p := range cmd.Pods {
		if err := checkName(p); err != nil {
			return err
		}
	}
	return nil
}

// checkSample validates a sample command: its namespace, pods and metrics.
func (e *Executor) checkSample(cmd protocol.Command) error {
	if err := e.checkPods(cmd); err != nil {
		return err
	}
	if len(cmd.Metrics) == 0 || len(cmd.Metrics) > maxSampleMetrics {
		return fmt.Errorf("give 1 to %d metrics", maxSampleMetrics)
	}
	for _, m := range cmd.Metrics {
		if !promtext.ValidName(m) {
			return fmt.Errorf("invalid metric name %q", m)
		}
	}
	return nil
}

// proxyPath is where the API server passes a request on to a pod's port.
func proxyPath(ns, pod, port, path string) string {
	return "/api/v1/namespaces/" + kube.Seg(ns) + "/pods/" + kube.Seg(pod) + ":" + port + "/proxy" + path
}

// readMetrics reads a pod's page of metrics. Only what parses as metrics
// comes back: the agent must not become a way to read any page a pod
// serves, so neither a page in another format nor an error page the pod
// answered with is repeated.
func (e *Executor) readMetrics(ctx context.Context, ns, pod, port, path string, most int) ([]protocol.MetricFamily, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, scrapeTimeout)
	defer cancel()
	body, err := e.Kube.GetBody(ctx, proxyPath(ns, pod, port, path), acceptText, maxScrapeBytes)
	if err != nil {
		var apiErr *kube.APIError
		// The API server's own refusals come as a Status, with a reason;
		// anything else is the pod's answer.
		if errors.As(err, &apiErr) && apiErr.Reason == "" {
			return nil, false, fmt.Errorf("the pod answered %s:%s%s with HTTP status %d", pod, port, path, apiErr.Status)
		}
		return nil, false, err
	}
	fams, truncated, err := promtext.Parse(bytes.NewReader(body), most)
	if err != nil {
		return nil, false, fmt.Errorf("%s:%s%s: %w", pod, port, path, err)
	}
	return fams, truncated, nil
}

func (e *Executor) scrape(ctx context.Context, cmd protocol.Command) (string, error) {
	fams, truncated, err := e.readMetrics(ctx, cmd.Namespace, cmd.Name, cmd.Port, cmd.Path, maxScrapeSamples)
	if err != nil {
		return "", err
	}
	return marshal(protocol.Scrape{Families: fams, Truncated: truncated})
}

const (
	// maxCollectSamples is what one pod may add to the store each round.
	maxCollectSamples = 20000
	// maxCollectText keeps a collect result under the server's limit for
	// results (8 MiB).
	maxCollectText = 6 << 20
)

// collect reads every metric of several pods for the server's store, a few
// pods at a time, and returns them in the text format: only what parsed
// as metrics travels on, as with scrape.
func (e *Executor) collect(ctx context.Context, cmd protocol.Command) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sampleBudget)
	defer cancel()
	out := make([]protocol.PodMetrics, len(cmd.Pods))
	sem := make(chan struct{}, sampleConcurrency)
	var wg sync.WaitGroup
	for i, pod := range cmd.Pods {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i].Pod = pod
			fams, truncated, err := e.readMetrics(ctx, cmd.Namespace, pod, cmd.Port, cmd.Path, maxCollectSamples)
			if err != nil {
				out[i].Error = err.Error()
				return
			}
			var b strings.Builder
			promtext.Format(&b, fams)
			out[i].Text, out[i].Truncated = b.String(), truncated
		}()
	}
	wg.Wait()
	// What does not fit next to the others is left out, to be asked for
	// by itself. The size counts the text as JSON carries it: quotes and
	// line breaks take two bytes there.
	size := 0
	for i := range out {
		quoted, _ := json.Marshal(out[i].Text)
		if n := len(quoted); size+n > maxCollectText {
			out[i].Text = ""
			if len(out) > 1 {
				out[i].Alone = true
			} else {
				out[i].Error = fmt.Sprintf("the pod's metrics take more than %d MiB in the text format, more than one round takes", maxCollectText>>20)
			}
		} else {
			size += n
		}
	}
	return marshal(out)
}

// sample reads the named samples of several pods, a few at a time. A pod
// that cannot be read says why, next to the others' samples.
func (e *Executor) sample(ctx context.Context, cmd protocol.Command) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sampleBudget)
	defer cancel()
	want := map[string]bool{}
	for _, m := range cmd.Metrics {
		want[m] = true
	}
	out := make([]protocol.PodSamples, len(cmd.Pods))
	sem := make(chan struct{}, sampleConcurrency)
	var wg sync.WaitGroup
	for i, pod := range cmd.Pods {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i].Pod = pod
			fams, _, err := e.readMetrics(ctx, cmd.Namespace, pod, cmd.Port, cmd.Path, math.MaxInt)
			if err != nil {
				out[i].Error = err.Error()
				return
			}
			for _, f := range fams {
				for _, s := range f.Samples {
					if want[s.Name] {
						out[i].Samples = append(out[i].Samples, s)
					}
				}
			}
		}()
	}
	wg.Wait()
	return marshal(out)
}
