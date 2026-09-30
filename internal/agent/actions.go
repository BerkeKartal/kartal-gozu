package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/kube"
	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

const (
	maxObjectEvents = 200
	execTimeout     = 15 * time.Second
	maxExecBytes    = 256 << 10
	maxHelmDetails  = 200
	revisionKey     = "deployment.kubernetes.io/revision"
)

var kindPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// objectEvents lists every event (not only warnings) about one object.
// Cluster-scoped objects such as nodes record theirs in any namespace.
func (e *Executor) objectEvents(ctx context.Context, cmd protocol.Command) (string, error) {
	if !kindPattern.MatchString(cmd.Kind) || cmd.Name == "" {
		return "", errors.New("a kind and a name are required")
	}
	path := "/api/v1/events"
	if cmd.Namespace != "" {
		if err := checkNamespace(cmd.Namespace); err != nil {
			return "", err
		}
		if !e.namespaceAllowed(cmd.Namespace) {
			return "", fmt.Errorf("namespace %q is outside this agent's scope", cmd.Namespace)
		}
		path = "/api/v1/namespaces/" + kube.Seg(cmd.Namespace) + "/events"
	} else if len(e.Namespaces) > 0 {
		return "", errors.New("this agent is limited to specific namespaces; cluster-wide events are outside its scope")
	}
	sel := "involvedObject.kind=" + cmd.Kind + ",involvedObject.name=" + fieldValue(cmd.Name)
	items, err := kube.ListAll[kube.Event](ctx, e.Kube, path, url.Values{"fieldSelector": {sel}})
	if err != nil {
		return "", err
	}
	out := make([]protocol.ObjectEvent, 0, len(items))
	for _, ev := range items {
		source := ev.Source.Component
		if source == "" {
			source = ev.ReportingController
		}
		if ev.Source.Host != "" {
			source += " (" + ev.Source.Host + ")"
		}
		count := ev.Count
		if count == 0 {
			count = 1
		}
		first := ev.FirstTimestamp
		if first.IsZero() {
			first = latest(ev.EventTime, ev.Metadata.CreationTimestamp)
		}
		out = append(out, protocol.ObjectEvent{
			Type: ev.Type, Reason: ev.Reason, Message: ev.Message, Count: count, Source: source,
			FirstSeen: first, LastSeen: latest(ev.LastTimestamp, ev.EventTime, ev.FirstTimestamp, ev.Metadata.CreationTimestamp),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > maxObjectEvents {
		out = out[:maxObjectEvents]
	}
	return marshal(out)
}

// fieldValue escapes a value for a field selector, where \ , and = are
// special: a name must not add conditions of its own.
func fieldValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`, `=`, `\=`).Replace(s)
}

// deletePod deletes a pod; its controller starts a replacement.
func (e *Executor) deletePod(ctx context.Context, cmd protocol.Command) (string, error) {
	if !strings.EqualFold(cmd.Kind, "pod") {
		return "", fmt.Errorf("only pods can be deleted here, not %q", cmd.Kind)
	}
	path := "/api/v1/namespaces/" + kube.Seg(cmd.Namespace) + "/pods/" + kube.Seg(cmd.Name)
	if _, err := e.Kube.Send(ctx, http.MethodDelete, path, "", nil, 1<<20); err != nil {
		return "", err
	}
	return "pod/" + cmd.Name + " deleted", nil
}

func (e *Executor) cordon(ctx context.Context, cmd protocol.Command) (string, error) {
	if cmd.Flag == nil {
		return "", errors.New("flag is required: true to cordon, false to uncordon")
	}
	patch := map[string]any{"spec": map[string]any{"unschedulable": *cmd.Flag}}
	if err := e.Kube.Patch(ctx, "/api/v1/nodes/"+kube.Seg(cmd.Name), "application/merge-patch+json", patch); err != nil {
		return "", err
	}
	if *cmd.Flag {
		return "node/" + cmd.Name + " cordoned", nil
	}
	return "node/" + cmd.Name + " uncordoned", nil
}

func cronJobPath(ns, name string) string {
	return "/apis/batch/v1/namespaces/" + kube.Seg(ns) + "/cronjobs/" + kube.Seg(name)
}

func (e *Executor) suspend(ctx context.Context, cmd protocol.Command) (string, error) {
	if cmd.Flag == nil {
		return "", errors.New("flag is required: true to suspend, false to resume")
	}
	patch := map[string]any{"spec": map[string]any{"suspend": *cmd.Flag}}
	if err := e.Kube.Patch(ctx, cronJobPath(cmd.Namespace, cmd.Name), "application/merge-patch+json", patch); err != nil {
		return "", err
	}
	if *cmd.Flag {
		return "cronjob/" + cmd.Name + " suspended", nil
	}
	return "cronjob/" + cmd.Name + " resumed", nil
}

// trigger starts a Job from a CronJob's template right away, like
// "kubectl create job --from=cronjob/NAME".
func (e *Executor) trigger(ctx context.Context, cmd protocol.Command) (string, error) {
	var cj struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			JobTemplate struct {
				Metadata struct {
					Labels      map[string]string `json:"labels"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
				Spec json.RawMessage `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}
	if err := e.Kube.Get(ctx, cronJobPath(cmd.Namespace, cmd.Name), &cj); err != nil {
		return "", err
	}
	annotations := map[string]string{"cronjob.kubernetes.io/instantiate": "manual"}
	for k, v := range cj.Spec.JobTemplate.Metadata.Annotations {
		annotations[k] = v
	}
	name := strings.TrimRight(truncate(cmd.Name, 44), "-.") + "-manual-" + strconv.FormatInt(e.now().Unix(), 36)
	job := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":        name,
			"namespace":   cmd.Namespace,
			"labels":      cj.Spec.JobTemplate.Metadata.Labels,
			"annotations": annotations,
			"ownerReferences": []map[string]any{{
				"apiVersion": "batch/v1", "kind": "CronJob", "name": cmd.Name, "uid": cj.Metadata.UID, "controller": true,
			}},
		},
		"spec": cj.Spec.JobTemplate.Spec,
	}
	body, err := json.Marshal(job)
	if err != nil {
		return "", err
	}
	path := "/apis/batch/v1/namespaces/" + kube.Seg(cmd.Namespace) + "/jobs"
	if _, err := e.Kube.Send(ctx, http.MethodPost, path, "application/json", body, 1<<20); err != nil {
		return "", err
	}
	return "job/" + name + " started from cronjob/" + cmd.Name, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// rollout is a Deployment's history with what a rollback needs besides.
type rollout struct {
	protocol.History
	sets        map[int64]string // each revision's ReplicaSet
	annotations map[string]string
	paused      bool
}

// history lists the ReplicaSets a Deployment owns, which are its revisions.
func (e *Executor) history(ctx context.Context, ns, name string) (rollout, error) {
	var d struct {
		Metadata struct {
			UID         string            `json:"uid"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Paused   bool `json:"paused"`
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
		} `json:"spec"`
	}
	base := "/apis/apps/v1/namespaces/" + kube.Seg(ns)
	if err := e.Kube.Get(ctx, base+"/deployments/"+kube.Seg(name), &d); err != nil {
		return rollout{}, err
	}
	keys := make([]string, 0, len(d.Spec.Selector.MatchLabels))
	for k := range d.Spec.Selector.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		keys[i] = k + "=" + d.Spec.Selector.MatchLabels[k]
	}
	var query url.Values
	if len(keys) > 0 {
		query = url.Values{"labelSelector": {strings.Join(keys, ",")}}
	}
	sets, err := kube.ListAll[kube.ReplicaSet](ctx, e.Kube, base+"/replicasets", query)
	if err != nil {
		return rollout{}, err
	}
	h := protocol.History{Revisions: []protocol.Revision{}}
	h.Current, _ = strconv.ParseInt(d.Metadata.Annotations[revisionKey], 10, 64)
	names := map[int64]string{}
	for _, rs := range sets {
		owned := false
		for _, o := range rs.Metadata.OwnerReferences {
			owned = owned || (o.UID == d.Metadata.UID && o.Kind == "Deployment")
		}
		rev, err := strconv.ParseInt(rs.Metadata.Annotations[revisionKey], 10, 64)
		if !owned || err != nil {
			continue
		}
		replicas := int32(0)
		if rs.Spec.Replicas != nil {
			replicas = *rs.Spec.Replicas
		}
		h.Revisions = append(h.Revisions, protocol.Revision{
			Revision: rev, ReplicaSet: rs.Metadata.Name, Images: images(rs.Spec.Template),
			ChangeCause: rs.Metadata.Annotations["kubernetes.io/change-cause"],
			Replicas:    replicas, Ready: rs.Status.ReadyReplicas, CreatedAt: rs.Metadata.CreationTimestamp,
		})
		names[rev] = rs.Metadata.Name
	}
	sort.Slice(h.Revisions, func(i, j int) bool { return h.Revisions[i].Revision > h.Revisions[j].Revision })
	return rollout{History: h, sets: names, annotations: d.Metadata.Annotations, paused: d.Spec.Paused}, nil
}

// deploymentOwnAnnotations stay on a Deployment through a rollback; its other
// annotations, such as the change cause, come from the revision.
var deploymentOwnAnnotations = map[string]bool{
	"kubectl.kubernetes.io/last-applied-configuration": true,
	"deployment.kubernetes.io/revision":                true,
	"deployment.kubernetes.io/revision-history":        true,
	"deployment.kubernetes.io/desired-replicas":        true,
	"deployment.kubernetes.io/max-replicas":            true,
	"deprecated.deployment.rollback.to":                true,
}

// rollback puts a revision's pod template and annotations back into the
// Deployment, which then rolls out, as "kubectl rollout undo --to-revision"
// does.
func (e *Executor) rollback(ctx context.Context, cmd protocol.Command) (string, error) {
	h, err := e.history(ctx, cmd.Namespace, cmd.Name)
	if err != nil {
		return "", err
	}
	if h.paused {
		return "", fmt.Errorf("deployment/%s is paused; resume it before rolling back", cmd.Name)
	}
	rs, ok := h.sets[cmd.Revision]
	if !ok {
		return "", fmt.Errorf("deployment/%s has no revision %d", cmd.Name, cmd.Revision)
	}
	if cmd.Revision == h.Current {
		return "", fmt.Errorf("deployment/%s is already at revision %d", cmd.Name, cmd.Revision)
	}
	var set struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Template map[string]any `json:"template"`
		} `json:"spec"`
	}
	base := "/apis/apps/v1/namespaces/" + kube.Seg(cmd.Namespace)
	if err := e.Kube.Get(ctx, base+"/replicasets/"+kube.Seg(rs), &set); err != nil {
		return "", err
	}
	if md, ok := set.Spec.Template["metadata"].(map[string]any); ok {
		if labels, ok := md["labels"].(map[string]any); ok {
			delete(labels, "pod-template-hash") // the Deployment adds its own
		}
	}
	annotations := map[string]string{}
	for k, v := range h.annotations {
		if deploymentOwnAnnotations[k] {
			annotations[k] = v
		}
	}
	for k, v := range set.Metadata.Annotations {
		if !deploymentOwnAnnotations[k] {
			annotations[k] = v
		}
	}
	patch := []map[string]any{
		{"op": "replace", "path": "/spec/template", "value": set.Spec.Template},
		{"op": "add", "path": "/metadata/annotations", "value": annotations},
	}
	if err := e.Kube.Patch(ctx, base+"/deployments/"+kube.Seg(cmd.Name), "application/json-patch+json", patch); err != nil {
		return "", err
	}
	return fmt.Sprintf("deployment/%s rolled back to revision %d", cmd.Name, cmd.Revision), nil
}

// exec runs a command in a container, without a terminal, and returns what
// it wrote. It gives up after execTimeout and returns what came until then.
func (e *Executor) exec(ctx context.Context, cmd protocol.Command) (string, error) {
	if len(cmd.Exec) == 0 {
		return "", errors.New("a command is required")
	}
	q := url.Values{"stdout": {"true"}, "stderr": {"true"}, "command": cmd.Exec}
	if cmd.Container != "" {
		q.Set("container", cmd.Container)
	}
	path := "/api/v1/namespaces/" + kube.Seg(cmd.Namespace) + "/pods/" + kube.Seg(cmd.Name) + "/exec?" + q.Encode()
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	out, err := e.Kube.Exec(ctx, path, maxExecBytes)
	res := protocol.ExecResult{Stdout: string(out.Stdout), Stderr: string(out.Stderr), ExitCode: out.ExitCode, Truncated: out.Truncated}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		res.ExitCode = -1
		res.Stderr += fmt.Sprintf("\n[stopped after %s]", execTimeout)
	case err != nil:
		return "", err
	}
	return marshal(res)
}

// apply replaces an object with the YAML in cmd.Body; the API server parses
// it and, thanks to resourceVersion, refuses to overwrite a newer version.
// Secrets are refused: their values reach the UI only as "<redacted>".
func (e *Executor) apply(ctx context.Context, cmd protocol.Command) (string, error) {
	if err := checkName(cmd.Name); err != nil {
		return "", err
	}
	if strings.TrimSpace(cmd.Body) == "" {
		return "", errors.New("the object's YAML is required")
	}
	if cmd.Group == "" && cmd.Resource == "secrets" {
		return "", errors.New("secrets cannot be edited here: their values are never shown, so saving would overwrite them")
	}
	path, err := e.collectionPath(cmd)
	if err != nil {
		return "", err
	}
	path += "/" + kube.Seg(cmd.Name)
	if cmd.DryRun {
		path += "?dryRun=All"
	}
	b, err := e.Kube.Send(ctx, http.MethodPut, path, "application/yaml", []byte(cmd.Body), maxObjectBytes)
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		return "", fmt.Errorf("decode object: %w", err)
	}
	Sanitize(obj)
	return encode(obj, true)
}

// helmReleases lists Helm 3 releases from the Secrets Helm keeps them in:
// their labels name the release, revision and status. When the agent may
// read Secrets, the latest revision's chart and app version are added; the
// release's values are never read out.
func (e *Executor) helmReleases(ctx context.Context) (string, error) {
	scopes := []string{"/api/v1/secrets"}
	if len(e.Namespaces) > 0 {
		scopes = scopes[:0]
		for _, ns := range e.Namespaces {
			scopes = append(scopes, "/api/v1/namespaces/"+kube.Seg(ns)+"/secrets")
		}
	}
	latestByName := map[string]kube.Meta{}
	for _, path := range scopes {
		items, err := kube.ListMetaWith(ctx, e.Kube, path, url.Values{"labelSelector": {"owner=helm"}}, maxListItems)
		if err != nil {
			return "", fmt.Errorf("listing Helm releases needs list access to Secrets (rbac-browse.yaml): %w", err)
		}
		for _, m := range items {
			key := m.Namespace + "/" + m.Labels["name"]
			if cur, ok := latestByName[key]; !ok || atoi(m.Labels["version"]) > atoi(cur.Labels["version"]) {
				latestByName[key] = m
			}
		}
	}
	out := make([]protocol.HelmRelease, 0, len(latestByName))
	for _, m := range latestByName {
		r := protocol.HelmRelease{Namespace: m.Namespace, Name: m.Labels["name"], Revision: atoi(m.Labels["version"]), Status: m.Labels["status"], Updated: m.CreationTimestamp}
		if sec, err := strconv.ParseInt(m.Labels["modifiedAt"], 10, 64); err == nil {
			r.Updated = time.Unix(sec, 0).UTC()
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	for i := range out {
		if i >= maxHelmDetails {
			break
		}
		name := "sh.helm.release.v1." + out[i].Name + ".v" + strconv.Itoa(out[i].Revision)
		if err := e.helmDetails(ctx, &out[i], name); err != nil && !kube.IsNotFound(err) {
			break // most likely no read access to Secrets; the list is still useful
		}
	}
	return marshal(out)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// helmDetails decodes a release Secret: its "release" value is base64 of
// gzipped JSON. Only chart metadata and status fields are kept.
func (e *Executor) helmDetails(ctx context.Context, r *protocol.HelmRelease, secret string) error {
	var s struct {
		Data map[string]string `json:"data"`
	}
	if err := e.Kube.Get(ctx, "/api/v1/namespaces/"+kube.Seg(r.Namespace)+"/secrets/"+kube.Seg(secret), &s); err != nil {
		return err
	}
	inner, err := base64.StdEncoding.DecodeString(s.Data["release"])
	if err != nil {
		return nil
	}
	gz, err := base64.StdEncoding.DecodeString(string(inner))
	if err != nil {
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil
	}
	defer zr.Close()
	var rel struct {
		Info struct {
			Status       string    `json:"status"`
			Description  string    `json:"description"`
			LastDeployed time.Time `json:"last_deployed"`
		} `json:"info"`
		Chart struct {
			Metadata struct {
				Name       string `json:"name"`
				Version    string `json:"version"`
				AppVersion string `json:"appVersion"`
			} `json:"metadata"`
		} `json:"chart"`
	}
	if err := json.NewDecoder(io.LimitReader(zr, 64<<20)).Decode(&rel); err != nil {
		return nil
	}
	r.Chart, r.ChartVersion, r.AppVersion = rel.Chart.Metadata.Name, rel.Chart.Metadata.Version, rel.Chart.Metadata.AppVersion
	r.Description = rel.Info.Description
	if rel.Info.Status != "" {
		r.Status = rel.Info.Status
	}
	if !rel.Info.LastDeployed.IsZero() {
		r.Updated = rel.Info.LastDeployed
	}
	return nil
}
