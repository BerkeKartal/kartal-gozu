package fakekube

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	rsAPICurrent = `{"metadata":{"name":"api-7c9f","namespace":"demo","uid":"uid-rs-2","creationTimestamp":"2026-09-20T10:00:00Z",
			"labels":{"app":"api","pod-template-hash":"7c9f"},
			"annotations":{"deployment.kubernetes.io/revision":"2","kubernetes.io/change-cause":"image abc123"},
			"ownerReferences":[{"kind":"Deployment","name":"api","uid":"uid-deploy-api","controller":true}]},
		"spec":{"replicas":2,"template":{"metadata":{"labels":{"app":"api","pod-template-hash":"7c9f"}},
			"spec":{"containers":[{"name":"app","image":"registry.example.org/demo/api:abc123"}]}}},
		"status":{"readyReplicas":1}}`
	rsAPIPrevious = `{"metadata":{"name":"api-5b6d","namespace":"demo","uid":"uid-rs-1","creationTimestamp":"2026-09-01T10:00:00Z",
			"labels":{"app":"api","pod-template-hash":"5b6d"},
			"annotations":{"deployment.kubernetes.io/revision":"1","kubernetes.io/change-cause":"image 0f00d1"},
			"ownerReferences":[{"kind":"Deployment","name":"api","uid":"uid-deploy-api","controller":true}]},
		"spec":{"replicas":0,"template":{"metadata":{"labels":{"app":"api","pod-template-hash":"5b6d"}},
			"spec":{"containers":[{"name":"app","image":"registry.example.org/demo/api:0f00d1"}]}}},
		"status":{"readyReplicas":0}}`
	// HelmValue is a "secret" inside a Helm release's values; it must never
	// appear in anything the agent sends.
	HelmValue = "helm-value-that-must-stay-put"
)

// drift makes a usage figure move over time when the server is Live, so
// the demo's history charts show something; tests get the base value.
func (f *Server) drift(base, seed int) int {
	if !f.Live {
		return base
	}
	t := float64(time.Now().Unix()) / 240
	v := float64(base) * (1 + 0.35*math.Sin(t+float64(seed)) + 0.1*math.Sin(3.7*t+float64(seed)*1.3))
	return max(1, int(v))
}

// helmSecrets are the Secrets Helm 3 keeps releases in.
func helmSecrets() []string {
	return []string{
		helmSecret("kube-system", "traefik", "traefik", "31.1.1", "v3.3.1", 1, "superseded", "Install complete"),
		helmSecret("kube-system", "traefik", "traefik", "32.0.0", "v3.3.2", 2, "deployed", "Upgrade complete"),
		helmSecret("demo", "api", "api", "1.4.0", "abc123", 3, "failed", "Upgrade \"api\" failed: timed out waiting for the condition"),
	}
}

func helmSecret(ns, name, chart, version, appVersion string, rev int, status, description string) string {
	release, _ := json.Marshal(map[string]any{
		"name": name, "namespace": ns, "version": rev,
		"info": map[string]any{"status": status, "description": description,
			"last_deployed": time.Date(2026, 9, 20+rev, 10, 0, 0, 0, time.UTC)},
		"chart":  map[string]any{"metadata": map[string]any{"name": chart, "version": version, "appVersion": appVersion}},
		"config": map[string]any{"password": HelmValue},
	})
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(release)
	zw.Close()
	helmEncoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	secret, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"name": fmt.Sprintf("sh.helm.release.v1.%s.v%d", name, rev), "namespace": ns,
			"creationTimestamp": time.Date(2026, 9, 20+rev, 10, 0, 0, 0, time.UTC),
			"labels":            map[string]string{"owner": "helm", "name": name, "status": status, "version": fmt.Sprint(rev)},
		},
		"type": "helm.sh/release.v1",
		"data": map[string]string{"release": base64.StdEncoding.EncodeToString([]byte(helmEncoded))},
	})
	return string(secret)
}

// serveMore answers the reads the fixtures in ServeHTTP do not cover.
func (f *Server) serveMore(w http.ResponseWriter, r *http.Request, x extra, metaOnly bool) bool {
	p, q := r.URL.Path, r.URL.Query()
	switch {
	case strings.HasPrefix(q.Get("fieldSelector"), "involvedObject."):
		io.WriteString(w, list(objectEvents(p, q.Get("fieldSelector"))...))
	case q.Get("labelSelector") == "owner=helm" && strings.HasSuffix(p, "/secrets"):
		if !metaOnly {
			writeStatus(w, http.StatusBadRequest, "BadRequest", "full objects requested where names were enough")
			return true
		}
		only := ""
		if rest, ok := strings.CutPrefix(p, "/api/v1/namespaces/"); ok {
			only = strings.TrimSuffix(rest, "/secrets")
		}
		var items []string
		for _, s := range helmSecrets() {
			var obj map[string]any
			json.Unmarshal([]byte(s), &obj)
			md, _ := obj["metadata"].(map[string]any)
			if only != "" && md["namespace"] != only {
				continue
			}
			b, _ := json.Marshal(map[string]any{"metadata": md})
			items = append(items, string(b))
		}
		io.WriteString(w, list(items...))
	case p == "/apis/apps/v1/namespaces/demo/replicasets":
		io.WriteString(w, list(rsAPICurrent, rsAPIPrevious))
	default:
		return false
	}
	return true
}

// objectEvents makes up a plausible event history for any object.
func objectEvents(p, selector string) []string {
	var kind, name string
	for _, part := range strings.Split(selector, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "involvedObject.kind":
			kind = v
		case "involvedObject.name":
			name = v
		}
	}
	ns := "default"
	if rest, ok := strings.CutPrefix(p, "/api/v1/namespaces/"); ok {
		ns, _, _ = strings.Cut(rest, "/")
	}
	ev := func(typ, reason, msg string, count, minutes int) string {
		b, _ := json.Marshal(map[string]any{
			"metadata":       map[string]any{"namespace": ns, "creationTimestamp": "2026-09-29T08:00:00Z"},
			"involvedObject": map[string]any{"kind": kind, "name": name, "namespace": ns},
			"type":           typ, "reason": reason, "message": msg, "count": count,
			"source":         map[string]any{"component": "kubelet", "host": "worker1"},
			"firstTimestamp": "2026-09-29T08:00:00Z",
			"lastTimestamp":  time.Date(2026, 9, 29, 8, minutes, 0, 0, time.UTC),
		})
		return string(b)
	}
	switch kind {
	case "Pod":
		out := []string{
			ev("Normal", "Scheduled", "Successfully assigned "+ns+"/"+name+" to worker1", 1, 0),
			ev("Normal", "Pulled", "Container image already present on machine", 3, 5),
			ev("Normal", "Started", "Started container", 3, 5),
		}
		if name == "api-7c9f-abcde" || strings.HasSuffix(name, "3") {
			out = append(out, ev("Warning", "BackOff", "Back-off restarting failed container", 12, 59))
		}
		return out
	case "Deployment":
		return []string{ev("Normal", "ScalingReplicaSet", "Scaled up replica set "+name+"-7c9f to 2", 1, 10)}
	case "Node":
		return []string{ev("Warning", "NodeHasInsufficientMemory", "Node "+name+" status is now: MemoryPressure", 4, 30)}
	}
	return nil
}

// serveChange answers PATCH, POST, PUT and DELETE, and records them.
func (f *Server) serveChange(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	p := r.URL.Path
	f.mu.Lock()
	f.patches = append(f.patches, Patch{Method: r.Method, Path: r.URL.RequestURI(), ContentType: r.Header.Get("Content-Type"), Body: string(b)})
	f.mu.Unlock()
	x := f.extra()
	switch r.Method {
	case http.MethodPost:
		if strings.HasSuffix(p, "/jobs") {
			w.WriteHeader(http.StatusCreated)
			w.Write(b)
			return
		}
	case http.MethodPut:
		if obj := f.find(p, x); obj != nil {
			md, _ := obj["metadata"].(map[string]any)
			ann, _ := md["annotations"].(map[string]any)
			if ann == nil {
				ann = map[string]any{}
				md["annotations"] = ann
			}
			ann["kartal-gozu.io/demo"] = "the demo keeps objects as they are; this shows what saving would return"
			json.NewEncoder(w).Encode(obj)
			return
		}
	default:
		if f.find(p, x) != nil {
			io.WriteString(w, "{}")
			return
		}
	}
	writeStatus(w, http.StatusNotFound, "NotFound", p+" not found")
}

// serveExec imitates the WebSocket exec endpoint with a tiny fake shell.
func (f *Server) serveExec(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 7 || f.find("/"+strings.Join(parts[:6], "/"), f.extra()) == nil {
		writeStatus(w, http.StatusNotFound, "NotFound", "pod not found")
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeStatus(w, http.StatusBadRequest, "BadRequest", "exec needs a WebSocket upgrade")
		return
	}
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	stdout, stderr, code := fakeShell(parts[5], r.URL.Query()["command"])
	send := func(op byte, payload []byte) {
		hdr := []byte{0x80 | op}
		switch n := len(payload); {
		case n < 126:
			hdr = append(hdr, byte(n))
		case n < 65536:
			hdr = append(hdr, 126, byte(n>>8), byte(n))
		default:
			var l [8]byte
			binary.BigEndian.PutUint64(l[:], uint64(n))
			hdr = append(append(hdr, 127), l[:]...)
		}
		rw.Write(append(hdr, payload...))
	}
	if stdout != "" {
		send(0x2, append([]byte{1}, stdout...))
	}
	if stderr != "" {
		send(0x2, append([]byte{2}, stderr...))
	}
	status := `{"metadata":{},"status":"Success"}`
	if code != 0 {
		status = fmt.Sprintf(`{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"%d"}]}}`, code)
	}
	send(0x2, append([]byte{3}, status...))
	send(0x8, nil)
	rw.Flush()
}

// fakeShell answers a few common commands. The UI wraps each command so the
// working directory survives between them: sh -c SCRIPT kartal CWD, where
// SCRIPT ends by printing "\n\x1f" and the new directory.
func fakeShell(pod string, argv []string) (stdout, stderr string, code int) {
	cwd, command, wrapped := "/", strings.Join(argv, " "), false
	if len(argv) == 5 && argv[0] == "sh" && argv[1] == "-c" {
		lines := strings.Split(argv[2], "\n")
		if len(lines) >= 3 {
			command, cwd, wrapped = strings.TrimSpace(strings.Join(lines[1:len(lines)-3], "\n")), argv[4], true
		}
	}
	if cwd == "" {
		cwd = "/"
	}
	// Like sh: "a && b" runs b only when a succeeded, "a || b" only when it
	// failed, and ";" or a new line runs the next command either way.
	var out, errs strings.Builder
	for _, s := range splitCommands(command) {
		if (s.op == "&&" && code != 0) || (s.op == "||" && code == 0) {
			continue
		}
		o, e, c := fakeCommand(pod, &cwd, s.text)
		out.WriteString(o)
		errs.WriteString(e)
		code = c
	}
	stdout, stderr = out.String(), errs.String()
	if wrapped {
		stdout += "\n\x1f" + cwd
	}
	return stdout, stderr, code
}

type step struct{ op, text string }

// splitCommands cuts a command line at &&, ||, ; and new lines. Quotes are
// not understood; the demo does not need them.
func splitCommands(s string) []step {
	var out []step
	op := ";"
	for {
		i, n, next := len(s), 0, ""
		for _, sep := range []string{"&&", "||", ";", "\n"} {
			if j := strings.Index(s, sep); j >= 0 && j < i {
				i, n, next = j, len(sep), sep
			}
		}
		if text := strings.TrimSpace(s[:i]); text != "" {
			out = append(out, step{op, text})
		}
		if i == len(s) {
			return out
		}
		op = next
		if op == "\n" {
			op = ";"
		}
		s = s[i+n:]
	}
}

var fakeDirs = map[string]string{
	"/":    "app\nbin\ndev\netc\nhome\nlib\nproc\ntmp\nusr\nvar\n",
	"/app": "config.yaml\nserver\nstatic\n",
	"/etc": "alpine-release\nhostname\nhosts\nos-release\npasswd\nresolv.conf\nssl\n",
}

// fakeCommand runs one simple command.
func fakeCommand(pod string, cwd *string, command string) (stdout, stderr string, code int) {
	fields := strings.Fields(command)
	switch fields[0] {
	case "pwd":
		stdout = *cwd + "\n"
	case "cd":
		dir := "/"
		if len(fields) > 1 {
			dir = fields[1]
		}
		*cwd = abs(*cwd, dir)
	case "ls":
		dir := *cwd
		if len(fields) > 1 && !strings.HasPrefix(fields[len(fields)-1], "-") {
			dir = abs(*cwd, fields[len(fields)-1])
		}
		stdout = fakeDirs[dir]
	case "whoami":
		stdout = "app\n"
	case "id":
		stdout = "uid=1000(app) gid=1000(app) groups=1000(app)\n"
	case "hostname":
		stdout = pod + "\n"
	case "env":
		stdout = "HOSTNAME=" + pod + "\nPATH=/usr/local/bin:/usr/bin:/bin\nAPP_ENV=demo\nLOG_LEVEL=debug\nKUBERNETES_SERVICE_HOST=10.96.0.1\n"
	case "date":
		stdout = time.Now().UTC().Format("Mon Jan  2 15:04:05 UTC 2006") + "\n"
	case "uname":
		stdout = "Linux " + pod + " 6.8.0-45-generic #45-Ubuntu SMP x86_64 Linux\n"
	case "cat":
		if len(fields) > 1 && abs(*cwd, fields[1]) == "/etc/os-release" {
			stdout = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"
		} else {
			stderr, code = "cat: can't open '"+strings.Join(fields[1:], " ")+"': No such file or directory\n", 1
		}
	case "echo":
		stdout = strings.Join(fields[1:], " ") + "\n"
	case "ps":
		stdout = "PID   USER     TIME  COMMAND\n    1 app       0:12 /app/server\n   42 app       0:00 sh -c ...\n"
	case "true":
	case "false":
		code = 1
	default:
		stderr, code = "sh: "+fields[0]+": not found\n", 127
	}
	return stdout, stderr, code
}

// abs resolves p against the working directory.
func abs(cwd, p string) string {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(cwd, p)
	}
	return path.Clean(p)
}
