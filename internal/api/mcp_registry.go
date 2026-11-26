package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

// The image registry's tools, for a server with a registry: they need a
// role in the registry (tool.registry), not in a cluster.

func init() { mcpTools = append(mcpTools, registryTools...) }

// toolFor tells whether a user may use a tool.
func (s *Server) toolFor(u auth.User, t *tool) bool {
	if t.registry {
		return s.cfg.RegistryURL != "" && u.RegistryRole() >= t.role
	}
	return u.ClusterRole() >= t.role
}

var registryTools = []tool{
	{
		name: "list_registry_projects", title: "List the registry's projects", role: auth.Viewer, registry: true, readOnly: true, repeat: true,
		doc: "The image registry's projects you may see: whether each is public, your role, how many repositories and artifacts it holds and their size, " +
			"its quota, immutable tags, whether it scans images on push, and the vulnerabilities' severity it refuses pulls for.",
		call: func(toolArgs) (string, string, any, error) {
			return http.MethodGet, "/api/v1/registry/projects", nil, nil
		},
	},
	{
		name: "list_artifacts", title: "List a registry repository's artifacts", role: auth.Viewer, registry: true, readOnly: true, repeat: true,
		doc: "With a repository: its artifacts (images, multi-arch indexes, Helm charts, signatures, SBOMs), newest first, with their tags, digests, size, " +
			"pushes and pulls, and what the last scan found (counts of critical, high, medium and low vulnerabilities; blocked when its project refuses pulls of it). " +
			"With a project instead: its repositories.",
		args: []toolArg{{name: "repository", typ: "string", doc: "A repository, such as team-a/web."},
			{name: "project", typ: "string", doc: "A project, to list its repositories."}},
		call: func(a toolArgs) (string, string, any, error) {
			switch {
			case a.has("repository"):
				return http.MethodGet, withQuery("/api/v1/registry/repository", url.Values{"name": {a.str("repository")}}), nil, nil
			case a.has("project"):
				return http.MethodGet, "/api/v1/registry/projects/" + seg(a.str("project")) + "/repositories", nil, nil
			}
			return "", "", nil, errors.New("give a repository, or a project to list its repositories")
		},
	},
	{
		name: "image_vulnerabilities", title: "An image's vulnerabilities", role: auth.Viewer, registry: true, readOnly: true, repeat: true,
		doc: "What the last scan of an image found: each vulnerability's ID, severity, package, installed version and the version that fixes it. " +
			"An image is named by a tag or a digest; a multi-arch tag's images are scanned one by one, so give one of them by its digest (list_artifacts shows them).",
		args: []toolArg{{name: "repository", typ: "string", doc: "The repository, such as team-a/web.", required: true},
			{name: "reference", typ: "string", doc: "A tag, such as 1.4.1, or a digest, sha256:....", required: true},
			{name: "severity", typ: "string", doc: "Only those of this severity and worse.", enum: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}},
			{name: "fixable", typ: "boolean", doc: "Only those a newer version of the package fixes."}},
		call: func(a toolArgs) (string, string, any, error) {
			q := url.Values{"repo": {a.str("repository")}, "ref": {a.str("reference")}}
			if a.has("severity") {
				q.Set("severity", a.str("severity"))
			}
			if a.flag("fixable") {
				q.Set("fixable", "true")
			}
			return http.MethodGet, withQuery("/api/v1/registry/vulnerabilities", q), nil, nil
		},
	},
	{
		name: "running_vulnerabilities", title: "Vulnerable images that run", role: auth.Viewer, registry: true, readOnly: true, repeat: true,
		doc: "The registry's images that run in the clusters, where you may see them: each workload with the image it runs and what its last scan found, " +
			"the most critical first (critical counts those its project does not allow).",
		call: func(toolArgs) (string, string, any, error) {
			return http.MethodGet, "/api/v1/registry/running-vulnerabilities", nil, nil
		},
	},
	{
		name: "scan_image", title: "Scan an image", role: auth.Operator, registry: true, repeat: true,
		doc: "Has an image, or a multi-arch index's images, scanned for vulnerabilities again; it runs in the background, image_vulnerabilities shows the result. Needs the operator role in its project.",
		args: []toolArg{{name: "repository", typ: "string", doc: "The repository, such as team-a/web.", required: true},
			{name: "digest", typ: "string", doc: "The artifact's digest, sha256:... (list_artifacts shows it).", required: true}},
		call: func(a toolArgs) (string, string, any, error) {
			return http.MethodPost, "/api/v1/registry/scan", map[string]string{"repo": a.str("repository"), "digest": a.str("digest")}, nil
		},
	},
	{
		name: "registry_jobs", title: "The registry's jobs", role: auth.Admin, registry: true, readOnly: true, repeat: true,
		doc: "The image registry's jobs, newest first (garbage collection, the blobs' check, retention, replication, vulnerability scans): who started each, " +
			"how it ended and what it did, with the schedules. For the registry's admins.",
		args: []toolArg{{name: "limit", typ: "integer", doc: "How many (30 when left out).", min: 1, max: 1000}},
		call: func(a toolArgs) (string, string, any, error) {
			n := 30
			if a.has("limit") {
				n = a.num("limit")
			}
			return http.MethodGet, "/api/v1/registry/jobs?limit=" + strconv.Itoa(n), nil, nil
		},
	},
	{
		name: "run_registry_job", title: "Run a registry job", role: auth.Admin, registry: true, destructive: true,
		doc: "Starts one of the image registry's jobs: gc (garbage collection), verify (the blobs' check), retention (of every project, or of one), " +
			"replication (of a rule, by its ID from registry_jobs or the UI) or scan (every image again). gc and retention delete; run them with dry_run first " +
			"and show the person you work for what would go. For the registry's admins, and a project's admins for its own retention.",
		args: []toolArg{{name: "kind", typ: "string", doc: "The job.", required: true, enum: []string{"gc", "verify", "retention", "replication", "scan"}},
			{name: "dry_run", typ: "boolean", doc: "Only say what it would do (gc, retention, replication)."},
			{name: "project", typ: "string", doc: "For retention: only this project's."},
			{name: "rule", typ: "string", doc: "For replication: the rule's ID."}},
		call: func(a toolArgs) (string, string, any, error) {
			body := map[string]any{"kind": a.str("kind"), "dryRun": a.flag("dry_run")}
			if a.has("project") {
				body["project"] = a.str("project")
			}
			if a.has("rule") {
				body["rule"] = a.str("rule")
			}
			return http.MethodPost, "/api/v1/registry/jobs", body, nil
		},
	},
}
