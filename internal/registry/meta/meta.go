// Package meta keeps what the registry knows besides the blobs: projects,
// repositories, the artifacts (manifests) in them and their tags, which
// blobs each repository may read, and a log of what people did.
//
// Everything is held in memory. Each change is written to a log of JSON
// lines and synced before it is applied, and the whole state is written to
// a snapshot now and then, after which the log starts over. Opening reads
// the snapshot and replays the log; a last line cut short by a crash is
// dropped. Every line sets a value rather than adding to one, so a line
// replayed twice (a crash between a snapshot and the log's truncation)
// changes nothing.
package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/scanner"
)

var (
	// ErrNoProject is a repository whose project does not exist: projects
	// are made first, as in Harbor.
	ErrNoProject = errors.New("project not found")
	// ErrNotFound is a repository, artifact or tag that is not there.
	ErrNotFound = errors.New("not found")
	// ErrNotEmpty is a project that still has repositories.
	ErrNotEmpty = errors.New("the project still has repositories")
	// ErrExists is a project that is already there.
	ErrExists = errors.New("already exists")
	// ErrInUse is what something else needs: an image an index of its
	// repository lists (deleting it would take a platform out of the
	// index, which goes first), or a blob an artifact uses.
	ErrInUse = errors.New("in use")
	// ErrImmutable is a change that an immutable tag does not allow.
	ErrImmutable = errors.New("immutable")
	// ErrQuota is a blob that does not fit in its project's quota.
	ErrQuota = errors.New("over the project's quota")
)

// Project groups repositories: the first part of a repository's name.
type Project struct {
	Name        string    `json:"name"`
	Public      bool      `json:"public"`
	Description string    `json:"description,omitempty"`
	Created     time.Time `json:"created"`
	CreatedBy   string    `json:"createdBy,omitempty"`
	// Immutable are patterns of tags (as path.Match takes them: v*,
	// release-*) that stay where they are once on an artifact: such a tag
	// is not moved or removed, and its artifact is not deleted.
	Immutable []string `json:"immutable,omitempty"`
	// Quota is how many bytes the project may hold, each blob counted
	// once; 0 is no limit.
	Quota int64 `json:"quota,omitempty"`
	// Retention are the rules that decide which artifacts stay: each picks
	// some and keeps some of those; one that a rule picks and none keeps
	// is deleted when retention runs. What no rule picks is left alone.
	Retention []RetentionRule `json:"retention,omitempty"`
	// ScanOnPush scans each image pushed (or copied) into the project for
	// known vulnerabilities, when the registry has a scanner.
	ScanOnPush bool `json:"scanOnPush,omitempty"`
	// BlockSeverity refuses pulls of an image with a vulnerability of that
	// severity or worse (CRITICAL, HIGH, MEDIUM, LOW) that Allowlist does
	// not name; empty lets every image be pulled. An image not scanned yet
	// is let through.
	BlockSeverity string   `json:"blockSeverity,omitempty"`
	Allowlist     []string `json:"allowlist,omitempty"`
	// Store is the blob store its blobs go to; empty is DefaultStore.
	Store string `json:"store,omitempty"`
	// MovedFrom is the store a move takes the project's blobs from: until
	// the move ends, a blob Store lacks is read there, and that store
	// keeps the project's blobs.
	MovedFrom string `json:"movedFrom,omitempty"`
}

// DefaultStore is the registry's own blob store, on its data volume.
const DefaultStore = "default"

// StoreName is the blob store a project's blobs go to.
func (p Project) StoreName() string {
	if p.Store == "" {
		return DefaultStore
	}
	return p.Store
}

// BlobStore is a store of blobs besides the registry's own: a directory
// (a volume of its own), or a bucket of S3 or of what speaks its API.
type BlobStore struct {
	Name string `json:"name"`
	// Kind is file or s3.
	Kind string `json:"kind"`
	// Path is a file store's directory.
	Path string `json:"path,omitempty"`
	// Of an S3 store: where, which bucket, below which prefix, and who.
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	AccessKey string `json:"accessKey,omitempty"`
	// Secret is the secret key, sealed: the registry alone opens it.
	Secret    string `json:"secret,omitempty"`
	PathStyle bool   `json:"pathStyle,omitempty"`
	CA        string `json:"ca,omitempty"`
	Insecure  bool   `json:"insecure,omitempty"`
	// Quota is a soft quota in bytes: past 90% of it there is an alert;
	// nothing is refused (a project's quota refuses).
	Quota   int64     `json:"quota,omitempty"`
	Created time.Time `json:"created"`
	By      string    `json:"by,omitempty"`
}

// Allows tells whether a project's allowlist names a vulnerability.
func (p Project) Allows(id string) bool {
	for _, a := range p.Allowlist {
		if strings.EqualFold(a, id) {
			return true
		}
	}
	return false
}

// Scan is what is known of an image's vulnerabilities: what its last scan
// found, and whether another is waiting or under way. Its report is kept
// next to the metadata, not in it.
type Scan struct {
	Digest string `json:"digest"`
	// Repo is a repository it is pulled from to be scanned.
	Repo   string     `json:"repo"`
	Status string     `json:"status"`
	Queued time.Time  `json:"queued"`
	By     string     `json:"by,omitempty"`
	Start  *time.Time `json:"start,omitempty"`
	// Of the last scan that ended: when, by what scanner, with a database
	// of when, and what it found, or why it failed (Error).
	Scanned  *time.Time       `json:"scanned,omitempty"`
	Scanner  string           `json:"scanner,omitempty"`
	DB       *time.Time       `json:"db,omitempty"`
	Summary  *scanner.Summary `json:"summary,omitempty"`
	OS       string           `json:"os,omitempty"`
	Packages int              `json:"packages,omitempty"`
	Error    string           `json:"error,omitempty"`
}

// A scan's states: waiting its turn, under way, and ended.
const (
	ScanQueued   = "queued"
	ScanScanning = "scanning"
	ScanDone     = "done"
	ScanFailed   = "failed"
)

// RetentionRule picks artifacts of some repositories by their tags, and
// keeps some of them.
type RetentionRule struct {
	// Repositories is a pattern of the repositories' names without the
	// project (web, charts/*); empty or ** is every one.
	Repositories string `json:"repositories,omitempty"`
	// Tags is a pattern of tags (v*, release-*; ** for every tag) the
	// artifacts it picks have; empty picks no tagged one. Untagged picks
	// the untagged too.
	Tags     string `json:"tags,omitempty"`
	Untagged bool   `json:"untagged,omitempty"`
	// Keep is what of them it keeps: the Count latest pushed or pulled
	// (latestPushed, latestPulled), those pushed or pulled within Days
	// (pushedWithin, pulledWithin), or all of them (always).
	Keep  string `json:"keep"`
	Count int    `json:"count,omitempty"`
	Days  int    `json:"days,omitempty"`
}

// Source is a registry that replication copies from.
type Source struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind is harbor, nexus or registry (any of the Distribution API).
	Kind string `json:"kind"`
	URL  string `json:"url"`
	// Repository is the Docker repository of a Nexus.
	Repository string `json:"repository,omitempty"`
	Username   string `json:"username,omitempty"`
	// Secret is the password or token, sealed: the registry alone opens it.
	Secret   string    `json:"secret,omitempty"`
	CA       string    `json:"ca,omitempty"`
	Insecure bool      `json:"insecure,omitempty"`
	Created  time.Time `json:"created"`
	By       string    `json:"by,omitempty"`
}

// ReplicationRule copies images from a source into a project.
type ReplicationRule struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
	// Repositories is a pattern of the source's repositories, whole names
	// (team-a/web, team-a/*, team-a/**, or ** for all); Tags one of their
	// tags (** or empty for all); Within the days they were pushed in, where
	// the source tells (0 for any time).
	Repositories string `json:"repositories"`
	Tags         string `json:"tags,omitempty"`
	Within       int    `json:"within,omitempty"`
	// Project is where they go, each named as at the source without its
	// first part (library/nginx is <project>/nginx), or with all of it
	// (KeepPath).
	Project  string `json:"project"`
	KeepPath bool   `json:"keepPath,omitempty"`
	// Overwrite moves a tag here that points elsewhere; Referrers copies
	// the signatures and SBOMs about what it copies; Platforms keeps of a
	// multi-arch image these (os/arch, os/arch/variant), all when none.
	Overwrite bool     `json:"overwrite,omitempty"`
	Referrers bool     `json:"referrers,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
	// Concurrency is how many images it copies at once; BandwidthKiB how
	// many KiB a second it may pull (0 for no limit).
	Concurrency  int `json:"concurrency,omitempty"`
	BandwidthKiB int `json:"bandwidthKiB,omitempty"`
	// Cron runs it on a schedule when Enabled; Since is when that was set,
	// Last when it last started a run.
	Cron    string     `json:"cron,omitempty"`
	Enabled bool       `json:"enabled"`
	Since   time.Time  `json:"since"`
	Last    *time.Time `json:"last,omitempty"`
	Created time.Time  `json:"created"`
	By      string     `json:"by,omitempty"`
}

// RunningImages are what a cluster said it runs, or may run: the digests
// and, of this registry, the repositories with their tags or digests.
type RunningImages struct {
	At      time.Time `json:"at"`
	Digests []string  `json:"digests"`
	Refs    []string  `json:"refs"`
}

// ValidTagPattern tells whether a pattern of immutable tags can be
// matched.
func ValidTagPattern(p string) bool {
	if p == "" || len(p) > 128 || strings.ContainsAny(p, "/ ") {
		return false
	}
	_, err := path.Match(p, "")
	return err == nil
}

// immutable tells whether a tag of a repository is immutable.
func (d *DB) immutable(repo, tag string) bool {
	p := d.projects[ProjectOf(repo)]
	if p == nil {
		return false
	}
	for _, pat := range p.Immutable {
		if ok, _ := path.Match(pat, tag); ok {
			return true
		}
	}
	return false
}

// immutableTag is an immutable tag on an artifact, or "".
func (d *DB) immutableTag(r *Repository, digest string) string {
	tags := []string{}
	for t, dg := range r.Tags {
		if dg == digest && d.immutable(r.Name, t) {
			tags = append(tags, t)
		}
	}
	sort.Strings(tags)
	if len(tags) == 0 {
		return ""
	}
	return tags[0]
}

// immutableError is ErrImmutable, saying which tag.
type immutableError struct{ repo, tag string }

func (e immutableError) Error() string {
	return "the tag " + e.tag + " of " + e.repo + " is immutable in its project"
}

func (e immutableError) Is(target error) bool { return target == ErrImmutable }

// PendingLinks is how long a link no artifact uses still counts: a push
// under way uploads its blobs before the manifest that uses them. Garbage
// collection spares it as long.
const PendingLinks = 2 * time.Hour

// counts tells whether a repository's link counts in what its project
// holds: an artifact uses it, or a push may.
func (d *DB) counts(r *Repository, used map[string]bool, digest string) bool {
	return used[digest] || d.now().Sub(r.Linked[digest]) < PendingLinks
}

// usage is what a project holds: its artifacts' blobs and manifests, and
// the blobs of pushes under way, each once. What an artifact deleted
// leaves behind counts no more, before garbage is collected.
func (d *DB) usage(project string) int64 {
	blobs := map[string]int64{}
	for _, r := range d.repos {
		if ProjectOf(r.Name) != project {
			continue
		}
		used := usedBy(r)
		for dg, n := range r.Blobs {
			if d.counts(r, used, dg) {
				blobs[dg] = n
			}
		}
		for dg, a := range r.Artifacts {
			blobs[dg] = a.Size
		}
	}
	var n int64
	for _, s := range blobs {
		n += s
	}
	return n
}

// holds tells whether a project has a blob already, counted in what it
// holds.
func (d *DB) holds(project, digest string) bool {
	for _, r := range d.repos {
		if ProjectOf(r.Name) == project {
			if _, ok := r.Blobs[digest]; ok && d.counts(r, usedBy(r), digest) {
				return true
			}
		}
	}
	return false
}

// HumanBytes writes a size as people read it: 1.5 GiB.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Artifact is a manifest in a repository.
type Artifact struct {
	Digest       string                `json:"digest"`
	MediaType    string                `json:"mediaType"`
	ArtifactType string                `json:"artifactType,omitempty"`
	Kind         string                `json:"kind"`
	Size         int64                 `json:"size"`
	Config       *manifest.Descriptor  `json:"config,omitempty"`
	Layers       []manifest.Descriptor `json:"layers,omitempty"`
	Manifests    []manifest.Descriptor `json:"manifests,omitempty"`
	Subject      string                `json:"subject,omitempty"`
	Annotations  map[string]string     `json:"annotations,omitempty"`
	// Platform, Created and Labels come from an image's config.
	Platform *manifest.Platform `json:"platform,omitempty"`
	Created  *time.Time         `json:"created,omitempty"`
	Labels   map[string]string  `json:"labels,omitempty"`
	Pushed   time.Time          `json:"pushed"`
	PushedBy string             `json:"pushedBy,omitempty"`
	LastPull *time.Time         `json:"lastPull,omitempty"`
	Pulls    int64              `json:"pulls"`
}

// Repository is a named set of artifacts.
type Repository struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	// Tags map a tag to an artifact's digest.
	Tags      map[string]string    `json:"tags"`
	Artifacts map[string]*Artifact `json:"artifacts"`
	// Blobs are the blobs the repository may read, with their sizes: those
	// uploaded or mounted into it. A manifest may only refer to these, so
	// that knowing a digest does not open another project's content.
	Blobs map[string]int64 `json:"blobs"`
	// Linked are when its blobs were uploaded or mounted, or used again by
	// a push; collecting garbage spares a blob linked lately, which a push
	// under way has not referred to yet.
	Linked map[string]time.Time `json:"linked,omitempty"`
}

// linkRenewal is how old a link gets before using it again renews it.
const linkRenewal = time.Hour

// Event is something someone did.
type Event struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user,omitempty"`
	Action  string    `json:"action"`
	Project string    `json:"project,omitempty"`
	Repo    string    `json:"repo,omitempty"`
	Digest  string    `json:"digest,omitempty"`
	Tag     string    `json:"tag,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

// Job is a task the registry ran, or runs: collecting garbage, checking
// the blobs.
type Job struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	DryRun bool   `json:"dryRun,omitempty"`
	// Project is the one project a job is about, if one; Rule the
	// replication rule it runs, and RuleName the rule's name then; Store
	// the blob store a move takes a project to.
	Project  string `json:"project,omitempty"`
	Store    string `json:"store,omitempty"`
	Rule     string `json:"rule,omitempty"`
	RuleName string `json:"ruleName,omitempty"`
	// Progress is how far a running job got; it is not kept.
	Progress *JobProgress `json:"progress,omitempty"`
	By       string       `json:"by"`
	Started  time.Time    `json:"started"`
	Finished *time.Time   `json:"finished,omitempty"`
	Status   string       `json:"status"`
	Summary  string       `json:"summary,omitempty"`
	// Error is why it failed; Alarm what it found wrong, though it ran.
	Error  string          `json:"error,omitempty"`
	Alarm  string          `json:"alarm,omitempty"`
	Report json.RawMessage `json:"report,omitempty"`
}

// JobProgress is how far a job got: of what it has to do, what is done,
// and the bytes it moved.
type JobProgress struct {
	Done  int   `json:"done"`
	Total int   `json:"total"`
	Bytes int64 `json:"bytes"`
	// Waiting says it waits for others of its kind to end.
	Waiting bool `json:"waiting,omitempty"`
}

// A job's states.
const (
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// keepJobs is how many jobs are remembered.
const keepJobs = 1000

// keepJobsEach is how many of each kind (and project, and rule) are
// remembered: hourly replications push out no night's collection.
const keepJobsEach = 20

// jobKey is what jobs are remembered by, so many of each.
func jobKey(j Job) string { return j.Kind + "\x00" + j.Project + "\x00" + j.Rule }

// Schedule runs a kind of job by itself, as a cron expression says.
type Schedule struct {
	Kind    string `json:"kind"`
	Cron    string `json:"cron"`
	Enabled bool   `json:"enabled"`
	// Since is when it was set: it first runs at the first time after it.
	Since time.Time `json:"since"`
	// Last is when it last started a job.
	Last *time.Time `json:"last,omitempty"`
	By   string     `json:"by,omitempty"`
}

// keepEvents is how many events are kept.
const keepEvents = 2000

// snapshotEvery is how many log lines lead to a snapshot.
const snapshotEvery = 1000

// entry is one line of the log.
type entry struct {
	Op       string           `json:"op"`
	Project  *Project         `json:"project,omitempty"`
	Name     string           `json:"name,omitempty"`
	Repo     string           `json:"repo,omitempty"`
	Digest   string           `json:"digest,omitempty"`
	Size     int64            `json:"size,omitempty"`
	Tag      string           `json:"tag,omitempty"`
	Artifact *Artifact        `json:"artifact,omitempty"`
	Pulls    int64            `json:"pulls,omitempty"`
	At       *time.Time       `json:"at,omitempty"`
	Event    *Event           `json:"event,omitempty"`
	Job      *Job             `json:"job,omitempty"`
	Schedule *Schedule        `json:"schedule,omitempty"`
	Running  *RunningImages   `json:"running,omitempty"`
	Source   *Source          `json:"source,omitempty"`
	Rule     *ReplicationRule `json:"rule,omitempty"`
	Scan     *Scan            `json:"scan,omitempty"`
	Store    *BlobStore       `json:"store,omitempty"`
}

type state struct {
	Projects  []*Project               `json:"projects"`
	Repos     []*Repository            `json:"repositories"`
	Events    []Event                  `json:"events"`
	Jobs      []Job                    `json:"jobs,omitempty"`
	Schedules []Schedule               `json:"schedules,omitempty"`
	Running   map[string]RunningImages `json:"running,omitempty"`
	Sources   []Source                 `json:"sources,omitempty"`
	Rules     []ReplicationRule        `json:"rules,omitempty"`
	Scans     []Scan                   `json:"scans,omitempty"`
	Stores    []BlobStore              `json:"stores,omitempty"`
}

// DB is the registry's metadata.
type DB struct {
	dir string
	now func() time.Time

	mu  sync.RWMutex
	wal *os.File
	// size is where the log ends, so that a write cut short can be undone.
	size  int64
	lines int
	// snapErr is the last snapshot's failure; the log keeps everything
	// meanwhile, and the next change tries again.
	snapErr   error
	projects  map[string]*Project
	repos     map[string]*Repository
	events    []Event
	jobs      []Job
	schedules map[string]Schedule
	// running are what each cluster last said it runs.
	running map[string]RunningImages
	sources map[string]Source
	rules   map[string]ReplicationRule
	// scans are by digest.
	scans map[string]Scan
	// stores are the blob stores besides the default one, by name.
	stores map[string]BlobStore
	// pulled are the artifacts pulled since their counts were last written.
	pulled map[[2]string]bool
	// onEvent hears of each event as it is written.
	onEvent func(Event)
}

// SetOnEvent hands each event to fn as it is written, such as to forward
// it to kartal-server. fn is called with the DB locked: it must not wait,
// nor call the DB.
func (d *DB) SetOnEvent(fn func(Event)) {
	d.mu.Lock()
	d.onEvent = fn
	d.mu.Unlock()
}

// Open reads the metadata kept in dir, or starts it there.
func Open(dir string) (*DB, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	d := &DB{dir: dir, now: time.Now, projects: map[string]*Project{}, repos: map[string]*Repository{}, pulled: map[[2]string]bool{},
		schedules: map[string]Schedule{}, running: map[string]RunningImages{}, sources: map[string]Source{},
		rules: map[string]ReplicationRule{}, scans: map[string]Scan{}, stores: map[string]BlobStore{}}
	if b, err := os.ReadFile(d.path("snapshot.json")); err == nil {
		var s state
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("the snapshot cannot be read: %w", err)
		}
		for _, p := range s.Projects {
			d.projects[p.Name] = p
		}
		for _, r := range s.Repos {
			fill(r)
			d.repos[r.Name] = r
		}
		d.events = s.Events
		d.jobs = s.Jobs
		for _, sc := range s.Schedules {
			d.schedules[sc.Kind] = sc
		}
		for name, ri := range s.Running {
			d.running[name] = ri
		}
		for _, src := range s.Sources {
			d.sources[src.ID] = src
		}
		for _, r := range s.Rules {
			d.rules[r.ID] = r
		}
		for _, sc := range s.Scans {
			d.scans[sc.Digest] = sc
		}
		for _, bs := range s.Stores {
			d.stores[bs.Name] = bs
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	good, err := d.replay()
	if err != nil {
		return nil, err
	}
	wal, err := os.OpenFile(d.path("wal.jsonl"), os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	// What follows the last whole line was cut short; it goes.
	if err := wal.Truncate(good); err != nil {
		wal.Close()
		return nil, err
	}
	if _, err := wal.Seek(good, io.SeekStart); err != nil {
		wal.Close()
		return nil, err
	}
	d.wal, d.size = wal, good
	return d, nil
}

func (d *DB) path(name string) string { return filepath.Join(d.dir, name) }

func fill(r *Repository) {
	if r.Tags == nil {
		r.Tags = map[string]string{}
	}
	if r.Artifacts == nil {
		r.Artifacts = map[string]*Artifact{}
	}
	if r.Blobs == nil {
		r.Blobs = map[string]int64{}
	}
	if r.Linked == nil {
		r.Linked = map[string]time.Time{}
	}
}

// replay applies the log, and says where its last whole line ends.
func (d *DB) replay() (int64, error) {
	b, err := os.ReadFile(d.path("wal.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var good int64
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			// A last line without its newline was being written.
			break
		}
		line := b[:i]
		var e entry
		if err := json.Unmarshal(line, &e); err != nil {
			if len(b) == i+1 {
				break
			}
			return 0, fmt.Errorf("line %d of the log cannot be read: %w", d.lines+1, err)
		}
		d.apply(e)
		d.lines++
		good += int64(i + 1)
		b = b[i+1:]
	}
	return good, nil
}

// apply makes a change in memory; the lock is held, or nobody else has the
// DB yet.
func (d *DB) apply(e entry) {
	switch e.Op {
	case "project":
		p := *e.Project
		d.projects[p.Name] = &p
	case "project-del":
		delete(d.projects, e.Name)
	case "repo":
		if d.repos[e.Name] == nil {
			r := &Repository{Name: e.Name}
			if e.At != nil {
				r.Created = *e.At
			}
			fill(r)
			d.repos[e.Name] = r
		}
	case "repo-del":
		delete(d.repos, e.Name)
	case "link":
		if r := d.repos[e.Repo]; r != nil {
			r.Blobs[e.Digest] = e.Size
			if e.At != nil {
				r.Linked[e.Digest] = *e.At
			}
		}
	case "unlink":
		if r := d.repos[e.Repo]; r != nil {
			delete(r.Blobs, e.Digest)
			delete(r.Linked, e.Digest)
		}
	case "artifact":
		if r := d.repos[e.Repo]; r != nil {
			a := *e.Artifact
			r.Artifacts[a.Digest] = &a
		}
	case "artifact-del":
		if r := d.repos[e.Repo]; r != nil {
			delete(r.Artifacts, e.Digest)
			for t, dg := range r.Tags {
				if dg == e.Digest {
					delete(r.Tags, t)
				}
			}
		}
	case "tag":
		if r := d.repos[e.Repo]; r != nil {
			r.Tags[e.Tag] = e.Digest
		}
	case "untag":
		if r := d.repos[e.Repo]; r != nil {
			delete(r.Tags, e.Tag)
		}
	case "pulls":
		if r := d.repos[e.Repo]; r != nil {
			if a := r.Artifacts[e.Digest]; a != nil {
				a.Pulls = e.Pulls
				if e.At != nil {
					t := *e.At
					a.LastPull = &t
				}
			}
		}
	case "event":
		d.events = append(d.events, *e.Event)
		if len(d.events) > keepEvents {
			d.events = append([]Event(nil), d.events[len(d.events)-keepEvents:]...)
		}
	case "job":
		for i := range d.jobs {
			if d.jobs[i].ID == e.Job.ID {
				d.jobs[i] = *e.Job
				return
			}
		}
		d.jobs = append(d.jobs, *e.Job)
		key, n := jobKey(*e.Job), 0
		for _, j := range d.jobs {
			if jobKey(j) == key {
				n++
			}
		}
		if n > keepJobsEach {
			for i, j := range d.jobs {
				if jobKey(j) == key {
					d.jobs = append(d.jobs[:i:i], d.jobs[i+1:]...)
					break
				}
			}
		}
		if len(d.jobs) > keepJobs {
			d.jobs = append([]Job(nil), d.jobs[len(d.jobs)-keepJobs:]...)
		}
	case "schedule":
		d.schedules[e.Schedule.Kind] = *e.Schedule
	case "running":
		d.running[e.Name] = *e.Running
	case "source":
		d.sources[e.Source.ID] = *e.Source
	case "source-del":
		delete(d.sources, e.Name)
	case "rule":
		d.rules[e.Rule.ID] = *e.Rule
	case "rule-del":
		delete(d.rules, e.Name)
	case "scan":
		d.scans[e.Scan.Digest] = *e.Scan
	case "scan-del":
		delete(d.scans, e.Name)
	case "store":
		d.stores[e.Store.Name] = *e.Store
	case "store-del":
		delete(d.stores, e.Name)
	}
}

// commit writes entries to the log, syncs it, then applies them; the lock
// is held.
func (d *DB) commit(entries ...entry) error {
	var buf bytes.Buffer
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if _, err := d.wal.Write(buf.Bytes()); err != nil {
		// Half a line would make every later one unreadable.
		d.undo()
		return fmt.Errorf("writing the metadata log: %w", err)
	}
	if err := d.wal.Sync(); err != nil {
		d.undo()
		return fmt.Errorf("syncing the metadata log: %w", err)
	}
	d.size += int64(buf.Len())
	for _, e := range entries {
		d.apply(e)
		if e.Op == "event" && d.onEvent != nil {
			d.onEvent(*e.Event)
		}
	}
	d.lines += len(entries)
	if d.lines >= snapshotEvery {
		// The change is in the log already; a snapshot that fails is tried
		// again with the next one.
		d.snapErr = d.snapshot()
	}
	return nil
}

// undo cuts the log back to its last whole line.
func (d *DB) undo() {
	_ = d.wal.Truncate(d.size)
	_, _ = d.wal.Seek(d.size, io.SeekStart)
}

// Healthy says whether the last snapshot failed.
func (d *DB) Healthy() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.snapErr
}

// snapshot writes the state and starts the log over; the lock is held.
func (d *DB) snapshot() error {
	s := state{Events: d.events, Jobs: d.jobs, Running: d.running}
	for _, sc := range d.schedules {
		s.Schedules = append(s.Schedules, sc)
	}
	sort.Slice(s.Schedules, func(i, j int) bool { return s.Schedules[i].Kind < s.Schedules[j].Kind })
	for _, src := range d.sources {
		s.Sources = append(s.Sources, src)
	}
	sort.Slice(s.Sources, func(i, j int) bool { return s.Sources[i].ID < s.Sources[j].ID })
	for _, r := range d.rules {
		s.Rules = append(s.Rules, r)
	}
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].ID < s.Rules[j].ID })
	for _, sc := range d.scans {
		s.Scans = append(s.Scans, sc)
	}
	sort.Slice(s.Scans, func(i, j int) bool { return s.Scans[i].Digest < s.Scans[j].Digest })
	for _, bs := range d.stores {
		s.Stores = append(s.Stores, bs)
	}
	sort.Slice(s.Stores, func(i, j int) bool { return s.Stores[i].Name < s.Stores[j].Name })
	for _, p := range d.projects {
		s.Projects = append(s.Projects, p)
	}
	for _, r := range d.repos {
		s.Repos = append(s.Repos, r)
	}
	sort.Slice(s.Projects, func(i, j int) bool { return s.Projects[i].Name < s.Projects[j].Name })
	sort.Slice(s.Repos, func(i, j int) bool { return s.Repos[i].Name < s.Repos[j].Name })
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := d.path("snapshot.json.tmp")
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, d.path("snapshot.json")); err != nil {
		return err
	}
	if dir, err := os.Open(d.dir); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	if err := d.wal.Truncate(0); err != nil {
		return err
	}
	if _, err := d.wal.Seek(0, io.SeekStart); err != nil {
		return err
	}
	d.lines, d.size = 0, 0
	return d.wal.Sync()
}

// Snapshot writes the whole state now, and starts the log over.
func (d *DB) Snapshot() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.flushPulls(); err != nil {
		return err
	}
	return d.snapshot()
}

// Close writes what is not written yet.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.flushPulls()
	if err == nil {
		err = d.snapshot()
	}
	if cerr := d.wal.Close(); err == nil {
		err = cerr
	}
	return err
}

// SetClock sets what the database takes for now: for tests, and for the
// demo, which makes up a past.
func (d *DB) SetClock(now func() time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.now = now
}

func (d *DB) event(user, action, project, repo, digest, tag, detail string) entry {
	return entry{Op: "event", Event: &Event{Time: d.now().UTC(), User: user, Action: action, Project: project, Repo: repo,
		Digest: digest, Tag: tag, Detail: detail}}
}

// ProjectOf is the project a repository belongs to: the first part of its
// name.
func ProjectOf(repo string) string {
	p, _, _ := strings.Cut(repo, "/")
	return p
}

// ---------------------------------------------------------------- projects

// ProjectInfo is a project with what it holds.
type ProjectInfo struct {
	Project
	Repositories int   `json:"repositories"`
	Artifacts    int   `json:"artifacts"`
	Size         int64 `json:"size"`
}

// Projects are every project, by name.
func (d *DB) Projects() []ProjectInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]ProjectInfo, 0, len(d.projects))
	for _, p := range d.projects {
		info := ProjectInfo{Project: *p, Size: d.usage(p.Name)}
		for _, r := range d.repos {
			if ProjectOf(r.Name) == p.Name {
				info.Repositories++
				info.Artifacts += len(r.Artifacts)
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Project is one project.
func (d *DB) Project(name string) (Project, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.projects[name]
	if !ok {
		return Project{}, false
	}
	return *p, true
}

// CreateProject adds a project.
func (d *DB) CreateProject(p Project, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.projects[p.Name]; ok {
		return ErrExists
	}
	if p.Store == DefaultStore {
		p.Store = ""
	}
	if _, ok := d.stores[p.Store]; p.Store != "" && !ok {
		return fmt.Errorf("%w: no blob store %s", ErrNotFound, p.Store)
	}
	p.Created, p.CreatedBy = d.now().UTC(), user
	return d.commit(entry{Op: "project", Project: &p}, d.event(user, "project-create", p.Name, "", "", "", visibility(p.Public)))
}

func visibility(public bool) string {
	if public {
		return "public"
	}
	return "private"
}

// ProjectChange is what changes in a project; a field left nil stays as
// it is.
type ProjectChange struct {
	Public      *bool            `json:"public"`
	Description *string          `json:"description"`
	Immutable   *[]string        `json:"immutable"`
	Quota       *int64           `json:"quota"`
	Retention   *[]RetentionRule `json:"retention"`
	ScanOnPush  *bool            `json:"scanOnPush"`
	// BlockSeverity is "" for no policy; Allowlist the vulnerabilities let
	// through.
	BlockSeverity *string   `json:"blockSeverity"`
	Allowlist     *[]string `json:"allowlist"`
	// Store moves a project with no repositories to another blob store.
	Store *string `json:"store"`
}

// UpdateProject changes a project: whether it is public, its description,
// its immutable tags and its quota.
func (d *DB) UpdateProject(name string, ch ProjectChange, user string) (Project, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, ok := d.projects[name]
	if !ok {
		return Project{}, ErrNoProject
	}
	p := *cur
	var said []string
	if ch.Public != nil && *ch.Public != p.Public {
		p.Public = *ch.Public
		said = append(said, visibility(p.Public))
	}
	if ch.Description != nil {
		p.Description = *ch.Description
	}
	if ch.Immutable != nil && strings.Join(*ch.Immutable, ",") != strings.Join(p.Immutable, ",") {
		p.Immutable = append([]string(nil), *ch.Immutable...)
		if len(p.Immutable) == 0 {
			p.Immutable = nil
			said = append(said, "no immutable tags")
		} else {
			said = append(said, "immutable tags "+strings.Join(p.Immutable, ", "))
		}
	}
	if ch.Retention != nil {
		before, _ := json.Marshal(p.Retention)
		p.Retention = append([]RetentionRule(nil), *ch.Retention...)
		if len(p.Retention) == 0 {
			p.Retention = nil
		}
		if after, _ := json.Marshal(p.Retention); string(after) != string(before) {
			said = append(said, fmt.Sprintf("retention rules: %d", len(p.Retention)))
		}
	}
	if ch.Quota != nil && *ch.Quota != p.Quota {
		p.Quota = *ch.Quota
		if p.Quota == 0 {
			said = append(said, "no quota")
		} else {
			said = append(said, "quota "+HumanBytes(p.Quota))
		}
	}
	if ch.Store != nil {
		to := *ch.Store
		if to == DefaultStore {
			to = ""
		}
		if to != p.Store {
			if _, ok := d.stores[to]; to != "" && !ok {
				return Project{}, fmt.Errorf("%w: no blob store %s", ErrNotFound, to)
			}
			if p.MovedFrom != "" {
				return Project{}, fmt.Errorf("%w: the project is being moved from %s", ErrNotEmpty, p.MovedFrom)
			}
			for rn := range d.repos {
				if ProjectOf(rn) == name {
					return Project{}, fmt.Errorf("%w: a project with repositories moves to another blob store with a job", ErrNotEmpty)
				}
			}
			p.Store = to
			said = append(said, "blob store "+p.StoreName())
		}
	}
	if ch.ScanOnPush != nil && *ch.ScanOnPush != p.ScanOnPush {
		p.ScanOnPush = *ch.ScanOnPush
		if p.ScanOnPush {
			said = append(said, "scan on push")
		} else {
			said = append(said, "no scan on push")
		}
	}
	if ch.BlockSeverity != nil && *ch.BlockSeverity != p.BlockSeverity {
		p.BlockSeverity = *ch.BlockSeverity
		if p.BlockSeverity == "" {
			said = append(said, "no pulls refused for vulnerabilities")
		} else {
			said = append(said, "pulls refused for "+strings.ToLower(p.BlockSeverity)+" vulnerabilities or worse")
		}
	}
	if ch.Allowlist != nil && strings.Join(*ch.Allowlist, ",") != strings.Join(p.Allowlist, ",") {
		added, removed := listChange(p.Allowlist, *ch.Allowlist)
		p.Allowlist = append([]string(nil), *ch.Allowlist...)
		if len(p.Allowlist) == 0 {
			p.Allowlist = nil
		}
		if len(added) > 0 {
			said = append(said, "allowed "+strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			said = append(said, "no longer allowed "+strings.Join(removed, ", "))
		}
	}
	if err := d.commit(entry{Op: "project", Project: &p}, d.event(user, "project-update", name, "", "", "", strings.Join(said, "; "))); err != nil {
		return Project{}, err
	}
	return p, nil
}

// listChange is what was added to a list and what was taken from it.
func listChange(before, after []string) (added, removed []string) {
	in := func(list []string, x string) bool {
		for _, y := range list {
			if strings.EqualFold(x, y) {
				return true
			}
		}
		return false
	}
	for _, x := range after {
		if !in(before, x) {
			added = append(added, x)
		}
	}
	for _, x := range before {
		if !in(after, x) {
			removed = append(removed, x)
		}
	}
	return added, removed
}

// DeleteProject removes a project that has no repositories left.
func (d *DB) DeleteProject(name, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.projects[name]; !ok {
		return ErrNoProject
	}
	for rn := range d.repos {
		if ProjectOf(rn) == name {
			return ErrNotEmpty
		}
	}
	// A rule that copies into it would fail every time it ran.
	for _, r := range d.rules {
		if r.Project == name {
			return fmt.Errorf("%w: the replication rule %s copies into it; delete the rule or change its project first", ErrInUse, r.Name)
		}
	}
	return d.commit(entry{Op: "project-del", Name: name}, d.event(user, "project-delete", name, "", "", "", ""))
}

// ---------------------------------------------------------------- repositories

// ensure makes a repository on its first push; the lock is held.
func (d *DB) ensure(repo string) ([]entry, error) {
	if d.repos[repo] != nil {
		return nil, nil
	}
	if d.projects[ProjectOf(repo)] == nil {
		return nil, ErrNoProject
	}
	t := d.now().UTC()
	return []entry{{Op: "repo", Name: repo, At: &t}}, nil
}

// LinkBlob lets a repository read a blob, which was uploaded or mounted
// into it, or which a push uses again: a link older than linkRenewal is
// renewed then.
func (d *DB) LinkBlob(repo, digest string, size int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now().UTC()
	if r := d.repos[repo]; r != nil {
		if n, ok := r.Blobs[digest]; ok && n == size && now.Sub(r.Linked[digest]) < linkRenewal {
			return nil
		}
	}
	entries, err := d.ensure(repo)
	if err != nil {
		return err
	}
	// A blob the project has already takes no more room.
	if p := d.projects[ProjectOf(repo)]; p.Quota > 0 && !d.holds(p.Name, digest) {
		if used := d.usage(p.Name); used+size > p.Quota {
			return fmt.Errorf("%w: %s holds %s of %s, and this is %s more", ErrQuota, p.Name, HumanBytes(used), HumanBytes(p.Quota), HumanBytes(size))
		}
	}
	return d.commit(append(entries, entry{Op: "link", Repo: repo, Digest: digest, Size: size, At: &now})...)
}

// UnlinkBlob takes a blob away from a repository.
func (d *DB) UnlinkBlob(repo, digest string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil {
		return ErrNotFound
	}
	if _, ok := r.Blobs[digest]; !ok {
		return ErrNotFound
	}
	// The artifacts that use it would not pull any more.
	if usedBy(r)[digest] {
		return fmt.Errorf("%w: an artifact of %s uses it", ErrInUse, repo)
	}
	return d.commit(entry{Op: "unlink", Repo: repo, Digest: digest})
}

// ---------------------------------------------------------------- garbage

// usedBy are the blobs a repository's artifacts use: their manifests,
// configs and layers, but for layers pulled from elsewhere (with urls),
// which the registry never has.
func usedBy(r *Repository) map[string]bool {
	used := map[string]bool{}
	for dg, a := range r.Artifacts {
		used[dg] = true
		if a.Config != nil {
			used[a.Config.Digest] = true
		}
		for _, l := range a.Layers {
			if len(l.URLs) == 0 {
				used[l.Digest] = true
			}
		}
	}
	return used
}

// GarbageLinks are, by repository, the blobs it links that none of its
// artifacts uses, linked before a time.
func (d *DB) GarbageLinks(before time.Time) map[string][]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string][]string{}
	for name, r := range d.repos {
		used := usedBy(r)
		for dg := range r.Blobs {
			if !used[dg] && r.Linked[dg].Before(before) {
				out[name] = append(out[name], dg)
			}
		}
		sort.Strings(out[name])
	}
	return out
}

// UnlinkGarbage takes the garbage links away, those that still are: unused,
// and not linked again since the time. It tells how many it took.
func (d *DB) UnlinkGarbage(garbage map[string][]string, before time.Time) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var entries []entry
	done := 0
	flush := func() error {
		if len(entries) == 0 {
			return nil
		}
		if err := d.commit(entries...); err != nil {
			return err
		}
		done += len(entries)
		entries = entries[:0]
		return nil
	}
	names := make([]string, 0, len(garbage))
	for name := range garbage {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := d.repos[name]
		if r == nil {
			continue
		}
		used := usedBy(r)
		for _, dg := range garbage[name] {
			if _, ok := r.Blobs[dg]; ok && !used[dg] && r.Linked[dg].Before(before) {
				entries = append(entries, entry{Op: "unlink", Repo: name, Digest: dg})
				if len(entries) >= 500 {
					if err := flush(); err != nil {
						return done, err
					}
				}
			}
		}
	}
	return done, flush()
}

// BlobsInUse are the blobs some repository links or uses, but for the
// links left out (as GarbageLinks gives them).
func (d *DB) BlobsInUse(except map[string][]string) map[string]bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string]bool{}
	for name, r := range d.repos {
		skip := map[string]bool{}
		for _, dg := range except[name] {
			skip[dg] = true
		}
		for dg := range r.Blobs {
			if !skip[dg] {
				out[dg] = true
			}
		}
		for dg := range usedBy(r) {
			out[dg] = true
		}
	}
	return out
}

// InUse tells whether some repository links a blob, or has it as a
// manifest. What an artifact uses is linked (UnlinkBlob keeps it so), so
// that is all there is to look at.
func (d *DB) InUse(digest string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, r := range d.repos {
		if _, ok := r.Blobs[digest]; ok {
			return true
		}
		if r.Artifacts[digest] != nil {
			return true
		}
	}
	return false
}

// Uses are, by repository, the blobs its artifacts use, sorted.
func (d *DB) Uses() map[string][]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string][]string{}
	for name, r := range d.repos {
		for dg := range usedBy(r) {
			out[name] = append(out[name], dg)
		}
		sort.Strings(out[name])
	}
	return out
}

// ---------------------------------------------------------------- jobs

// PutJob records a job, or what became of it.
func (d *DB) PutJob(j Job) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.commit(entry{Op: "job", Job: &j})
}

// Jobs are the jobs remembered, the newest first, at most n (0 for all).
func (d *DB) Jobs(n int) []Job {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Job, 0, len(d.jobs))
	for i := len(d.jobs) - 1; i >= 0 && (n == 0 || len(out) < n); i-- {
		out = append(out, d.jobs[i])
	}
	return out
}

// Job is one job.
func (d *DB) Job(id string) (Job, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, j := range d.jobs {
		if j.ID == id {
			return j, true
		}
	}
	return Job{}, false
}

// Schedules are the jobs' schedules, by kind.
func (d *DB) Schedules() []Schedule {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Schedule, 0, len(d.schedules))
	for _, sc := range d.schedules {
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// SetSchedule sets a kind of job's schedule. A user's change is logged; the
// registry's own defaults are not.
func (d *DB) SetSchedule(sc Schedule, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries := []entry{{Op: "schedule", Schedule: &sc}}
	if user != "" {
		state := "off"
		if sc.Enabled {
			state = "on"
		}
		entries = append(entries, d.event(user, "schedule", "", "", "", "", sc.Kind+": "+sc.Cron+" ("+state+")"))
	}
	return d.commit(entries...)
}

// SetRunning keeps what a cluster said it runs, when it changed.
func (d *DB) SetRunning(cluster string, ri RunningImages) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	sort.Strings(ri.Digests)
	sort.Strings(ri.Refs)
	if cur, ok := d.running[cluster]; ok && strings.Join(cur.Digests, ",") == strings.Join(ri.Digests, ",") &&
		strings.Join(cur.Refs, ",") == strings.Join(ri.Refs, ",") {
		return nil
	}
	ri.At = ri.At.UTC()
	return d.commit(entry{Op: "running", Name: cluster, Running: &ri})
}

// Running are what each cluster last said it runs.
func (d *DB) Running() map[string]RunningImages {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[string]RunningImages, len(d.running))
	for name, ri := range d.running {
		out[name] = ri
	}
	return out
}

// ---------------------------------------------------------------- sources

// Sources are the registries to copy from, by name.
func (d *DB) Sources() []Source {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Source, 0, len(d.sources))
	for _, src := range d.sources {
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Source is one source.
func (d *DB) Source(id string) (Source, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	src, ok := d.sources[id]
	return src, ok
}

// PutSource adds a source or changes one; names are not shared.
func (d *DB) PutSource(src Source, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, other := range d.sources {
		if id != src.ID && strings.EqualFold(other.Name, src.Name) {
			return fmt.Errorf("%w: a source named %s", ErrExists, other.Name)
		}
	}
	action := "source-add"
	if _, ok := d.sources[src.ID]; ok {
		action = "source-change"
	}
	return d.commit(entry{Op: "source", Source: &src}, d.event(user, action, "", "", "", "", src.Name+" ("+src.URL+")"))
}

// DeleteSource removes a source.
func (d *DB) DeleteSource(id, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	src, ok := d.sources[id]
	if !ok {
		return ErrNotFound
	}
	for _, r := range d.rules {
		if r.Source == id {
			return fmt.Errorf("%w: the replication rule %s copies from it", ErrInUse, r.Name)
		}
	}
	return d.commit(entry{Op: "source-del", Name: id}, d.event(user, "source-delete", "", "", "", "", src.Name))
}

// Rules are the replication rules, by name.
func (d *DB) Rules() []ReplicationRule {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]ReplicationRule, 0, len(d.rules))
	for _, r := range d.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Rule is one rule.
func (d *DB) Rule(id string) (ReplicationRule, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.rules[id]
	return r, ok
}

// PutRule adds a rule or changes one; names are not shared.
func (d *DB) PutRule(r ReplicationRule, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, other := range d.rules {
		if id != r.ID && strings.EqualFold(other.Name, r.Name) {
			return fmt.Errorf("%w: a rule named %s", ErrExists, other.Name)
		}
	}
	if _, ok := d.sources[r.Source]; !ok {
		return fmt.Errorf("%w: no such source", ErrNotFound)
	}
	action := "rule-add"
	if _, ok := d.rules[r.ID]; ok {
		action = "rule-change"
	}
	return d.commit(entry{Op: "rule", Rule: &r}, d.event(user, action, r.Project, "", "", "", r.Name+": "+r.Repositories+" → "+r.Project))
}

// DeleteRule removes a rule.
func (d *DB) DeleteRule(id, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.rules[id]
	if !ok {
		return ErrNotFound
	}
	return d.commit(entry{Op: "rule-del", Name: id}, d.event(user, "rule-delete", r.Project, "", "", "", r.Name))
}

// MarkRuleRun notes that a rule's schedule started it.
func (d *DB) MarkRuleRun(id string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.rules[id]
	if !ok {
		return ErrNotFound
	}
	at = at.UTC()
	r.Last = &at
	return d.commit(entry{Op: "rule", Rule: &r})
}

// MarkScheduled notes that a schedule started its job.
func (d *DB) MarkScheduled(kind string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	sc, ok := d.schedules[kind]
	if !ok {
		return ErrNotFound
	}
	at = at.UTC()
	sc.Last = &at
	return d.commit(entry{Op: "schedule", Schedule: &sc})
}

// Blob is a blob's size, when the repository may read it.
func (d *DB) Blob(repo, digest string) (int64, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r := d.repos[repo]
	if r == nil {
		return 0, false
	}
	n, ok := r.Blobs[digest]
	return n, ok
}

// RepoInfo is a repository with what it holds.
type RepoInfo struct {
	Name      string    `json:"name"`
	Created   time.Time `json:"created"`
	Artifacts int       `json:"artifacts"`
	Tags      int       `json:"tags"`
	Size      int64     `json:"size"`
	Updated   time.Time `json:"updated"`
	Pulls     int64     `json:"pulls"`
}

// Repositories are a project's repositories, by name.
func (d *DB) Repositories(project string) []RepoInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []RepoInfo
	for _, r := range d.repos {
		if ProjectOf(r.Name) != project {
			continue
		}
		info := RepoInfo{Name: r.Name, Created: r.Created, Artifacts: len(r.Artifacts), Tags: len(r.Tags), Updated: r.Created}
		used := usedBy(r)
		for dg, n := range r.Blobs {
			if d.counts(r, used, dg) {
				info.Size += n
			}
		}
		for _, a := range r.Artifacts {
			if _, linked := r.Blobs[a.Digest]; !linked {
				info.Size += a.Size
			}
			info.Pulls += a.Pulls
			if a.Pushed.After(info.Updated) {
				info.Updated = a.Pushed
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Catalog lists the repositories of the projects keep lets through, by
// name, after last, at most n (0 for all).
func (d *DB) Catalog(keep func(project string) bool, last string, n int) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []string
	for name := range d.repos {
		if name > last && keep(ProjectOf(name)) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// DeleteRepository removes a repository with its artifacts and tags.
func (d *DB) DeleteRepository(repo, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil {
		return ErrNotFound
	}
	for t := range r.Tags {
		if d.immutable(repo, t) {
			return immutableError{repo, t}
		}
	}
	return d.commit(entry{Op: "repo-del", Name: repo}, d.event(user, "repository-delete", ProjectOf(repo), repo, "", "", ""))
}

// ---------------------------------------------------------------- artifacts

// PutArtifact stores a pushed manifest, and points a tag at it when given.
func (d *DB) PutArtifact(repo string, a Artifact, tag, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries, err := d.ensure(repo)
	if err != nil {
		return err
	}
	if r := d.repos[repo]; r != nil && tag != "" {
		if dg, ok := r.Tags[tag]; ok && dg != a.Digest && d.immutable(repo, tag) {
			return immutableError{repo, tag}
		}
	}
	if r := d.repos[repo]; r != nil {
		if cur := r.Artifacts[a.Digest]; cur != nil {
			// The same manifest pushed again keeps its history.
			a.Pushed, a.PushedBy, a.Pulls, a.LastPull = cur.Pushed, cur.PushedBy, cur.Pulls, cur.LastPull
		}
	}
	if a.Pushed.IsZero() {
		a.Pushed, a.PushedBy = d.now().UTC(), user
	}
	entries = append(entries, entry{Op: "artifact", Repo: repo, Artifact: &a})
	if tag != "" {
		entries = append(entries, entry{Op: "tag", Repo: repo, Tag: tag, Digest: a.Digest})
	}
	entries = append(entries, d.event(user, "push", ProjectOf(repo), repo, a.Digest, tag, a.Kind))
	return d.commit(entries...)
}

// Resolve is the digest a tag or a digest stands for in a repository.
func (d *DB) Resolve(repo, ref string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r := d.repos[repo]
	if r == nil {
		return "", false
	}
	if strings.HasPrefix(ref, "sha256:") {
		_, ok := r.Artifacts[ref]
		return ref, ok
	}
	dg, ok := r.Tags[ref]
	return dg, ok
}

// Artifact is one artifact.
func (d *DB) Artifact(repo, digest string) (Artifact, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r := d.repos[repo]
	if r == nil {
		return Artifact{}, false
	}
	a, ok := r.Artifacts[digest]
	if !ok {
		return Artifact{}, false
	}
	return *a, true
}

// ArtifactInfo is an artifact with its tags.
type ArtifactInfo struct {
	Artifact
	Tags []string `json:"tags"`
}

// Artifacts are a repository's artifacts, the newest first.
func (d *DB) Artifacts(repo string) ([]ArtifactInfo, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r := d.repos[repo]
	if r == nil {
		return nil, false
	}
	tags := map[string][]string{}
	for t, dg := range r.Tags {
		tags[dg] = append(tags[dg], t)
	}
	out := make([]ArtifactInfo, 0, len(r.Artifacts))
	for _, a := range r.Artifacts {
		ts := tags[a.Digest]
		sort.Strings(ts)
		if ts == nil {
			ts = []string{}
		}
		out = append(out, ArtifactInfo{Artifact: *a, Tags: ts})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Pushed.Equal(out[j].Pushed) {
			return out[i].Pushed.After(out[j].Pushed)
		}
		return out[i].Digest < out[j].Digest
	})
	return out, true
}

// DeleteArtifact removes an artifact, the tags that point at it, and what
// means nothing without it: what is about it (its signatures and SBOMs, and
// theirs), and, of an index, its images that nothing else keeps (a tag of
// their own, another index that lists them), as Harbor deletes them. An
// image that an index of the repository lists stays (ErrInUse).
func (d *DB) DeleteArtifact(repo, digest, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil || r.Artifacts[digest] == nil {
		return ErrNotFound
	}
	listedBy := map[string][]string{} // an index's image: the indexes
	for _, a := range r.Artifacts {
		for _, m := range a.Manifests {
			listedBy[m.Digest] = append(listedBy[m.Digest], a.Digest)
		}
	}
	if indexes := listedBy[digest]; len(indexes) > 0 {
		sort.Strings(indexes)
		return fmt.Errorf("%w: an index of the repository lists it, %s", ErrInUse, indexes[0])
	}
	if t := d.immutableTag(r, digest); t != "" {
		return immutableError{repo, t}
	}
	tagged := map[string]bool{}
	for _, dg := range r.Tags {
		tagged[dg] = true
	}
	entries := []entry{{Op: "artifact-del", Repo: repo, Digest: digest}, d.event(user, "delete", ProjectOf(repo), repo, digest, "", "")}
	gone := []string{digest}
	seen := map[string]bool{digest: true}
	// keptElsewhere tells whether an index not going lists an image.
	keptElsewhere := func(dg string) bool {
		for _, by := range listedBy[dg] {
			if !seen[by] {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(gone); i++ {
		type follower struct{ digest, why string }
		var more []follower
		for _, a := range r.Artifacts {
			if a.Subject == gone[i] && !seen[a.Digest] && len(listedBy[a.Digest]) == 0 && d.immutableTag(r, a.Digest) == "" {
				more = append(more, follower{a.Digest, "about " + gone[i]})
			}
		}
		// The index going is seen already, so it keeps none of its images.
		if idx := r.Artifacts[gone[i]]; idx != nil {
			for _, m := range idx.Manifests {
				c := m.Digest
				if r.Artifacts[c] != nil && !seen[c] && !tagged[c] && d.immutableTag(r, c) == "" && !keptElsewhere(c) {
					more = append(more, follower{c, "of the index " + gone[i]})
				}
			}
		}
		sort.Slice(more, func(a, b int) bool { return more[a].digest < more[b].digest })
		for _, f := range more {
			if seen[f.digest] {
				continue
			}
			seen[f.digest] = true
			gone = append(gone, f.digest)
			entries = append(entries, entry{Op: "artifact-del", Repo: repo, Digest: f.digest},
				d.event(user, "delete", ProjectOf(repo), repo, f.digest, "", f.why))
		}
	}
	return d.commit(entries...)
}

// Tag points a tag at an artifact of the repository.
func (d *DB) Tag(repo, tag, digest, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil || r.Artifacts[digest] == nil {
		return ErrNotFound
	}
	if r.Tags[tag] == digest {
		return nil
	}
	if _, ok := r.Tags[tag]; ok && d.immutable(repo, tag) {
		return immutableError{repo, tag}
	}
	return d.commit(entry{Op: "tag", Repo: repo, Tag: tag, Digest: digest}, d.event(user, "tag", ProjectOf(repo), repo, digest, tag, ""))
}

// Untag removes a tag; its artifact stays.
func (d *DB) Untag(repo, tag, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil {
		return ErrNotFound
	}
	dg, ok := r.Tags[tag]
	if !ok {
		return ErrNotFound
	}
	if d.immutable(repo, tag) {
		return immutableError{repo, tag}
	}
	return d.commit(entry{Op: "untag", Repo: repo, Tag: tag}, d.event(user, "untag", ProjectOf(repo), repo, dg, tag, ""))
}

// Tags are a repository's tags, sorted, after last, at most n (0 for all).
func (d *DB) Tags(repo, last string, n int) ([]string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r := d.repos[repo]
	if r == nil {
		return nil, false
	}
	out := []string{}
	for t := range r.Tags {
		if t > last {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out, true
}

// Referrers are the artifacts of a repository whose subject is digest,
// such as its signatures and SBOMs, of artifactType when it is given.
func (d *DB) Referrers(repo, digest, artifactType string) []Artifact {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r := d.repos[repo]
	if r == nil {
		return nil
	}
	var out []Artifact
	for _, a := range r.Artifacts {
		if a.Subject != digest {
			continue
		}
		at := a.ArtifactType
		if at == "" && a.Config != nil {
			at = a.Config.MediaType
		}
		if artifactType == "" || at == artifactType {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out
}

// ---------------------------------------------------------------- blob stores

// BlobStores are the blob stores besides the default one, by name.
func (d *DB) BlobStores() []BlobStore {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]BlobStore, 0, len(d.stores))
	for _, bs := range d.stores {
		out = append(out, bs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// BlobStoreNamed is one blob store.
func (d *DB) BlobStoreNamed(name string) (BlobStore, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	bs, ok := d.stores[name]
	return bs, ok
}

// PutBlobStore adds a blob store or changes one.
func (d *DB) PutBlobStore(bs BlobStore, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if bs.Name == DefaultStore {
		return fmt.Errorf("%w: the default blob store is the registry's own", ErrExists)
	}
	action := "store-add"
	if _, ok := d.stores[bs.Name]; ok {
		action = "store-change"
	}
	where := bs.Path
	if bs.Kind == "s3" {
		where = bs.Endpoint + "/" + bs.Bucket + "/" + bs.Prefix
	}
	return d.commit(entry{Op: "store", Store: &bs}, d.event(user, action, "", "", "", "", bs.Name+" ("+bs.Kind+" "+where+")"))
}

// DeleteBlobStore removes a blob store that no project uses.
func (d *DB) DeleteBlobStore(name, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.stores[name]; !ok {
		return ErrNotFound
	}
	for _, p := range d.projects {
		if p.Store == name || p.MovedFrom == name {
			return fmt.Errorf("%w: the project %s keeps its blobs there", ErrInUse, p.Name)
		}
	}
	return d.commit(entry{Op: "store-del", Name: name}, d.event(user, "store-delete", "", "", "", "", name))
}

// StoreProjects are the projects whose blobs go to a blob store, by name.
func (d *DB) StoreProjects(store string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []string
	for _, p := range d.projects {
		if p.StoreName() == store {
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out
}

// inStore tells whether a repository's blobs are in a blob store; the
// lock is held.
func (d *DB) inStore(repo, store string) bool {
	p := d.projects[ProjectOf(repo)]
	if p == nil {
		// A project gone leaves no repositories, but its own store's
		// collection is where they would be.
		return store == DefaultStore
	}
	return p.StoreName() == store || p.MovedFrom == store
}

// MoveProject points a project at another blob store, which its blobs
// were copied to; the one they come from stays MovedFrom until EndMove.
func (d *DB) MoveProject(name, to, user string) (Project, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, ok := d.projects[name]
	if !ok {
		return Project{}, ErrNoProject
	}
	if to == DefaultStore {
		to = ""
	}
	if _, ok := d.stores[to]; to != "" && !ok {
		return Project{}, fmt.Errorf("%w: no blob store %s", ErrNotFound, to)
	}
	p := *cur
	from := p.StoreName()
	if p.Store == to {
		return p, nil
	}
	p.Store, p.MovedFrom = to, from
	if p.MovedFrom == p.StoreName() {
		p.MovedFrom = ""
	}
	if err := d.commit(entry{Op: "project", Project: &p}, d.event(user, "project-move", name, "", "", "", from+" → "+p.StoreName())); err != nil {
		return Project{}, err
	}
	return p, nil
}

// EndMove ends a project's move: the store it came from has nothing of it
// any more.
func (d *DB) EndMove(name, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, ok := d.projects[name]
	if !ok {
		return ErrNoProject
	}
	if cur.MovedFrom == "" {
		return nil
	}
	p := *cur
	from := p.MovedFrom
	p.MovedFrom = ""
	return d.commit(entry{Op: "project", Project: &p}, d.event(user, "project-moved", name, "", "", "", from+" → "+p.StoreName()))
}

// ProjectBlobs are, with their sizes, the blobs a project's repositories
// link and the manifests they have: what a move copies.
func (d *DB) ProjectBlobs(project string) map[string]int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string]int64{}
	for name, r := range d.repos {
		if ProjectOf(name) != project {
			continue
		}
		for dg, n := range r.Blobs {
			out[dg] = n
		}
		for dg, a := range r.Artifacts {
			out[dg] = a.Size
		}
	}
	return out
}

// InUseIn is InUse of the repositories whose blobs are in a blob store.
func (d *DB) InUseIn(digest, store string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for name, r := range d.repos {
		if !d.inStore(name, store) {
			continue
		}
		if _, ok := r.Blobs[digest]; ok {
			return true
		}
		if r.Artifacts[digest] != nil {
			return true
		}
	}
	return false
}

// BlobsInUseIn is BlobsInUse of the repositories whose blobs are in a
// blob store.
func (d *DB) BlobsInUseIn(except map[string][]string, store string) map[string]bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string]bool{}
	for name, r := range d.repos {
		if !d.inStore(name, store) {
			continue
		}
		skip := map[string]bool{}
		for _, dg := range except[name] {
			skip[dg] = true
		}
		for dg := range r.Blobs {
			if !skip[dg] {
				out[dg] = true
			}
		}
		for dg := range usedBy(r) {
			out[dg] = true
		}
	}
	return out
}

// StoreUsage is what a blob store holds by the metadata, as a project's
// usage counts it, each blob once, and how many blobs: "" for every store.
func (d *DB) StoreUsage(store string) (int64, int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	blobs := map[string]int64{}
	for name, r := range d.repos {
		if store != "" && !d.inStore(name, store) {
			continue
		}
		used := usedBy(r)
		for dg, n := range r.Blobs {
			if d.counts(r, used, dg) {
				blobs[dg] = n
			}
		}
		for dg, a := range r.Artifacts {
			blobs[dg] = a.Size
		}
	}
	var n int64
	for _, size := range blobs {
		n += size
	}
	return n, len(blobs)
}

// ---------------------------------------------------------------- scans

// PutScan records an image's scan, or what became of it.
func (d *DB) PutScan(sc Scan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.commit(entry{Op: "scan", Scan: &sc})
}

// Scan is what is known of an image's vulnerabilities.
func (d *DB) Scan(digest string) (Scan, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	sc, ok := d.scans[digest]
	return sc, ok
}

// Scans are every image's scan, by digest.
func (d *DB) Scans() []Scan {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Scan, 0, len(d.scans))
	for _, sc := range d.scans {
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out
}

// DeleteScan forgets an image's scan.
func (d *DB) DeleteScan(digest string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.scans[digest]; !ok {
		return nil
	}
	return d.commit(entry{Op: "scan-del", Name: digest})
}

// Holders are the repositories that have an artifact, by name.
func (d *DB) Holders(digest string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []string
	for name, r := range d.repos {
		if r.Artifacts[digest] != nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Images are the artifacts of a kind (such as image) the registry holds,
// each once: by digest, the first repository by name that has it.
func (d *DB) Images(kind string) map[string]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string]string{}
	for name, r := range d.repos {
		for dg, a := range r.Artifacts {
			if a.Kind != kind {
				continue
			}
			if cur, ok := out[dg]; !ok || name < cur {
				out[dg] = name
			}
		}
	}
	return out
}

// RecordPull counts a pull of an artifact; counts are written by Flush.
func (d *DB) RecordPull(repo, digest string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil {
		return
	}
	a := r.Artifacts[digest]
	if a == nil {
		return
	}
	t := d.now().UTC()
	a.Pulls++
	a.LastPull = &t
	d.pulled[[2]string{repo, digest}] = true
}

// Flush writes the pull counts that changed.
func (d *DB) Flush() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushPulls()
}

func (d *DB) flushPulls() error {
	if len(d.pulled) == 0 {
		return nil
	}
	var entries []entry
	for k := range d.pulled {
		r := d.repos[k[0]]
		if r == nil || r.Artifacts[k[1]] == nil {
			continue
		}
		a := r.Artifacts[k[1]]
		entries = append(entries, entry{Op: "pulls", Repo: k[0], Digest: k[1], Pulls: a.Pulls, At: a.LastPull})
	}
	d.pulled = map[[2]string]bool{}
	if len(entries) == 0 {
		return nil
	}
	return d.commit(entries...)
}

// Events are the latest events, newest first, at most n (0 for all), of
// the projects keep lets through.
func (d *DB) Events(keep func(project string) bool, n int) []Event {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := []Event{}
	for i := len(d.events) - 1; i >= 0; i-- {
		e := d.events[i]
		if keep != nil && !keep(e.Project) {
			continue
		}
		out = append(out, e)
		if n > 0 && len(out) == n {
			break
		}
	}
	return out
}

// Record adds an event that is not a change of the metadata, such as a
// failed push.
func (d *DB) Record(user, action, project, repo, digest, tag, detail string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.commit(d.event(user, action, project, repo, digest, tag, detail))
}
