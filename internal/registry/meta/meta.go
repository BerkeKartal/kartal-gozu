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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
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
)

// Project groups repositories: the first part of a repository's name.
type Project struct {
	Name        string    `json:"name"`
	Public      bool      `json:"public"`
	Description string    `json:"description,omitempty"`
	Created     time.Time `json:"created"`
	CreatedBy   string    `json:"createdBy,omitempty"`
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
}

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

// keepEvents is how many events are kept.
const keepEvents = 2000

// snapshotEvery is how many log lines lead to a snapshot.
const snapshotEvery = 1000

// entry is one line of the log.
type entry struct {
	Op       string     `json:"op"`
	Project  *Project   `json:"project,omitempty"`
	Name     string     `json:"name,omitempty"`
	Repo     string     `json:"repo,omitempty"`
	Digest   string     `json:"digest,omitempty"`
	Size     int64      `json:"size,omitempty"`
	Tag      string     `json:"tag,omitempty"`
	Artifact *Artifact  `json:"artifact,omitempty"`
	Pulls    int64      `json:"pulls,omitempty"`
	At       *time.Time `json:"at,omitempty"`
	Event    *Event     `json:"event,omitempty"`
}

type state struct {
	Projects []*Project    `json:"projects"`
	Repos    []*Repository `json:"repositories"`
	Events   []Event       `json:"events"`
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
	snapErr  error
	projects map[string]*Project
	repos    map[string]*Repository
	events   []Event
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
	d := &DB{dir: dir, now: time.Now, projects: map[string]*Project{}, repos: map[string]*Repository{}, pulled: map[[2]string]bool{}}
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
		}
	case "unlink":
		if r := d.repos[e.Repo]; r != nil {
			delete(r.Blobs, e.Digest)
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
	s := state{Events: d.events}
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
		info := ProjectInfo{Project: *p}
		blobs := map[string]int64{}
		for _, r := range d.repos {
			if ProjectOf(r.Name) != p.Name {
				continue
			}
			info.Repositories++
			info.Artifacts += len(r.Artifacts)
			for dg, n := range r.Blobs {
				blobs[dg] = n
			}
			for dg, a := range r.Artifacts {
				blobs[dg] = a.Size
			}
		}
		for _, n := range blobs {
			info.Size += n
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
	p.Created, p.CreatedBy = d.now().UTC(), user
	return d.commit(entry{Op: "project", Project: &p}, d.event(user, "project-create", p.Name, "", "", "", visibility(p.Public)))
}

func visibility(public bool) string {
	if public {
		return "public"
	}
	return "private"
}

// UpdateProject changes whether a project is public and its description.
func (d *DB) UpdateProject(name string, public bool, description, user string) (Project, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, ok := d.projects[name]
	if !ok {
		return Project{}, ErrNoProject
	}
	p := *cur
	p.Public, p.Description = public, description
	if err := d.commit(entry{Op: "project", Project: &p}, d.event(user, "project-update", name, "", "", "", visibility(public))); err != nil {
		return Project{}, err
	}
	return p, nil
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
// into it.
func (d *DB) LinkBlob(repo, digest string, size int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r := d.repos[repo]; r != nil {
		if n, ok := r.Blobs[digest]; ok && n == size {
			return nil
		}
	}
	entries, err := d.ensure(repo)
	if err != nil {
		return err
	}
	return d.commit(append(entries, entry{Op: "link", Repo: repo, Digest: digest, Size: size})...)
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
	return d.commit(entry{Op: "unlink", Repo: repo, Digest: digest})
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
		for _, n := range r.Blobs {
			info.Size += n
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
	if d.repos[repo] == nil {
		return ErrNotFound
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

// DeleteArtifact removes an artifact and the tags that point at it.
func (d *DB) DeleteArtifact(repo, digest, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.repos[repo]
	if r == nil || r.Artifacts[digest] == nil {
		return ErrNotFound
	}
	return d.commit(entry{Op: "artifact-del", Repo: repo, Digest: digest}, d.event(user, "delete", ProjectOf(repo), repo, digest, "", ""))
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
