package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/cron"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/remote"
)

// Replication copies images from a source into a project, as a rule says:
// it lists what the source has, leaves what is here already, and copies
// the rest from the bottom up (an index's images, then their configs and
// layers, the manifests, and the tags last), checking every digest. A
// blob the registry has is linked, not pulled again. Run again, it goes on
// where it stopped.

// JobReplication is a run of a replication rule.
const JobReplication = "replication"

// ReplicationReport is what a run did, or in a dry run would do.
type ReplicationReport struct {
	DryRun  bool      `json:"dryRun"`
	Rule    string    `json:"rule"`
	Source  string    `json:"source"`
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	// Picked are the tags the rule picks at the source. Of those, Copied
	// were copied (or would be), Present were here already, Kept are here
	// pointing at another image and stayed, Failed could not be copied.
	Picked  int   `json:"picked"`
	Copied  int   `json:"copied"`
	Present int   `json:"present"`
	Kept    int   `json:"kept"`
	Failed  int   `json:"failed"`
	Bytes   int64 `json:"bytes"`
	// Items say what was copied, kept or failed: the first 200.
	Items []ReplicationItem `json:"items"`
}

// ReplicationItem is one tag a run copied, kept or could not copy.
type ReplicationItem struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Digest string `json:"digest,omitempty"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// The results of an item.
const (
	itemCopied  = "copied"
	itemWould   = "would copy"
	itemKept    = "kept"
	itemFailed  = "failed"
	itemPresent = "present"
)

func (r ReplicationReport) String() string {
	verb := "copied"
	if r.DryRun {
		verb = "would copy"
	}
	return fmt.Sprintf("%d tags picked: %s %d (%s), %d here already, %d kept, %d failed", r.Picked, verb, r.Copied,
		meta.HumanBytes(r.Bytes), r.Present, r.Kept, r.Failed)
}

// ---------------------------------------------------------------- rules

// repoMatch matches a repository's whole name: ** is every one, a/** every
// one below a, and * any run of characters within a part.
func repoMatch(pattern, name string) bool {
	switch {
	case pattern == "" || pattern == "**":
		return true
	case strings.HasSuffix(pattern, "/**"):
		prefix := strings.TrimSuffix(pattern, "/**")
		n := strings.Count(prefix, "/") + 1
		parts := strings.Split(name, "/")
		if len(parts) <= n {
			return false
		}
		ok, _ := path.Match(prefix, strings.Join(parts[:n], "/"))
		return ok
	}
	ok, _ := path.Match(pattern, name)
	return ok
}

func tagMatch(pattern, tag string) bool {
	if pattern == "" || pattern == "**" {
		return true
	}
	ok, _ := path.Match(pattern, tag)
	return ok
}

// targetRepo is where a rule puts a repository of the source.
func targetRepo(r meta.ReplicationRule, from string) string {
	rest := from
	if parts := strings.Split(from, "/"); !r.KeepPath && len(parts) > 1 {
		rest = strings.Join(parts[1:], "/")
	}
	return r.Project + "/" + rest
}

var platformRE = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)

// platformOK tells whether a rule keeps an image of a platform; one that
// names none (an attestation's unknown/unknown) goes with any.
func platformOK(r meta.ReplicationRule, p *manifest.Platform) bool {
	if len(r.Platforms) == 0 || p == nil {
		return true
	}
	short := p.OS + "/" + p.Architecture
	return slices.Contains(r.Platforms, short) || (p.Variant != "" && slices.Contains(r.Platforms, short+"/"+p.Variant))
}

// ErrRule is a rule that cannot be as asked.
var ErrRule = errors.New("not a replication rule")

// checkRule checks a rule an admin set.
func (s *Server) checkRule(r meta.ReplicationRule) error {
	bad := func(format string, a ...any) error { return fmt.Errorf("%w: %s", ErrRule, fmt.Sprintf(format, a...)) }
	if !sourceName.MatchString(r.Name) {
		return bad("a name is letters, digits, spaces and . _ -, at most 64")
	}
	if _, ok := s.cfg.DB.Source(r.Source); !ok {
		return bad("no such source")
	}
	repos := strings.TrimSuffix(r.Repositories, "/**")
	if r.Repositories == "" || len(r.Repositories) > 255 {
		return bad("name the repositories to copy, such as team-a/web, team-a/** or **")
	}
	if repos != "**" {
		if _, err := path.Match(repos, ""); err != nil {
			return bad("%q is not a pattern of repositories", r.Repositories)
		}
	}
	if r.Tags != "" && r.Tags != "**" && !meta.ValidTagPattern(r.Tags) {
		return bad("%q is not a pattern of tags", r.Tags)
	}
	if !ValidProject(r.Project) {
		return bad("%q is not a project", r.Project)
	}
	if _, ok := s.cfg.DB.Project(r.Project); !ok {
		return bad("project %s does not exist; make it first", r.Project)
	}
	for _, p := range r.Platforms {
		if !platformRE.MatchString(p) {
			return bad("%q is not a platform, such as linux/amd64 or linux/arm64/v8", p)
		}
	}
	switch {
	case r.Within < 0 || r.Within > 36500:
		return bad("the days are between 0 and 36500")
	case r.Concurrency < 0 || r.Concurrency > 8:
		return bad("it copies between 1 and 8 images at once")
	case r.BandwidthKiB < 0 || r.BandwidthKiB > 10<<20:
		return bad("the bandwidth is at most %d KiB a second", 10<<20)
	}
	if r.Cron != "" {
		if _, err := cron.Parse(r.Cron); err != nil {
			return bad("%s", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------- copying

// limiter keeps the bytes pulled a second under a rate.
type limiter struct {
	mu   sync.Mutex
	rate float64 // bytes a second
	next time.Time
}

func (l *limiter) wait(ctx context.Context, n int) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	d := l.next.Sub(now)
	l.next = l.next.Add(time.Duration(float64(n) / l.rate * float64(time.Second)))
	l.mu.Unlock()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// counted reads a blob, counting it and keeping to the limit.
type counted struct {
	ctx   context.Context
	r     io.Reader
	limit *limiter
	n     *atomic.Int64
}

func (c *counted) Read(p []byte) (int, error) {
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
		if werr := c.limit.wait(c.ctx, n); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// copier copies for one run.
type copier struct {
	s     *Server
	c     *remote.Client
	rule  meta.ReplicationRule
	user  string
	limit *limiter
	bytes atomic.Int64

	mu    sync.Mutex
	doing map[string]chan struct{} // the blobs being pulled
}

// hold lets one worker pull a blob at a time; the others wait for it.
func (cp *copier) hold(digest string) func() {
	for {
		cp.mu.Lock()
		ch, busy := cp.doing[digest]
		if !busy {
			ch = make(chan struct{})
			cp.doing[digest] = ch
			cp.mu.Unlock()
			return func() {
				cp.mu.Lock()
				delete(cp.doing, digest)
				cp.mu.Unlock()
				close(ch)
			}
		}
		cp.mu.Unlock()
		<-ch
	}
}

// blob makes a blob the repository's: linked when the registry has it,
// pulled when not, its digest checked as the store takes it.
func (cp *copier) blob(ctx context.Context, from, to string, d manifest.Descriptor) error {
	s := cp.s
	if _, ok := s.cfg.DB.Blob(to, d.Digest); ok {
		return nil
	}
	defer cp.hold(d.Digest)()
	// A blob some repository has is linked. One the store has and no
	// repository does is garbage, which a collection may be deleting right
	// now: it is pulled again, which makes it new in the store.
	st, storeName, err := s.storeOf(to)
	if err != nil {
		return err
	}
	link := func(size int64) error {
		if err := s.cfg.DB.LinkBlob(to, d.Digest, size); err != nil {
			if errors.Is(err, meta.ErrQuota) {
				return err
			}
			return fmt.Errorf("recording %s: %w", d.Digest, err)
		}
		// The project moved to another store meanwhile.
		if err := s.settle(to, storeName, d.Digest); err != nil {
			return fmt.Errorf("copying %s into the project's new store: %w", d.Digest, err)
		}
		return nil
	}
	if size, err := st.Stat(d.Digest); err == nil && s.cfg.DB.InUseIn(d.Digest, storeName) {
		return link(size)
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		rc, _, err := cp.c.Blob(ctx, from, d.Digest)
		if err != nil {
			lastErr = err
			if errors.Is(err, remote.ErrNotFound) || ctx.Err() != nil {
				break
			}
			continue
		}
		id, err := st.StartUpload()
		if err != nil {
			rc.Close()
			return err
		}
		_, err = st.Append(id, 0, &counted{ctx: ctx, r: rc, limit: cp.limit, n: &cp.bytes})
		rc.Close()
		if err != nil {
			st.Cancel(id)
			lastErr = fmt.Errorf("pulling %s: %w", d.Digest, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		size, err := st.Finish(id, d.Digest)
		if err != nil {
			st.Cancel(id)
			if errors.Is(err, blobstore.ErrDigestMismatch) {
				return fmt.Errorf("the source's %s is not that digest", d.Digest)
			}
			return err
		}
		return link(size)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return lastErr
}

// narrow is a manifest as the rule keeps it here: an index of only the
// platforms it keeps is a new one, of another digest. It answers the
// manifest, its digest, and whether it is a new one.
func (cp *copier) narrow(body []byte, mt, digest string) ([]byte, string, bool, error) {
	m, err := manifest.Parse(mt, body)
	if err != nil {
		return nil, "", false, err
	}
	if !m.Index() {
		return body, digest, false, nil
	}
	var keep []manifest.Descriptor
	for _, child := range m.Manifests {
		if platformOK(cp.rule, child.Platform) {
			keep = append(keep, child)
		}
	}
	if len(keep) == 0 {
		return nil, "", false, errors.New("it has no image of the platforms the rule keeps")
	}
	if len(keep) == len(m.Manifests) {
		return body, digest, false, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", false, err
	}
	list, err := json.Marshal(keep)
	if err != nil {
		return nil, "", false, err
	}
	raw["manifests"] = list
	if body, err = json.Marshal(raw); err != nil {
		return nil, "", false, err
	}
	return body, blobstore.Digest(body), true, nil
}

// manifest copies a manifest and all it refers to; it answers the digest
// it has here, which differs from the source's when some platforms of an
// index were left out, and whether that is so.
func (cp *copier) manifest(ctx context.Context, from, to string, body []byte, mt, digest string) (string, bool, error) {
	s := cp.s
	body, digest, rewritten, err := cp.narrow(body, mt, digest)
	if err != nil {
		return "", false, err
	}
	if _, ok := s.cfg.DB.Artifact(to, digest); ok {
		return digest, rewritten, nil
	}
	m, err := manifest.Parse(mt, body)
	if err != nil {
		return "", false, err
	}
	if m.Index() {
		for _, child := range m.Manifests {
			if _, ok := s.cfg.DB.Artifact(to, child.Digest); ok {
				continue
			}
			cb, cmt, cd, err := cp.c.Manifest(ctx, from, child.Digest)
			if err != nil {
				return "", false, err
			}
			if cmt == "" {
				cmt = child.MediaType
			}
			if _, _, err := cp.manifest(ctx, from, to, cb, cmt, cd); err != nil {
				return "", false, err
			}
		}
	} else {
		for _, d := range m.References() {
			if err := cp.blob(ctx, from, to, d); err != nil {
				return "", false, err
			}
		}
	}
	if _, _, e := s.storeManifest(to, digest, mt, body, cp.user); e != nil {
		return "", false, errors.New(e.message)
	}
	return digest, rewritten, nil
}

// referrers copies the signatures and SBOMs about an artifact.
func (cp *copier) referrers(ctx context.Context, from, to, digest string) error {
	refs, err := cp.c.Referrers(ctx, from, digest)
	if err != nil {
		return err
	}
	for _, rf := range refs {
		if _, ok := cp.s.cfg.DB.Artifact(to, rf.Digest); ok {
			continue
		}
		b, mt, d, err := cp.c.Manifest(ctx, from, rf.Digest)
		if err != nil {
			return err
		}
		if mt == "" {
			mt = rf.MediaType
		}
		if _, _, err := cp.manifest(ctx, from, to, b, mt, d); err != nil {
			return err
		}
	}
	return nil
}

// one copies a tag.
func (cp *copier) one(ctx context.Context, img remote.Image, to string, dryRun bool) ReplicationItem {
	s := cp.s
	item := ReplicationItem{From: img.Repo + ":" + img.Tag, To: to + ":" + img.Tag, Digest: img.Digest}
	fail := func(err error) ReplicationItem {
		item.Result, item.Error = itemFailed, err.Error()
		return item
	}
	if !ValidName(to) {
		return fail(fmt.Errorf("%s is not a repository's name here", to))
	}
	here, tagged := s.cfg.DB.Resolve(to, img.Tag)
	if img.Digest != "" && tagged && here == img.Digest {
		item.Result = itemPresent
		return item
	}
	body, mt, digest, err := cp.c.Manifest(ctx, img.Repo, img.Tag)
	if err != nil {
		return fail(err)
	}
	// What it is here, its platforms narrowed as the rule says.
	_, want, _, err := cp.narrow(body, mt, digest)
	if err != nil {
		return fail(err)
	}
	item.Digest = want
	if tagged && here == want {
		item.Result = itemPresent
		return item
	}
	if tagged && !cp.rule.Overwrite {
		item.Result, item.Error = itemKept, "the tag here is another image's, and the rule does not overwrite"
		return item
	}
	if dryRun {
		item.Result = itemWould
		return item
	}
	final, rewritten, err := cp.manifest(ctx, img.Repo, to, body, mt, digest)
	if err != nil {
		return fail(err)
	}
	item.Digest = final
	if cp.rule.Referrers && !rewritten {
		if err := cp.referrers(ctx, img.Repo, to, digest); err != nil {
			item.Error = "its signatures and SBOMs: " + err.Error()
		}
	}
	if err := s.cfg.DB.Tag(to, img.Tag, final, cp.user); err != nil {
		if errors.Is(err, meta.ErrImmutable) {
			item.Result, item.Error = itemKept, err.Error()
			return item
		}
		return fail(err)
	}
	item.Result = itemCopied
	return item
}

// Replicate runs a rule.
func (s *Server) Replicate(ctx context.Context, ruleID string, dryRun bool, user string, progress func(meta.JobProgress)) (ReplicationReport, error) {
	start := time.Now()
	rep := ReplicationReport{DryRun: dryRun, Started: s.now().UTC(), Items: []ReplicationItem{}}
	r, ok := s.cfg.DB.Rule(ruleID)
	if !ok {
		return rep, errors.New("no such replication rule")
	}
	rep.Rule = r.Name
	src, ok := s.cfg.DB.Source(r.Source)
	if !ok {
		return rep, errors.New("the rule's source is gone")
	}
	rep.Source = src.Name
	if _, ok := s.cfg.DB.Project(r.Project); !ok {
		return rep, fmt.Errorf("project %s does not exist", r.Project)
	}
	rs, c, err := s.remoteSource(src)
	if err != nil {
		return rep, err
	}
	imgs, err := remote.Images(ctx, rs, c, r.Repositories, func(repo string) bool { return repoMatch(r.Repositories, repo) })
	if err != nil {
		return rep, fmt.Errorf("listing %s: %w", src.Name, err)
	}
	since := s.now().AddDate(0, 0, -r.Within)
	var picked []remote.Image
	for _, img := range imgs {
		if !tagMatch(r.Tags, img.Tag) || (r.Within > 0 && !img.Pushed.IsZero() && img.Pushed.Before(since)) {
			continue
		}
		picked = append(picked, img)
	}
	rep.Picked = len(picked)
	cp := &copier{s: s, c: c, rule: r, user: user, doing: map[string]chan struct{}{}}
	if r.BandwidthKiB > 0 {
		cp.limit = &limiter{rate: float64(r.BandwidthKiB) * 1024}
	}
	workers := r.Concurrency
	if workers <= 0 {
		workers = 2
	}
	work := make(chan remote.Image)
	var mu sync.Mutex
	done := 0
	// How far it got, at once and every second, as big layers take long.
	report := func() {
		if progress != nil {
			progress(meta.JobProgress{Done: done, Total: len(picked), Bytes: cp.bytes.Load()})
		}
	}
	report()
	stopTicking := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopTicking:
				return
			case <-t.C:
				mu.Lock()
				report()
				mu.Unlock()
			}
		}
	}()
	defer close(stopTicking)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for img := range work {
				item := cp.one(ctx, img, targetRepo(r, img.Repo), dryRun)
				mu.Lock()
				switch item.Result {
				case itemCopied, itemWould:
					rep.Copied++
				case itemPresent:
					rep.Present++
				case itemKept:
					rep.Kept++
				default:
					rep.Failed++
				}
				if item.Result != itemPresent && len(rep.Items) < 200 {
					rep.Items = append(rep.Items, item)
				}
				done++
				report()
				mu.Unlock()
			}
		}()
	}
feed:
	for _, img := range picked {
		select {
		case work <- img:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	sort.Slice(rep.Items, func(i, j int) bool { return rep.Items[i].From < rep.Items[j].From })
	rep.Bytes = cp.bytes.Load()
	rep.Seconds = time.Since(start).Seconds()
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	// A run that changed nothing, as most hourly ones, is not worth a line
	// of the log.
	if !dryRun && rep.Copied+rep.Kept+rep.Failed > 0 {
		if err := s.cfg.DB.Record(user, "replicate", r.Project, "", "", "", r.Name+": "+rep.String()); err != nil {
			s.cfg.Log.Warn("registry: recording a replication", "err", err)
		}
	}
	return rep, nil
}
