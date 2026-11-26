package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// Blob stores, as Nexus has them: the registry's own (meta.DefaultStore,
// Config.Store), and others its admins add, a directory or a bucket of S3.
// Each project keeps its blobs in one; collecting garbage and checking the
// blobs go store by store, a blob counting as used in a store only by the
// repositories of the projects there.

// ErrStore is a blob store that cannot be as asked.
var ErrStore = errors.New("not a blob store")

var storeNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// storeHealth is what the last look at a store found.
type storeHealth struct {
	problem string
	at      time.Time
}

// openStore makes a store of its record.
func (s *Server) openStore(bs meta.BlobStore) (blobstore.Store, error) {
	switch bs.Kind {
	case "file":
		return blobstore.NewFile(bs.Path)
	case "s3":
		secret, err := s.unseal(bs.Secret)
		if err != nil {
			return nil, err
		}
		if s.cfg.StagingDir == "" {
			return nil, errors.New("the registry has no directory for an S3 store's uploads (Config.StagingDir)")
		}
		return blobstore.NewS3(blobstore.S3Config{Endpoint: bs.Endpoint, Region: bs.Region, Bucket: bs.Bucket, Prefix: bs.Prefix,
			AccessKey: bs.AccessKey, SecretKey: secret, PathStyle: bs.PathStyle, CA: bs.CA, Insecure: bs.Insecure,
			Staging: filepath.Join(s.cfg.StagingDir, bs.Name), HTTP: s.cfg.StoreHTTP})
	}
	return nil, fmt.Errorf("%w: the kind is file or s3", ErrStore)
}

// storeNamed is a blob store by name, opened on first use.
func (s *Server) storeNamed(name string) (blobstore.Store, error) {
	if name == "" || name == meta.DefaultStore {
		return s.cfg.Store, nil
	}
	s.storesMu.Lock()
	defer s.storesMu.Unlock()
	if st, ok := s.opened[name]; ok {
		return st, nil
	}
	bs, ok := s.cfg.DB.BlobStoreNamed(name)
	if !ok {
		return nil, fmt.Errorf("%w: there is no blob store %s", ErrStore, name)
	}
	st, err := s.openStore(bs)
	if err != nil {
		return nil, fmt.Errorf("the blob store %s cannot be opened: %w", name, err)
	}
	s.opened[name] = st
	return st, nil
}

// dropStore forgets an opened store, whose record changed.
func (s *Server) dropStore(name string) {
	s.storesMu.Lock()
	delete(s.opened, name)
	delete(s.health, name)
	s.storesMu.Unlock()
}

// storeNameOf is the blob store a repository's project keeps its blobs in.
func (s *Server) storeNameOf(repo string) string {
	p, _ := s.cfg.DB.Project(meta.ProjectOf(repo))
	return p.StoreName()
}

// storeOf is the blob store of a repository's project.
func (s *Server) storeOf(repo string) (blobstore.Store, string, error) {
	name := s.storeNameOf(repo)
	st, err := s.storeNamed(name)
	return st, name, err
}

// noStore answers a request whose blob store cannot be opened.
func (s *Server) noStore(w http.ResponseWriter, err error) {
	s.cfg.Log.Error("registry: a blob store", "err", err)
	writeError(w, errorf(http.StatusServiceUnavailable, "UNAVAILABLE", "the project's blob store is not available now"))
}

// namedStore is a store with its name, or why it cannot be opened.
type namedStore struct {
	name  string
	store blobstore.Store
	err   error
}

// allStores are the default store and the others, by name.
func (s *Server) allStores() []namedStore {
	out := []namedStore{{name: meta.DefaultStore, store: s.cfg.Store}}
	for _, bs := range s.cfg.DB.BlobStores() {
		st, err := s.storeNamed(bs.Name)
		out = append(out, namedStore{name: bs.Name, store: st, err: err})
	}
	return out
}

// pinger is a store that can tell whether it answers.
type pinger interface{ Ping() error }

// checkStores looks at every store, keeping what it finds for the views
// and the alerts.
func (s *Server) checkStores(ctx context.Context) {
	for _, ns := range s.allStores() {
		problem := ""
		switch {
		case ns.err != nil:
			problem = ns.err.Error()
		default:
			if p, ok := ns.store.(pinger); ok {
				done := make(chan error, 1)
				go func() { done <- p.Ping() }()
				select {
				case err := <-done:
					if err != nil {
						problem = err.Error()
					}
				case <-time.After(30 * time.Second):
					problem = "it did not answer in 30 seconds"
				case <-ctx.Done():
					return
				}
			}
		}
		s.storesMu.Lock()
		s.health[ns.name] = storeHealth{problem: problem, at: s.now()}
		s.storesMu.Unlock()
	}
}

// storeCheckEvery is how often the stores are looked at.
const storeCheckEvery = 5 * time.Minute

func (s *Server) watchStores(ctx context.Context) {
	t := time.NewTicker(storeCheckEvery)
	defer t.Stop()
	for {
		s.checkStores(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------- views and changes

// StoreView is a blob store as the API shows it: never its secret key.
type StoreView struct {
	meta.BlobStore
	HasSecret bool `json:"hasSecret"`
	// Size is what the projects there hold, each blob once, and Blobs how
	// many; Projects are those projects.
	Size     int64    `json:"size"`
	Blobs    int      `json:"blobs"`
	Projects []string `json:"projects"`
	// Problem is what the last look at it found wrong, at Checked.
	Problem string     `json:"problem,omitempty"`
	Checked *time.Time `json:"checked,omitempty"`
	Default bool       `json:"default,omitempty"`
}

func (s *Server) storeView(bs meta.BlobStore) StoreView {
	v := StoreView{BlobStore: bs, HasSecret: bs.Secret != ""}
	v.Secret = ""
	v.Size, v.Blobs = s.cfg.DB.StoreUsage(bs.Name)
	v.Projects = s.cfg.DB.StoreProjects(bs.Name)
	if v.Projects == nil {
		v.Projects = []string{}
	}
	s.storesMu.Lock()
	if h, ok := s.health[bs.Name]; ok {
		at := h.at.UTC()
		v.Problem, v.Checked = h.problem, &at
	}
	s.storesMu.Unlock()
	return v
}

// StoreViews are every blob store, the default one first.
func (s *Server) StoreViews() []StoreView {
	def := meta.BlobStore{Name: meta.DefaultStore, Kind: "file"}
	if f, ok := s.cfg.Store.(*blobstore.File); ok {
		def.Path = f.Root()
	}
	out := []StoreView{s.storeView(def)}
	out[0].Default = true
	for _, bs := range s.cfg.DB.BlobStores() {
		out = append(out, s.storeView(bs))
	}
	return out
}

// StoreInput is a blob store as its admins give it; SecretKey nil keeps
// the one there.
type StoreInput struct {
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	Path      string  `json:"path"`
	Endpoint  string  `json:"endpoint"`
	Region    string  `json:"region"`
	Bucket    string  `json:"bucket"`
	Prefix    string  `json:"prefix"`
	AccessKey string  `json:"accessKey"`
	SecretKey *string `json:"secretKey"`
	PathStyle bool    `json:"pathStyle"`
	CA        string  `json:"ca"`
	Insecure  bool    `json:"insecure"`
	Quota     int64   `json:"quota"`
}

// store makes a record of what its admins gave, over cur when it changes.
func (s *Server) store(in StoreInput, cur meta.BlobStore) (meta.BlobStore, string, error) {
	bs := meta.BlobStore{Name: strings.TrimSpace(in.Name), Kind: in.Kind, Quota: in.Quota, Created: cur.Created, By: cur.By, Secret: cur.Secret}
	if cur.Name != "" {
		bs.Name = cur.Name
	}
	if !storeNameRE.MatchString(bs.Name) || bs.Name == meta.DefaultStore {
		return bs, "", fmt.Errorf("%w: a name is lowercase letters, digits and dashes, 2 to 32, not default", ErrStore)
	}
	if bs.Quota < 0 {
		return bs, "", fmt.Errorf("%w: a quota is a number of bytes, 0 for none", ErrStore)
	}
	secret := ""
	switch in.Kind {
	case "file":
		p := filepath.Clean(strings.TrimSpace(in.Path))
		if !filepath.IsAbs(p) || p == "/" {
			return bs, "", fmt.Errorf("%w: a file store's path is a directory of its own, such as /var/lib/kartal-registry-archive", ErrStore)
		}
		bs.Path = p
	case "s3":
		bs.Endpoint, bs.Region, bs.Bucket, bs.Prefix = strings.TrimSpace(in.Endpoint), strings.TrimSpace(in.Region), strings.TrimSpace(in.Bucket), strings.TrimSpace(in.Prefix)
		bs.AccessKey, bs.PathStyle, bs.CA, bs.Insecure = strings.TrimSpace(in.AccessKey), in.PathStyle, strings.TrimSpace(in.CA), in.Insecure
		if len(bs.AccessKey) > 256 || len(bs.CA) > 64<<10 {
			return bs, "", fmt.Errorf("%w: the access key or the CA is too long", ErrStore)
		}
		if in.SecretKey != nil {
			sealed, err := s.seal(*in.SecretKey)
			if err != nil {
				return bs, "", err
			}
			bs.Secret, secret = sealed, *in.SecretKey
		} else if bs.Secret != "" {
			var err error
			if secret, err = s.unseal(bs.Secret); err != nil {
				return bs, "", err
			}
		}
	default:
		return bs, "", fmt.Errorf("%w: the kind is file or s3", ErrStore)
	}
	return bs, secret, nil
}

// TestStore tries a store out as its record says, before it is kept.
func (s *Server) TestStore(bs meta.BlobStore, secret string) error {
	if bs.Kind == "s3" {
		staging := s.cfg.StagingDir
		if staging == "" {
			return errors.New("the registry has no directory for an S3 store's uploads")
		}
		st, err := blobstore.NewS3(blobstore.S3Config{Endpoint: bs.Endpoint, Region: bs.Region, Bucket: bs.Bucket, Prefix: bs.Prefix,
			AccessKey: bs.AccessKey, SecretKey: secret, PathStyle: bs.PathStyle, CA: bs.CA, Insecure: bs.Insecure,
			Staging: filepath.Join(staging, ".test-"+bs.Name), HTTP: s.cfg.StoreHTTP})
		if err != nil {
			return err
		}
		return st.Check()
	}
	st, err := blobstore.NewFile(bs.Path)
	if err != nil {
		return err
	}
	return st.Ping()
}

// PutStore adds a blob store, or changes one, once it works.
func (s *Server) PutStore(in StoreInput, name, by string) (meta.BlobStore, error) {
	var cur meta.BlobStore
	if name != "" {
		var ok bool
		if cur, ok = s.cfg.DB.BlobStoreNamed(name); !ok {
			return meta.BlobStore{}, meta.ErrNotFound
		}
		if in.Kind != cur.Kind {
			return meta.BlobStore{}, fmt.Errorf("%w: a store keeps its kind", ErrStore)
		}
	} else {
		if _, ok := s.cfg.DB.BlobStoreNamed(strings.TrimSpace(in.Name)); ok {
			return meta.BlobStore{}, fmt.Errorf("%w: a blob store of that name exists", meta.ErrExists)
		}
	}
	bs, secret, err := s.store(in, cur)
	if err != nil {
		return bs, err
	}
	if err := s.overlaps(bs); err != nil {
		return bs, err
	}
	if bs.Kind == "s3" && secret == "" {
		return bs, fmt.Errorf("%w: an S3 store needs its secret key", ErrStore)
	}
	if err := s.TestStore(bs, secret); err != nil {
		return bs, fmt.Errorf("%w: it does not work: %v", ErrStore, err)
	}
	if name == "" {
		bs.Created, bs.By = s.now().UTC(), by
	}
	if err := s.cfg.DB.PutBlobStore(bs, by); err != nil {
		return bs, err
	}
	s.dropStore(bs.Name)
	return bs, nil
}

func storeError(w http.ResponseWriter, s *Server, what string, err error) {
	switch {
	case errors.Is(err, ErrStore), errors.Is(err, ErrSource):
		adminError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, meta.ErrNotFound):
		adminError(w, http.StatusNotFound, "no such blob store")
	case errors.Is(err, meta.ErrExists), errors.Is(err, meta.ErrInUse):
		adminError(w, http.StatusConflict, err.Error())
	default:
		s.adminInternal(w, what, err)
	}
}

func (s *Server) listStores(w http.ResponseWriter, _ *http.Request) {
	adminJSON(w, http.StatusOK, s.StoreViews())
}

func (s *Server) createStore(w http.ResponseWriter, r *http.Request) {
	var in StoreInput
	if !readBody(w, r, &in) {
		return
	}
	bs, err := s.PutStore(in, "", actor(r))
	if err != nil {
		storeError(w, s, "adding a blob store", err)
		return
	}
	adminJSON(w, http.StatusCreated, s.storeView(bs))
}

func (s *Server) updateStore(w http.ResponseWriter, r *http.Request) {
	var in StoreInput
	if !readBody(w, r, &in) {
		return
	}
	bs, err := s.PutStore(in, r.PathValue("name"), actor(r))
	if err != nil {
		storeError(w, s, "changing a blob store", err)
		return
	}
	adminJSON(w, http.StatusOK, s.storeView(bs))
}

func (s *Server) deleteStore(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.cfg.DB.DeleteBlobStore(name, actor(r)); err != nil {
		storeError(w, s, "deleting a blob store", err)
		return
	}
	s.dropStore(name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testStore(w http.ResponseWriter, r *http.Request) {
	var in StoreInput
	if !readBody(w, r, &in) {
		return
	}
	var cur meta.BlobStore
	if name := strings.TrimSpace(in.Name); name != "" {
		cur, _ = s.cfg.DB.BlobStoreNamed(name)
	}
	bs, secret, err := s.store(in, cur)
	if err == nil {
		err = s.overlaps(bs)
	}
	if err != nil {
		storeError(w, s, "testing a blob store", err)
		return
	}
	out := map[string]any{"ok": true}
	if err := s.TestStore(bs, secret); err != nil {
		out = map[string]any{"ok": false, "error": err.Error()}
	}
	adminJSON(w, http.StatusOK, out)
}

// overlaps refuses a store that would share its blobs with another: two
// stores in one directory, or one bucket below prefixes one inside the
// other, would each collect the other's blobs as garbage. A directory
// store is also kept out of the registry's own places.
func (s *Server) overlaps(bs meta.BlobStore) error {
	inside := func(a, b string) bool {
		a, b = filepath.Clean(a), filepath.Clean(b)
		return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
	}
	switch bs.Kind {
	case "file":
		own := map[string]string{"the default store": "", "the S3 stores' uploads": s.cfg.StagingDir, "the scans' reports": s.cfg.ScanDir}
		if f, ok := s.cfg.Store.(*blobstore.File); ok {
			own["the default store"] = f.Root()
		}
		for what, p := range own {
			if p != "" && inside(bs.Path, p) {
				return fmt.Errorf("%w: %s shares its place with %s (%s)", ErrStore, bs.Path, what, p)
			}
		}
		for _, other := range s.cfg.DB.BlobStores() {
			if other.Name != bs.Name && other.Kind == "file" && inside(bs.Path, other.Path) {
				return fmt.Errorf("%w: %s shares its place with the store %s (%s)", ErrStore, bs.Path, other.Name, other.Path)
			}
		}
	case "s3":
		norm := func(x meta.BlobStore) (string, string) {
			p := strings.TrimPrefix(x.Prefix, "/")
			if p != "" && !strings.HasSuffix(p, "/") {
				p += "/"
			}
			return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(x.Endpoint), "/")) + " " + x.Bucket, p
		}
		where, prefix := norm(bs)
		for _, other := range s.cfg.DB.BlobStores() {
			if other.Name == bs.Name || other.Kind != "s3" {
				continue
			}
			ow, op := norm(other)
			if ow == where && (strings.HasPrefix(prefix, op) || strings.HasPrefix(op, prefix)) {
				return fmt.Errorf("%w: the bucket %s below %q is the store %s's place too (below %q)", ErrStore, bs.Bucket, prefix, other.Name, op)
			}
		}
	}
	return nil
}
