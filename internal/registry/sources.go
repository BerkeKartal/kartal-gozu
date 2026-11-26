package registry

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/remote"
)

// Sources are the registries replication copies from: Harbor, Nexus, or
// any of the Distribution API. Their passwords are sealed with AES-GCM, by
// a key the registry's admins never see; the API never gives them back.

// SourcesKey makes the key that seals the sources' secrets from a secret
// of the registry's (KARTAL_REGISTRY_SOURCES_KEY, or the one it shares
// with kartal-server): changing it means typing the passwords again.
func SourcesKey(secret string) []byte {
	sum := sha256.Sum256([]byte("kartal-registry/sources\x00" + secret))
	return sum[:]
}

func (s *Server) aead() (cipher.AEAD, error) {
	if len(s.cfg.SourcesKey) != 32 {
		return nil, fmt.Errorf("%w: the registry has no key to keep the sources' passwords with (KARTAL_REGISTRY_SOURCES_KEY)", ErrSource)
	}
	block, err := aes.NewCipher(s.cfg.SourcesKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal seals a secret; nothing seals to nothing.
func (s *Server) seal(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	g, err := s.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (s *Server) unseal(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	g, err := s.aead()
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(b) < g.NonceSize() {
		return "", errors.New("the source's password cannot be read")
	}
	plain, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
	if err != nil {
		return "", errors.New("the source's password cannot be read: the registry's key changed; type it again")
	}
	return string(plain), nil
}

// remoteSource is how to read a source, its password opened.
func (s *Server) remoteSource(src meta.Source) (remote.Source, *remote.Client, error) {
	pass, err := s.unseal(src.Secret)
	if err != nil {
		return remote.Source{}, nil, err
	}
	rs := remote.Source{Kind: src.Kind, URL: src.URL, Repository: src.Repository,
		Options: remote.Options{Username: src.Username, Password: pass, CA: src.CA, Insecure: src.Insecure, HTTP: s.cfg.RemoteHTTP}}
	c, err := remote.Open(rs)
	return rs, c, err
}

// SourceView is a source as the API shows it: with no secret.
type SourceView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	URL        string    `json:"url"`
	Repository string    `json:"repository,omitempty"`
	Username   string    `json:"username,omitempty"`
	HasSecret  bool      `json:"hasSecret"`
	CA         string    `json:"ca,omitempty"`
	Insecure   bool      `json:"insecure,omitempty"`
	Created    time.Time `json:"created"`
	By         string    `json:"by,omitempty"`
}

func sourceView(src meta.Source) SourceView {
	return SourceView{ID: src.ID, Name: src.Name, Kind: src.Kind, URL: src.URL, Repository: src.Repository, Username: src.Username,
		HasSecret: src.Secret != "", CA: src.CA, Insecure: src.Insecure, Created: src.Created, By: src.By}
}

// SourceInput is a source as an admin sets it. A password left out (nil)
// stays as it was; an empty one is none.
type SourceInput struct {
	ID         string  `json:"id,omitempty"`
	Name       string  `json:"name"`
	Kind       string  `json:"kind"`
	URL        string  `json:"url"`
	Repository string  `json:"repository"`
	Username   string  `json:"username"`
	Password   *string `json:"password"`
	CA         string  `json:"ca"`
	Insecure   bool    `json:"insecure"`
}

var sourceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// ErrSource is a source that cannot be as asked.
var ErrSource = errors.New("not a source")

// source makes a source of what an admin sent, onto what was there.
func (s *Server) source(in SourceInput, cur meta.Source) (meta.Source, error) {
	in.Name, in.URL = strings.TrimSpace(in.Name), strings.TrimSuffix(strings.TrimSpace(in.URL), "/")
	switch {
	case !sourceName.MatchString(in.Name):
		return meta.Source{}, fmt.Errorf("%w: a name is letters, digits, spaces and . _ -, at most 64", ErrSource)
	case !slices.Contains(remote.Kinds, in.Kind):
		return meta.Source{}, fmt.Errorf("%w: the kind is harbor, nexus or registry", ErrSource)
	case in.Kind == remote.KindNexus && strings.TrimSpace(in.Repository) == "":
		return meta.Source{}, fmt.Errorf("%w: a Nexus source names its Docker repository", ErrSource)
	case len(in.Username) > 256 || (in.Password != nil && len(*in.Password) > 4096) || len(in.CA) > 64<<10:
		return meta.Source{}, fmt.Errorf("%w: the user name, password or CA is too long", ErrSource)
	}
	src := cur
	src.Name, src.Kind, src.URL, src.Username, src.CA, src.Insecure = in.Name, in.Kind, in.URL, strings.TrimSpace(in.Username), in.CA, in.Insecure
	src.Repository = ""
	if in.Kind == remote.KindNexus {
		src.Repository = strings.TrimSpace(in.Repository)
	}
	if in.Password != nil {
		sealed, err := s.seal(*in.Password)
		if err != nil {
			return meta.Source{}, err
		}
		src.Secret = sealed
	}
	// The address and the CA must be ones a client can be made of.
	if _, _, err := s.remoteSource(src); err != nil {
		return meta.Source{}, fmt.Errorf("%w: %s", ErrSource, err)
	}
	return src, nil
}

// SourceTest is what trying a source found.
type SourceTest struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Seconds float64 `json:"seconds"`
	// Projects are those it lists, when it lists them.
	Projects []remote.Project `json:"projects,omitempty"`
}

// TestSource tries a source: its registry lets it in, and its listing
// answers (Harbor's and Nexus's APIs, or the catalog).
func (s *Server) TestSource(ctx context.Context, src meta.Source) SourceTest {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out := SourceTest{}
	rs, c, err := s.remoteSource(src)
	if err == nil {
		err = c.Ping(ctx)
	}
	if err == nil {
		out.Projects, err = remote.Projects(ctx, rs, c)
		// A registry without a catalog (Docker Hub) still is one.
		if err != nil && src.Kind == remote.KindRegistry {
			out.Projects, err = nil, nil
		}
	}
	out.OK = err == nil
	if err != nil {
		out.Error = err.Error()
	}
	out.Seconds = time.Since(start).Seconds()
	return out
}

// ---------------------------------------------------------------- admin API

func (s *Server) listSources(w http.ResponseWriter, _ *http.Request) {
	out := []SourceView{}
	for _, src := range s.cfg.DB.Sources() {
		out = append(out, sourceView(src))
	}
	adminJSON(w, http.StatusOK, out)
}

func sourceError(w http.ResponseWriter, s *Server, what string, err error) {
	switch {
	case errors.Is(err, ErrSource):
		adminError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, meta.ErrExists), errors.Is(err, meta.ErrInUse):
		adminError(w, http.StatusConflict, err.Error())
	case errors.Is(err, meta.ErrNotFound):
		adminError(w, http.StatusNotFound, "no such source")
	default:
		s.adminInternal(w, what, err)
	}
}

// AddSource adds a source.
func (s *Server) AddSource(in SourceInput, by string) (meta.Source, error) {
	b := make([]byte, 8)
	rand.Read(b)
	src, err := s.source(in, meta.Source{ID: hex.EncodeToString(b), Created: s.now().UTC(), By: by})
	if err != nil {
		return meta.Source{}, err
	}
	return src, s.cfg.DB.PutSource(src, by)
}

func (s *Server) createSource(w http.ResponseWriter, r *http.Request) {
	var in SourceInput
	if !readBody(w, r, &in) {
		return
	}
	src, err := s.AddSource(in, actor(r))
	if err != nil {
		sourceError(w, s, "adding a source", err)
		return
	}
	adminJSON(w, http.StatusCreated, sourceView(src))
}

// Migration is what migrating a project of a source did: whether the
// project was made here, the rule that copies it, and its first run.
type Migration struct {
	Project string `json:"project"`
	Created bool   `json:"created"`
	Public  bool   `json:"public"`
	Rule    string `json:"rule,omitempty"`
	Job     string `json:"job,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Migrate moves projects of a source here: each is made (public as it is
// there), a rule copies all its repositories, and runs now; with sync it
// runs every hour too, while people move over. Migrating a project again
// runs its rule again.
func (s *Server) Migrate(ctx context.Context, sourceID string, projects []string, sync bool, by string) ([]Migration, error) {
	src, ok := s.cfg.DB.Source(sourceID)
	if !ok {
		return nil, fmt.Errorf("%w: no such source", ErrSource)
	}
	rs, c, err := s.remoteSource(src)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	there, err := remote.Projects(ctx, rs, c)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", src.Name, err)
	}
	public := map[string]bool{}
	for _, p := range there {
		public[p.Name] = p.Public
	}
	rules := map[string]meta.ReplicationRule{}
	for _, r := range s.cfg.DB.Rules() {
		rules[strings.ToLower(r.Name)] = r
	}
	var out []Migration
	for _, name := range projects {
		m := Migration{Project: name, Public: public[name]}
		pub, listed := public[name]
		switch {
		case !listed:
			m.Error = "the source has no such project"
		case !ValidProject(name):
			m.Error = "not a project's name here: lower-case letters and digits, which . _ - may join"
		}
		if m.Error != "" {
			out = append(out, m)
			continue
		}
		if _, ok := s.cfg.DB.Project(name); !ok {
			if err := s.cfg.DB.CreateProject(meta.Project{Name: name, Public: pub, Description: "Moved from " + src.Name}, by); err != nil {
				m.Error = err.Error()
				out = append(out, m)
				continue
			}
			m.Created = true
		}
		ruleName := "Migration of " + name
		if len(ruleName) > 64 {
			ruleName = ruleName[:64]
		}
		r, exists := rules[strings.ToLower(ruleName)]
		if !exists || r.Source != src.ID {
			b := make([]byte, 8)
			rand.Read(b)
			now := s.now().UTC()
			r = meta.ReplicationRule{ID: hex.EncodeToString(b), Name: ruleName, Source: src.ID, Repositories: name + "/**", Tags: "**",
				Project: name, Referrers: true, Concurrency: 2, Created: now, By: by, Since: now}
			if exists {
				r.Name = ruleName[:min(len(ruleName), 56)] + " " + r.ID[:7]
			}
		}
		if sync {
			if r.Cron != "0 * * * *" || !r.Enabled {
				r.Since = s.now().UTC()
			}
			r.Cron, r.Enabled = "0 * * * *", true
		}
		if err := s.checkRule(r); err == nil {
			err = s.cfg.DB.PutRule(r, by)
			if err != nil {
				m.Error = err.Error()
			}
		} else {
			m.Error = err.Error()
		}
		if m.Error != "" {
			out = append(out, m)
			continue
		}
		m.Rule = r.ID
		if j, err := s.StartReplication(r.ID, false, by); err != nil {
			m.Error = err.Error()
		} else {
			m.Job = j.ID
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *Server) migrate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Projects []string `json:"projects"`
		Sync     bool     `json:"sync"`
	}
	if !readBody(w, r, &in) {
		return
	}
	if len(in.Projects) == 0 || len(in.Projects) > 200 {
		adminError(w, http.StatusBadRequest, "name between 1 and 200 projects to move")
		return
	}
	out, err := s.Migrate(r.Context(), r.PathValue("id"), in.Projects, in.Sync, actor(r))
	if err != nil {
		if errors.Is(err, ErrSource) {
			adminError(w, http.StatusNotFound, err.Error())
			return
		}
		adminError(w, http.StatusBadGateway, err.Error())
		return
	}
	adminJSON(w, http.StatusOK, out)
}

func (s *Server) updateSource(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.cfg.DB.Source(r.PathValue("id"))
	if !ok {
		adminError(w, http.StatusNotFound, "no such source")
		return
	}
	var in SourceInput
	if !readBody(w, r, &in) {
		return
	}
	src, err := s.source(in, cur)
	if err == nil {
		err = s.cfg.DB.PutSource(src, actor(r))
	}
	if err != nil {
		sourceError(w, s, "changing a source", err)
		return
	}
	adminJSON(w, http.StatusOK, sourceView(src))
}

func (s *Server) deleteSource(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.DB.DeleteSource(r.PathValue("id"), actor(r)); err != nil {
		sourceError(w, s, "deleting a source", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// testSource tries a source as it would be saved: one sent whole, or a
// saved one (with id), changed by what was sent.
func (s *Server) testSource(w http.ResponseWriter, r *http.Request) {
	var in SourceInput
	if !readBody(w, r, &in) {
		return
	}
	cur := meta.Source{}
	if in.ID != "" {
		var ok bool
		if cur, ok = s.cfg.DB.Source(in.ID); !ok {
			adminError(w, http.StatusNotFound, "no such source")
			return
		}
	}
	if in.Name == "" {
		in.Name = "test"
	}
	src, err := s.source(in, cur)
	if err != nil {
		sourceError(w, s, "trying a source", err)
		return
	}
	adminJSON(w, http.StatusOK, s.TestSource(r.Context(), src))
}

func (s *Server) sourceProjects(w http.ResponseWriter, r *http.Request) {
	src, ok := s.cfg.DB.Source(r.PathValue("id"))
	if !ok {
		adminError(w, http.StatusNotFound, "no such source")
		return
	}
	rs, c, err := s.remoteSource(src)
	if err != nil {
		adminError(w, http.StatusBadGateway, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	projects, err := remote.Projects(ctx, rs, c)
	if err != nil {
		adminError(w, http.StatusBadGateway, err.Error())
		return
	}
	if projects == nil {
		projects = []remote.Project{}
	}
	adminJSON(w, http.StatusOK, projects)
}
