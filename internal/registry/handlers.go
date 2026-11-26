package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/manifest"
	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

func noProject(name string) *apiError {
	return errorf(http.StatusNotFound, "NAME_UNKNOWN", "project %s does not exist; an admin makes it first, in Kartal Gözü", meta.ProjectOf(name))
}

// ---------------------------------------------------------------- blobs

func (s *Server) blob(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	if !blobstore.ValidDigest(t.ref) {
		writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "%q is not a sha256 digest", t.ref))
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !s.may(w, r, g, t.name, "pull") {
			return
		}
		if _, ok := s.cfg.DB.Blob(t.name, t.ref); !ok {
			writeError(w, errorf(http.StatusNotFound, "BLOB_UNKNOWN", "%s is not in %s", t.ref, t.name))
			return
		}
		f, size, err := s.cfg.Store.Open(t.ref)
		if errors.Is(err, blobstore.ErrNotFound) {
			writeError(w, errorf(http.StatusNotFound, "BLOB_UNKNOWN", "%s is gone from the store", t.ref))
			return
		}
		if err != nil {
			s.internal(w, "opening a blob", err)
			return
		}
		defer f.Close()
		h := w.Header()
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Docker-Content-Digest", t.ref)
		h.Set("ETag", `"`+t.ref+`"`)
		h.Set("Cache-Control", "max-age=31536000")
		if r.Method == http.MethodHead {
			h.Set("Content-Length", strconv.FormatInt(size, 10))
			h.Set("Accept-Ranges", "bytes")
			return
		}
		// Ranges, If-None-Match: content addressed by its digest never
		// changes, which ServeContent works with.
		http.ServeContent(w, r, "", time.Time{}, f)
	case http.MethodDelete:
		if !s.may(w, r, g, t.name, "delete") {
			return
		}
		if err := s.cfg.DB.UnlinkBlob(t.name, t.ref); errors.Is(err, meta.ErrNotFound) {
			writeError(w, errorf(http.StatusNotFound, "BLOB_UNKNOWN", "%s is not in %s", t.ref, t.name))
			return
		} else if err != nil {
			s.internal(w, "unlinking a blob", err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		w.Header().Set("Allow", "GET, HEAD, DELETE")
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "not a method for blobs"))
	}
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.cfg.Log.Error("registry: "+what, "err", err)
	writeError(w, errorf(http.StatusInternalServerError, "UNKNOWN", "%s failed", what))
}

// ---------------------------------------------------------------- uploads

func (s *Server) uploadURL(name, id string) string { return "/v2/" + name + "/blobs/uploads/" + id }

// uploadIn tells whether an upload was started in the repository; a
// restart forgets it, and the client starts over.
func (s *Server) uploadIn(id, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return id != "" && s.uploads[id] == name
}

func (s *Server) forget(id string) {
	s.mu.Lock()
	delete(s.uploads, id)
	s.mu.Unlock()
}

func (s *Server) progress(w http.ResponseWriter, name, id string, size int64, status int) {
	h := w.Header()
	h.Set("Location", s.uploadURL(name, id))
	h.Set("Docker-Upload-UUID", id)
	h.Set("Range", "0-"+strconv.FormatInt(max(size-1, 0), 10))
	h.Set("Content-Length", "0")
	w.WriteHeader(status)
}

func (s *Server) created(w http.ResponseWriter, name, digest string) {
	h := w.Header()
	h.Set("Location", "/v2/"+name+"/blobs/"+digest)
	h.Set("Docker-Content-Digest", digest)
	h.Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// finish makes an upload a blob of the repository.
func (s *Server) finish(w http.ResponseWriter, name, id, digest string) {
	if !blobstore.ValidDigest(digest) {
		writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "%q is not a sha256 digest", digest))
		return
	}
	size, err := s.cfg.Store.Finish(id, digest)
	switch {
	case errors.Is(err, blobstore.ErrDigestMismatch):
		writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "the content uploaded is not %s", digest))
		return
	case errors.Is(err, blobstore.ErrNotFound):
		writeError(w, errorf(http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload"))
		return
	case err != nil:
		s.internal(w, "finishing an upload", err)
		return
	}
	s.forget(id)
	if err := s.cfg.DB.LinkBlob(name, digest, size); errors.Is(err, meta.ErrNoProject) {
		writeError(w, noProject(name))
		return
	} else if err != nil {
		s.internal(w, "recording a blob", err)
		return
	}
	s.created(w, name, digest)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	if !s.may(w, r, g, t.name, "push") {
		return
	}
	if _, ok := s.cfg.DB.Project(meta.ProjectOf(t.name)); !ok {
		writeError(w, noProject(t.name))
		return
	}
	if t.ref == "" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "start an upload with POST"))
			return
		}
		s.startUpload(w, r, g, t)
		return
	}
	if !s.uploadIn(t.ref, t.name) {
		writeError(w, errorf(http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload in %s", t.name))
		return
	}
	switch r.Method {
	case http.MethodGet:
		size, err := s.cfg.Store.UploadSize(t.ref)
		if err != nil {
			writeError(w, errorf(http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload"))
			return
		}
		s.progress(w, t.name, t.ref, size, http.StatusNoContent)
	case http.MethodPatch:
		size, err := s.cfg.Store.UploadSize(t.ref)
		if err != nil {
			writeError(w, errorf(http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload"))
			return
		}
		offset := size
		if cr := r.Header.Get("Content-Range"); cr != "" {
			start, _, ok := strings.Cut(strings.TrimPrefix(cr, "bytes "), "-")
			n, err := strconv.ParseInt(start, 10, 64)
			if !ok || err != nil || n != size {
				w.Header().Set("Range", "0-"+strconv.FormatInt(max(size-1, 0), 10))
				w.Header().Set("Location", s.uploadURL(t.name, t.ref))
				writeError(w, errorf(http.StatusRequestedRangeNotSatisfiable, "BLOB_UPLOAD_INVALID", "the chunk must start at %d", size))
				return
			}
			offset = n
		}
		size, err = s.cfg.Store.Append(t.ref, offset, r.Body)
		if errors.Is(err, blobstore.ErrOffset) {
			w.Header().Set("Range", "0-"+strconv.FormatInt(max(size-1, 0), 10))
			writeError(w, errorf(http.StatusRequestedRangeNotSatisfiable, "BLOB_UPLOAD_INVALID", "the chunk must start at %d", size))
			return
		}
		if err != nil {
			s.internal(w, "writing a chunk", err)
			return
		}
		s.progress(w, t.name, t.ref, size, http.StatusAccepted)
	case http.MethodPut:
		size, err := s.cfg.Store.UploadSize(t.ref)
		if err != nil {
			writeError(w, errorf(http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload"))
			return
		}
		// The last chunk may come with the PUT.
		if _, err := s.cfg.Store.Append(t.ref, size, r.Body); err != nil {
			s.internal(w, "writing the last chunk", err)
			return
		}
		s.finish(w, t.name, t.ref, r.URL.Query().Get("digest"))
	case http.MethodDelete:
		s.forget(t.ref)
		if err := s.cfg.Store.Cancel(t.ref); err != nil && !errors.Is(err, blobstore.ErrNotFound) {
			s.internal(w, "cancelling an upload", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PATCH, PUT, DELETE")
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "not a method for uploads"))
	}
}

// startUpload starts an upload, or takes a blob whole, or mounts one; upload
// checked that the project is there. It may go meanwhile, while the
// repository is not made yet.
func (s *Server) startUpload(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	q := r.URL.Query()
	// A blob another repository has is linked here without a copy, when the
	// client may read it there.
	if mount := q.Get("mount"); mount != "" && blobstore.ValidDigest(mount) {
		if from := q.Get("from"); ValidName(from) && g != nil && g.access["repository:"+from]["pull"] {
			if size, ok := s.cfg.DB.Blob(from, mount); ok {
				if _, err := s.cfg.Store.Stat(mount); err == nil {
					if err := s.cfg.DB.LinkBlob(t.name, mount, size); errors.Is(err, meta.ErrNoProject) {
						writeError(w, noProject(t.name))
						return
					} else if err != nil {
						s.internal(w, "mounting a blob", err)
						return
					}
					s.created(w, t.name, mount)
					return
				}
			}
		}
	}
	id, err := s.cfg.Store.StartUpload()
	if err != nil {
		s.internal(w, "starting an upload", err)
		return
	}
	s.mu.Lock()
	s.uploads[id] = t.name
	s.mu.Unlock()
	// The whole blob in the POST.
	if digest := q.Get("digest"); digest != "" {
		if _, err := s.cfg.Store.Append(id, 0, r.Body); err != nil {
			s.cfg.Store.Cancel(id)
			s.forget(id)
			s.internal(w, "writing a blob", err)
			return
		}
		if !blobstore.ValidDigest(digest) {
			s.cfg.Store.Cancel(id)
			s.forget(id)
			writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "%q is not a sha256 digest", digest))
			return
		}
		if _, err := s.cfg.Store.Finish(id, digest); err != nil {
			s.cfg.Store.Cancel(id)
			s.forget(id)
			if errors.Is(err, blobstore.ErrDigestMismatch) {
				writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "the content uploaded is not %s", digest))
				return
			}
			s.internal(w, "finishing a blob", err)
			return
		}
		s.forget(id)
		size, _ := s.cfg.Store.Stat(digest)
		if err := s.cfg.DB.LinkBlob(t.name, digest, size); errors.Is(err, meta.ErrNoProject) {
			writeError(w, noProject(t.name))
			return
		} else if err != nil {
			s.internal(w, "recording a blob", err)
			return
		}
		s.created(w, t.name, digest)
		return
	}
	s.progress(w, t.name, id, 0, http.StatusAccepted)
}

// ---------------------------------------------------------------- manifests

func (s *Server) manifest(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !s.may(w, r, g, t.name, "pull") {
			return
		}
		digest, ok := s.cfg.DB.Resolve(t.name, t.ref)
		if !ok {
			writeError(w, errorf(http.StatusNotFound, "MANIFEST_UNKNOWN", "%s:%s is not there", t.name, t.ref))
			return
		}
		a, _ := s.cfg.DB.Artifact(t.name, digest)
		f, size, err := s.cfg.Store.Open(digest)
		if err != nil {
			writeError(w, errorf(http.StatusNotFound, "MANIFEST_UNKNOWN", "the manifest %s is gone from the store", digest))
			return
		}
		defer f.Close()
		h := w.Header()
		h.Set("Content-Type", a.MediaType)
		h.Set("Docker-Content-Digest", digest)
		h.Set("ETag", `"`+digest+`"`)
		h.Set("Content-Length", strconv.FormatInt(size, 10))
		if r.Method == http.MethodHead {
			return
		}
		if _, err := io.Copy(w, f); err == nil {
			s.cfg.DB.RecordPull(t.name, digest)
		}
	case http.MethodPut:
		if !s.may(w, r, g, t.name, "push") {
			return
		}
		s.putManifest(w, r, g, t)
	case http.MethodDelete:
		if !s.may(w, r, g, t.name, "delete") {
			return
		}
		var err error
		if blobstore.ValidDigest(t.ref) {
			err = s.cfg.DB.DeleteArtifact(t.name, t.ref, subject(g))
		} else {
			err = s.cfg.DB.Untag(t.name, t.ref, subject(g))
		}
		if errors.Is(err, meta.ErrNotFound) {
			writeError(w, errorf(http.StatusNotFound, "MANIFEST_UNKNOWN", "%s:%s is not there", t.name, t.ref))
			return
		}
		if errors.Is(err, meta.ErrInUse) {
			writeError(w, errorf(http.StatusConflict, "DENIED", "%s; delete the index first", err))
			return
		}
		if err != nil {
			s.internal(w, "deleting a manifest", err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "not a method for manifests"))
	}
}

func (s *Server) putManifest(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	byDigest := strings.HasPrefix(t.ref, "sha256:")
	if !byDigest && !ValidTag(t.ref) {
		writeError(w, errorf(http.StatusBadRequest, "MANIFEST_INVALID", "%q is not a tag: letters, digits, _ . -, at most 128", t.ref))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, manifest.MaxSize+1))
	if err != nil {
		writeError(w, errorf(http.StatusBadRequest, "MANIFEST_INVALID", "the manifest could not be read"))
		return
	}
	if len(body) > manifest.MaxSize {
		writeError(w, errorf(http.StatusRequestEntityTooLarge, "SIZE_INVALID", "a manifest may be at most %d bytes", manifest.MaxSize))
		return
	}
	digest := blobstore.Digest(body)
	if byDigest && t.ref != digest {
		writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "the manifest's digest is %s, not %s", digest, t.ref))
		return
	}
	m, err := manifest.Parse(r.Header.Get("Content-Type"), body)
	if err != nil {
		writeError(w, errorf(http.StatusBadRequest, "MANIFEST_INVALID", "%s", err.Error()))
		return
	}
	if _, ok := s.cfg.DB.Project(meta.ProjectOf(t.name)); !ok {
		writeError(w, noProject(t.name))
		return
	}
	// Everything it refers to must be in this repository already.
	for _, ref := range m.References() {
		if _, ok := s.cfg.DB.Blob(t.name, ref.Digest); !ok {
			e := errorf(http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN", "blob %s is not in %s; push it first", ref.Digest, t.name)
			e.detail = map[string]string{"digest": ref.Digest}
			writeError(w, e)
			return
		}
	}
	for _, child := range m.Manifests {
		if _, ok := s.cfg.DB.Artifact(t.name, child.Digest); !ok {
			e := errorf(http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN", "manifest %s is not in %s; push it first", child.Digest, t.name)
			e.detail = map[string]string{"digest": child.Digest}
			writeError(w, e)
			return
		}
	}
	a := meta.Artifact{Digest: digest, MediaType: m.MediaType, ArtifactType: m.ArtifactType, Kind: m.Kind(), Size: int64(len(body)),
		Config: m.Config, Layers: m.Layers, Manifests: m.Manifests, Annotations: m.Annotations}
	if m.Subject != nil {
		a.Subject = m.Subject.Digest
	}
	if m.Config != nil && manifest.IsImageConfig(m.Config.MediaType) && m.Config.Size <= manifest.MaxConfigSize {
		if c := s.readConfig(m.Config.Digest); c != nil {
			p := c.Platform
			if p.OS != "" || p.Architecture != "" {
				a.Platform = &p
			}
			a.Created, a.Labels = c.Created, c.Labels
		}
	}
	if err := s.cfg.Store.Put(digest, body); err != nil {
		s.internal(w, "storing a manifest", err)
		return
	}
	tag := ""
	if !byDigest {
		tag = t.ref
	}
	if err := s.cfg.DB.PutArtifact(t.name, a, tag, subject(g)); errors.Is(err, meta.ErrNoProject) {
		writeError(w, noProject(t.name))
		return
	} else if err != nil {
		s.internal(w, "recording a manifest", err)
		return
	}
	h := w.Header()
	h.Set("Location", "/v2/"+t.name+"/manifests/"+digest)
	h.Set("Docker-Content-Digest", digest)
	if m.Subject != nil {
		h.Set("OCI-Subject", m.Subject.Digest)
	}
	h.Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// readConfig reads an image's config from the store, or nil.
func (s *Server) readConfig(digest string) *manifest.Config {
	f, size, err := s.cfg.Store.Open(digest)
	if err != nil || size > manifest.MaxConfigSize {
		if f != nil {
			f.Close()
		}
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	c, err := manifest.ImageConfig(b)
	if err != nil {
		return nil
	}
	return c
}

// ---------------------------------------------------------------- tags, referrers

func (s *Server) tags(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	if r.Method != http.MethodGet {
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET"))
		return
	}
	if !s.may(w, r, g, t.name, "pull") {
		return
	}
	n, last, e := page(r)
	if e != nil {
		writeError(w, e)
		return
	}
	limit := n
	if limit > 0 {
		limit++
	}
	tags, ok := s.cfg.DB.Tags(t.name, last, limit)
	if !ok {
		writeError(w, errorf(http.StatusNotFound, "NAME_UNKNOWN", "%s is not there", t.name))
		return
	}
	if n > 0 && len(tags) > n {
		tags = tags[:n]
		next(w, "/v2/"+t.name+"/tags/list", n, tags[n-1])
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"name": t.name, "tags": tags})
}

func (s *Server) referrers(w http.ResponseWriter, r *http.Request, g *grant, t target) {
	if r.Method != http.MethodGet {
		writeError(w, errorf(http.StatusMethodNotAllowed, "UNSUPPORTED", "use GET"))
		return
	}
	if !blobstore.ValidDigest(t.ref) {
		writeError(w, errorf(http.StatusBadRequest, "DIGEST_INVALID", "%q is not a sha256 digest", t.ref))
		return
	}
	if !s.may(w, r, g, t.name, "pull") {
		return
	}
	artifactType := r.URL.Query().Get("artifactType")
	descs := []manifest.Descriptor{}
	for _, a := range s.cfg.DB.Referrers(t.name, t.ref, artifactType) {
		at := a.ArtifactType
		if at == "" && a.Config != nil {
			at = a.Config.MediaType
		}
		descs = append(descs, manifest.Descriptor{MediaType: a.MediaType, Digest: a.Digest, Size: a.Size, ArtifactType: at, Annotations: a.Annotations})
	}
	if artifactType != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(map[string]any{"schemaVersion": 2, "mediaType": manifest.OCIIndex, "manifests": descs})
	w.Header().Set("Content-Type", manifest.OCIIndex)
	w.Write(buf.Bytes())
}
