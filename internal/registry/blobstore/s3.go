package blobstore

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// S3Config sets an S3 store up.
type S3Config struct {
	// Endpoint is the service's address, such as
	// https://s3.eu-central-1.amazonaws.com or http://minio.storage:9000.
	Endpoint string
	// Region is the bucket's (us-east-1 when empty, as MinIO takes).
	Region string
	Bucket string
	// Prefix is where in the bucket the blobs go:
	// <prefix>blobs/sha256/<first two hex digits>/<hex>, as File lays them
	// out, so that either can be copied into the other.
	Prefix    string
	AccessKey string
	SecretKey string
	// PathStyle names the bucket in the path, as MinIO wants, rather than in
	// the host.
	PathStyle bool
	// Staging is the local directory uploads are kept in until they are
	// whole; a finished one goes to the bucket.
	Staging string
	// PartSize is how much of a large blob one request carries (64 MiB
	// when zero, at least 5 MiB); a blob no larger goes in one request.
	PartSize int64
	// CA is a PEM bundle to trust besides the system's; Insecure takes any
	// certificate.
	CA       string
	Insecure bool
	// HTTP replaces the client, for tests.
	HTTP *http.Client
}

// S3 is a Store whose blobs are objects of a bucket. Its uploads are on a
// disk (Staging) until they are whole, as chunks of a push come in any
// size and S3 takes parts of 5 MiB at least.
type S3 struct {
	cfg      S3Config
	base     *url.URL
	client   *http.Client
	local    *File
	partSize int64
	now      func() time.Time

	// placing is held while blobs are deleted; recent are the blobs this
	// process stored (or found stored) lately, which collecting garbage
	// spares, as File spares a blob it renewed.
	placing sync.Mutex
	recent  map[string]time.Time
}

var (
	bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	prefixRE = regexp.MustCompile(`^[A-Za-z0-9._/-]*$`)
)

const (
	defaultPartSize = 64 << 20
	minPartSize     = 5 << 20
)

// NewS3 makes an S3 store; it asks the bucket nothing yet (Check does).
func NewS3(cfg S3Config) (*S3, error) {
	base, err := url.Parse(strings.TrimSuffix(strings.TrimSpace(cfg.Endpoint), "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("%q is not an S3 endpoint, such as https://s3.eu-central-1.amazonaws.com", cfg.Endpoint)
	}
	if !bucketRE.MatchString(cfg.Bucket) {
		return nil, fmt.Errorf("%q is not a bucket's name: lowercase letters, digits, dots and dashes, 3 to 63", cfg.Bucket)
	}
	cfg.Prefix = strings.TrimPrefix(strings.TrimSpace(cfg.Prefix), "/")
	if !prefixRE.MatchString(cfg.Prefix) || strings.Contains(cfg.Prefix, "..") || strings.Contains(cfg.Prefix, "//") {
		return nil, fmt.Errorf("%q is not a prefix: letters, digits, . _ - and /", cfg.Prefix)
	}
	if cfg.Prefix != "" && !strings.HasSuffix(cfg.Prefix, "/") {
		cfg.Prefix += "/"
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("an S3 store needs an access key and its secret")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	part := cfg.PartSize
	if part == 0 {
		part = defaultPartSize
	}
	if part < minPartSize {
		return nil, fmt.Errorf("a part is at least %d bytes, as S3 takes them", minPartSize)
	}
	if cfg.Staging == "" {
		return nil, errors.New("an S3 store needs a local directory for the uploads under way")
	}
	local, err := NewFile(cfg.Staging)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTP
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.ResponseHeaderTimeout = 2 * time.Minute
		// Insecure is asked for, of one store whose certificate cannot be
		// checked.
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.Insecure}
		if cfg.CA != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM([]byte(cfg.CA)) {
				return nil, errors.New("the CA is not a PEM certificate")
			}
			tlsCfg.RootCAs = pool
		}
		tr.TLSClientConfig = tlsCfg
		client = &http.Client{Transport: tr}
	}
	return &S3{cfg: cfg, base: base, client: client, local: local, partSize: part, now: time.Now, recent: map[string]time.Time{}}, nil
}

func (s *S3) key(digest string) (string, error) {
	if !ValidDigest(digest) {
		return "", ErrNotFound
	}
	hexPart := strings.TrimPrefix(digest, "sha256:")
	return s.cfg.Prefix + "blobs/sha256/" + hexPart[:2] + "/" + hexPart, nil
}

// objectURL is where an object (or, with no key, the bucket) is.
func (s *S3) objectURL(key string, q url.Values) *url.URL {
	u := *s.base
	path := strings.TrimSuffix(s.base.Path, "/")
	if s.cfg.PathStyle {
		path += "/" + s.cfg.Bucket
		if key != "" {
			path += "/" + key
		}
	} else {
		u.Host = s.cfg.Bucket + "." + u.Host
		path += "/" + key
	}
	u.Path, u.RawPath = path, uriEncode(path, true)
	u.RawQuery = canonicalQuery(q)
	return &u
}

// s3Retries is how many times a request is tried: the service's own
// trouble (5xx, slow down) and the network's are worth another try.
const s3Retries = 4

// do makes a signed request, trying again what may pass the next time;
// body (of size bytes, whose SHA-256 is payload) is read from its start
// each time.
func (s *S3) do(method, key string, q url.Values, body io.ReadSeeker, size int64, payload string, header http.Header) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < s3Retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(100<<attempt) * time.Millisecond)
		}
		req, err := http.NewRequest(method, s.base.String(), http.NoBody)
		if err != nil {
			return nil, err
		}
		req.URL = s.objectURL(key, q)
		req.Host = req.URL.Host
		if body != nil {
			if _, err := body.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			req.Body, req.ContentLength = io.NopCloser(body), size
		}
		for k, vs := range header {
			req.Header[k] = vs
		}
		signV4(req, s.cfg.AccessKey, s.cfg.SecretKey, s.cfg.Region, "s3", payload, s.now())
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			lastErr = s3Error(resp)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("S3 %s %s: %w", method, key, lastErr)
}

// s3Error reads the error a response says, and closes it.
func s3Error(resp *http.Response) error {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(b, &e) == nil && e.Code != "" {
		return fmt.Errorf("%d %s: %s", resp.StatusCode, e.Code, e.Message)
	}
	return fmt.Errorf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
}

// head is an object's size and when it was last written.
func (s *S3) head(key string) (int64, time.Time, error) {
	resp, err := s.do(http.MethodHead, key, nil, nil, 0, emptySHA256, nil)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return 0, time.Time{}, ErrNotFound
	default:
		return 0, time.Time{}, fmt.Errorf("S3 HEAD %s: %w", key, s3Error(resp))
	}
	mod, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return resp.ContentLength, mod, nil
}

func (s *S3) Stat(digest string) (int64, error) {
	key, err := s.key(digest)
	if err != nil {
		return 0, ErrNotFound
	}
	size, _, err := s.head(key)
	return size, err
}

func (s *S3) Open(digest string) (ReadSeekCloser, int64, error) {
	key, err := s.key(digest)
	if err != nil {
		return nil, 0, ErrNotFound
	}
	size, _, err := s.head(key)
	if err != nil {
		return nil, 0, err
	}
	return &s3Reader{s: s, key: key, size: size}, size, nil
}

// s3Reader reads an object from where it was sought to, asking for the
// rest of it (a range) only when it is read: seeking to the end, as
// http.ServeContent does, asks nothing.
type s3Reader struct {
	s         *S3
	key       string
	size, off int64
	body      io.ReadCloser
}

func (r *s3Reader) Read(p []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	for tries := 0; ; tries++ {
		if r.body == nil {
			h := http.Header{"Range": {"bytes=" + strconv.FormatInt(r.off, 10) + "-"}}
			resp, err := r.s.do(http.MethodGet, r.key, nil, nil, 0, emptySHA256, h)
			if err != nil {
				return 0, err
			}
			if resp.StatusCode != http.StatusPartialContent && !(resp.StatusCode == http.StatusOK && r.off == 0) {
				return 0, fmt.Errorf("S3 GET %s: %w", r.key, s3Error(resp))
			}
			r.body = resp.Body
		}
		n, err := r.body.Read(p)
		r.off += int64(n)
		if err == nil {
			return n, nil
		}
		r.body.Close()
		r.body = nil
		if errors.Is(err, io.EOF) && r.off >= r.size {
			return n, io.EOF
		}
		// Cut off before its end: what came is given, the rest asked for
		// again from there, once or twice.
		if n > 0 {
			return n, nil
		}
		if tries >= 2 {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
	}
}

func (r *s3Reader) Seek(offset int64, whence int) (int64, error) {
	var to int64
	switch whence {
	case io.SeekStart:
		to = offset
	case io.SeekCurrent:
		to = r.off + offset
	case io.SeekEnd:
		to = r.size + offset
	default:
		return r.off, errors.New("bad whence")
	}
	if to < 0 {
		return r.off, errors.New("seeking before the start")
	}
	if to != r.off && r.body != nil {
		r.body.Close()
		r.body = nil
	}
	r.off = to
	return to, nil
}

func (r *s3Reader) Close() error {
	if r.body != nil {
		err := r.body.Close()
		r.body = nil
		return err
	}
	return nil
}

// mark notes that a blob is being stored, which collecting garbage spares.
func (s *S3) mark(digest string) {
	s.placing.Lock()
	defer s.placing.Unlock()
	now := s.now()
	s.recent[digest] = now
	if len(s.recent) > 10000 {
		for d, at := range s.recent {
			if now.Sub(at) > 24*time.Hour {
				delete(s.recent, d)
			}
		}
	}
}

func (s *S3) Put(digest string, b []byte) error {
	if Digest(b) != digest {
		return ErrDigestMismatch
	}
	key, err := s.key(digest)
	if err != nil {
		return err
	}
	s.mark(digest)
	if _, _, err := s.head(key); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.putObject(key, bytes.NewReader(b), int64(len(b)), strings.TrimPrefix(digest, "sha256:"))
}

func (s *S3) putObject(key string, body io.ReadSeeker, size int64, sha string) error {
	resp, err := s.do(http.MethodPut, key, nil, body, size, sha, http.Header{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("S3 PUT %s: %w", key, s3Error(resp))
	}
	resp.Body.Close()
	return nil
}

func (s *S3) Delete(digest string) error {
	key, err := s.key(digest)
	if err != nil {
		return nil
	}
	s.placing.Lock()
	defer s.placing.Unlock()
	return s.deleteObject(key)
}

func (s *S3) deleteObject(key string) error {
	resp, err := s.do(http.MethodDelete, key, nil, nil, 0, emptySHA256, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("S3 DELETE %s: %w", key, s3Error(resp))
	}
	resp.Body.Close()
	return nil
}

func (s *S3) DeleteIf(digest string, before time.Time, keep func() bool) (int64, bool, error) {
	key, err := s.key(digest)
	if err != nil {
		return 0, false, nil
	}
	s.placing.Lock()
	defer s.placing.Unlock()
	if at, ok := s.recent[digest]; ok && !at.Before(before) {
		return 0, false, nil
	}
	size, mod, err := s.head(key)
	if errors.Is(err, ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !mod.Before(before) || keep() {
		return 0, false, nil
	}
	if err := s.deleteObject(key); err != nil {
		return 0, false, err
	}
	return size, true, nil
}

func (s *S3) Walk(fn func(digest string, size int64, modified time.Time) error) error {
	prefix := s.cfg.Prefix + "blobs/sha256/"
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := s.do(http.MethodGet, "", q, nil, 0, emptySHA256, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("S3 listing %s: %w", prefix, s3Error(resp))
		}
		var page struct {
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
			Contents              []struct {
				Key          string    `xml:"Key"`
				Size         int64     `xml:"Size"`
				LastModified time.Time `xml:"LastModified"`
			} `xml:"Contents"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("S3 listing %s: %w", prefix, err)
		}
		for _, c := range page.Contents {
			name := strings.TrimPrefix(c.Key, prefix)
			_, hexPart, ok := strings.Cut(name, "/")
			if !ok || !ValidDigest("sha256:"+hexPart) || name[:2] != hexPart[:2] {
				continue
			}
			if err := fn("sha256:"+hexPart, c.Size, c.LastModified); err != nil {
				return err
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		token = page.NextContinuationToken
	}
}

// The uploads under way are on the disk.

func (s *S3) StartUpload() (string, error) { return s.local.StartUpload() }

func (s *S3) UploadSize(id string) (int64, error) { return s.local.UploadSize(id) }

func (s *S3) Append(id string, offset int64, r io.Reader) (int64, error) {
	return s.local.Append(id, offset, r)
}

func (s *S3) Cancel(id string) error { return s.local.Cancel(id) }

func (s *S3) WalkUploads(fn func(id string, size int64, modified time.Time) error) error {
	return s.local.WalkUploads(fn)
}

// Finish checks an upload as File does, then stores it in the bucket,
// unless the bucket has it already, and drops it from the disk.
func (s *S3) Finish(id, digest string) (int64, error) {
	return s.local.finishWith(id, digest, func(p string, size int64) error {
		key, err := s.key(digest)
		if err != nil {
			return err
		}
		s.mark(digest)
		if _, _, err := s.head(key); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		} else if err != nil {
			if err := s.upload(key, p, size, strings.TrimPrefix(digest, "sha256:")); err != nil {
				return err
			}
		}
		return os.Remove(p)
	})
}

// upload stores a file as an object: in one request, or in parts when it
// is large.
func (s *S3) upload(key, path string, size int64, sha string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if size <= s.partSize {
		return s.putObject(key, io.NewSectionReader(f, 0, size), size, sha)
	}
	resp, err := s.do(http.MethodPost, key, url.Values{"uploads": {""}}, nil, 0, emptySHA256, http.Header{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("S3 starting a multipart upload of %s: %w", key, s3Error(resp))
	}
	var started struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&started)
	resp.Body.Close()
	if err != nil || started.UploadID == "" {
		return fmt.Errorf("S3 starting a multipart upload of %s: no upload ID: %v", key, err)
	}
	abort := func(cause error) error {
		if resp, err := s.do(http.MethodDelete, key, url.Values{"uploadId": {started.UploadID}}, nil, 0, emptySHA256, nil); err == nil {
			resp.Body.Close()
		}
		return cause
	}
	type part struct {
		Number int    `xml:"PartNumber"`
		ETag   string `xml:"ETag"`
	}
	var parts []part
	for n, off := 1, int64(0); off < size; n, off = n+1, off+s.partSize {
		length := min(s.partSize, size-off)
		section := io.NewSectionReader(f, off, length)
		h := sha256.New()
		if _, err := io.Copy(h, section); err != nil {
			return abort(err)
		}
		q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {started.UploadID}}
		resp, err := s.do(http.MethodPut, key, q, section, length, hex.EncodeToString(h.Sum(nil)), nil)
		if err != nil {
			return abort(err)
		}
		if resp.StatusCode != http.StatusOK {
			return abort(fmt.Errorf("S3 part %d of %s: %w", n, key, s3Error(resp)))
		}
		resp.Body.Close()
		parts = append(parts, part{Number: n, ETag: resp.Header.Get("ETag")})
	}
	body, err := xml.Marshal(struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []part   `xml:"Part"`
	}{Parts: parts})
	if err != nil {
		return abort(err)
	}
	resp, err = s.do(http.MethodPost, key, url.Values{"uploadId": {started.UploadID}}, bytes.NewReader(body), int64(len(body)), sha256Hex(body),
		http.Header{"Content-Type": {"application/xml"}})
	if err != nil {
		return abort(err)
	}
	// S3 may answer 200 with an error in the body.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || bytes.Contains(b, []byte("<Error>")) {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return abort(fmt.Errorf("S3 completing %s: %w", key, s3Error(resp)))
	}
	return nil
}

// Check tells whether the bucket can be written and read: it stores a
// small object below the prefix, reads it and deletes it.
func (s *S3) Check() error {
	key := s.cfg.Prefix + ".kartal-check"
	body := []byte("kartal-registry " + s.now().UTC().Format(time.RFC3339) + "\n")
	if err := s.putObject(key, bytes.NewReader(body), int64(len(body)), sha256Hex(body)); err != nil {
		return err
	}
	if _, _, err := s.head(key); err != nil {
		return err
	}
	s.placing.Lock()
	defer s.placing.Unlock()
	return s.deleteObject(key)
}

// Ping tells whether the bucket answers, and the keys may see it; it
// writes nothing, unlike Check.
func (s *S3) Ping() error {
	resp, err := s.do(http.MethodHead, "", nil, nil, 0, emptySHA256, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errors.New("404 NoSuchBucket: the bucket does not exist")
	case http.StatusForbidden:
		return errors.New("403 AccessDenied: the keys may not see the bucket")
	}
	return fmt.Errorf("S3 HEAD of the bucket: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
}
