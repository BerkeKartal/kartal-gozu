// Package s3test is a fake S3 for tests: as much of it as the registry's
// S3 store uses, path-style: objects, ranges, listing in pages, multipart
// uploads. It checks a body against the SHA-256 it was signed with, as S3
// does, and a request's signature with Verify, when set.
package s3test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fake is a fake S3 with one bucket.
type Fake struct {
	*httptest.Server
	Bucket, Access, Secret string
	// Verify checks a request's signature, when set.
	Verify func(r *http.Request) bool

	mu      sync.Mutex
	Objects map[string]Object
	Uploads map[string]map[int][]byte
	nextID  int
	// Page is how many objects a listing gives at once; Fail how many of
	// the next requests fail with 500; Clock what time objects are written
	// at.
	Page  int
	Fail  int
	Clock func() time.Time
	asked []string
}

// Object is an object of the bucket.
type Object struct {
	Data []byte
	Mod  time.Time
}

// New starts a fake S3, closed when the test ends.
func New(t testing.TB) *Fake {
	f := &Fake{Bucket: "kartal", Access: "AKFAKE", Secret: "secret/fake+key", Objects: map[string]Object{}, Uploads: map[string]map[int][]byte{},
		Page: 1000, Clock: time.Now}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// Requests are the requests it was sent, as "METHOD path?query".
func (f *Fake) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// Keys are the objects' keys, sorted.
func (f *Fake) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.Objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Do runs fn with the fake locked, to look at or change its state.
func (f *Fake) Do(fn func(f *Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *Fake) error(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, msg)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	if f.Fail > 0 {
		f.Fail--
		f.error(w, http.StatusInternalServerError, "InternalError", "try again")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+f.Access+"/") || (f.Verify != nil && !f.Verify(r)) {
		f.error(w, http.StatusForbidden, "SignatureDoesNotMatch", "the signature does not match")
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != f.Bucket {
		f.error(w, http.StatusNotFound, "NoSuchBucket", "the bucket does not exist")
		return
	}
	body, _ := io.ReadAll(r.Body)
	if sha := r.Header.Get("X-Amz-Content-Sha256"); sha != "UNSIGNED-PAYLOAD" && sha != sha256Hex(body) {
		f.error(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch", "the body is not what was signed")
		return
	}
	q := r.URL.Query()
	switch {
	case key == "" && r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		f.list(w, q.Get("prefix"), q.Get("continuation-token"))
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.nextID++
		id := "up+" + strconv.Itoa(f.nextID) + "/x="
		f.Uploads[id] = map[int][]byte{}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == http.MethodPut && q.Has("uploadId"):
		parts, ok := f.Uploads[q.Get("uploadId")]
		if !ok {
			f.error(w, http.StatusNotFound, "NoSuchUpload", "no such upload")
			return
		}
		n, _ := strconv.Atoi(q.Get("partNumber"))
		parts[n] = body
		sum := md5.Sum(body)
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	case r.Method == http.MethodPost && q.Has("uploadId"):
		parts, ok := f.Uploads[q.Get("uploadId")]
		if !ok {
			f.error(w, http.StatusNotFound, "NoSuchUpload", "no such upload")
			return
		}
		var done struct {
			Parts []struct {
				Number int    `xml:"PartNumber"`
				ETag   string `xml:"ETag"`
			} `xml:"Part"`
		}
		if err := xml.Unmarshal(body, &done); err != nil || len(done.Parts) == 0 {
			f.error(w, http.StatusBadRequest, "MalformedXML", "the list of parts cannot be read")
			return
		}
		var all []byte
		for i, p := range done.Parts {
			sum := md5.Sum(parts[p.Number])
			if p.Number != i+1 || p.ETag != `"`+hex.EncodeToString(sum[:])+`"` {
				f.error(w, http.StatusBadRequest, "InvalidPart", "a part is not the one uploaded")
				return
			}
			all = append(all, parts[p.Number]...)
		}
		delete(f.Uploads, q.Get("uploadId"))
		f.Objects[key] = Object{Data: all, Mod: f.Clock()}
		fmt.Fprint(w, "<CompleteMultipartUploadResult><Key>"+key+"</Key></CompleteMultipartUploadResult>")
	case r.Method == http.MethodDelete && q.Has("uploadId"):
		delete(f.Uploads, q.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut:
		f.Objects[key] = Object{Data: body, Mod: f.Clock()}
	case r.Method == http.MethodHead || r.Method == http.MethodGet:
		o, ok := f.Objects[key]
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.error(w, http.StatusNotFound, "NoSuchKey", "the key does not exist")
			return
		}
		w.Header().Set("Last-Modified", o.Mod.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(o.Data)))
			return
		}
		http.ServeContent(w, r, "", o.Mod, bytes.NewReader(o.Data))
	case r.Method == http.MethodDelete:
		delete(f.Objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.error(w, http.StatusNotImplemented, "NotImplemented", r.Method)
	}
}

func (f *Fake) list(w http.ResponseWriter, prefix, token string) {
	after := ""
	if token != "" {
		b, _ := base64.StdEncoding.DecodeString(token)
		after = string(b)
	}
	var keys []string
	for k := range f.Objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	truncated := len(keys) > f.Page
	if truncated {
		keys = keys[:f.Page]
	}
	var b strings.Builder
	b.WriteString("<ListBucketResult><IsTruncated>" + strconv.FormatBool(truncated) + "</IsTruncated>")
	if truncated {
		// Tokens with + / = in them, as S3's are.
		b.WriteString("<NextContinuationToken>" + base64.StdEncoding.EncodeToString([]byte(keys[len(keys)-1])) + "</NextContinuationToken>")
	}
	for _, k := range keys {
		o := f.Objects[k]
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>", k, len(o.Data), o.Mod.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	b.WriteString("</ListBucketResult>")
	w.Write([]byte(b.String()))
}
