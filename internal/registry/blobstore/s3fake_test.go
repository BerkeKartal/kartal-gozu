package blobstore

import (
	"bytes"
	"crypto/md5"
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

// fakeS3 is as much of S3 as the store uses, path-style: objects, ranges,
// listing in pages, multipart uploads. It checks each request's signature
// as it arrived, and a body against the SHA-256 it was signed with, as S3
// does.
type fakeS3 struct {
	*httptest.Server
	bucket, access, secret string

	mu      sync.Mutex
	objects map[string]fakeObject
	uploads map[string]map[int][]byte
	nextID  int
	// page is how many objects a listing gives at once; fail how many of
	// the next requests fail with 500.
	page  int
	fail  int
	asked []string
	clock func() time.Time
}

type fakeObject struct {
	data []byte
	mod  time.Time
}

func newFakeS3(t *testing.T) *fakeS3 {
	f := &fakeS3{bucket: "kartal", access: "AKFAKE", secret: "secret/fake+key", objects: map[string]fakeObject{}, uploads: map[string]map[int][]byte{},
		page: 1000, clock: time.Now}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeS3) error(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, msg)
}

// signedRight signs the request again as it arrived, and compares.
func (f *fakeS3) signedRight(r *http.Request) bool {
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return false
	}
	again := r.Clone(r.Context())
	again.Header.Del("Authorization")
	signV4(again, f.access, f.secret, "us-east-1", "s3", r.Header.Get("X-Amz-Content-Sha256"), at)
	return again.Header.Get("Authorization") == r.Header.Get("Authorization")
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	if f.fail > 0 {
		f.fail--
		f.error(w, http.StatusInternalServerError, "InternalError", "try again")
		return
	}
	if !f.signedRight(r) {
		f.error(w, http.StatusForbidden, "SignatureDoesNotMatch", "the signature does not match")
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != f.bucket {
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
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		f.list(w, q)
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.nextID++
		id := "up+" + strconv.Itoa(f.nextID) + "/x="
		f.uploads[id] = map[int][]byte{}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == http.MethodPut && q.Has("uploadId"):
		parts, ok := f.uploads[q.Get("uploadId")]
		if !ok {
			f.error(w, http.StatusNotFound, "NoSuchUpload", "no such upload")
			return
		}
		n, _ := strconv.Atoi(q.Get("partNumber"))
		parts[n] = body
		sum := md5.Sum(body)
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	case r.Method == http.MethodPost && q.Has("uploadId"):
		parts, ok := f.uploads[q.Get("uploadId")]
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
		delete(f.uploads, q.Get("uploadId"))
		f.objects[key] = fakeObject{data: all, mod: f.clock()}
		fmt.Fprint(w, "<CompleteMultipartUploadResult><Key>"+key+"</Key></CompleteMultipartUploadResult>")
	case r.Method == http.MethodDelete && q.Has("uploadId"):
		delete(f.uploads, q.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut:
		f.objects[key] = fakeObject{data: body, mod: f.clock()}
	case r.Method == http.MethodHead || r.Method == http.MethodGet:
		o, ok := f.objects[key]
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.error(w, http.StatusNotFound, "NoSuchKey", "the key does not exist")
			return
		}
		w.Header().Set("Last-Modified", o.mod.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
			return
		}
		http.ServeContent(w, r, "", o.mod, bytes.NewReader(o.data))
	case r.Method == http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.error(w, http.StatusNotImplemented, "NotImplemented", r.Method)
	}
}

func (f *fakeS3) list(w http.ResponseWriter, q map[string][]string) {
	prefix := ""
	if v := q["prefix"]; len(v) > 0 {
		prefix = v[0]
	}
	after := ""
	if v := q["continuation-token"]; len(v) > 0 {
		b, _ := base64.StdEncoding.DecodeString(v[0])
		after = string(b)
	}
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	truncated := len(keys) > f.page
	if truncated {
		keys = keys[:f.page]
	}
	var b strings.Builder
	b.WriteString("<ListBucketResult><IsTruncated>" + strconv.FormatBool(truncated) + "</IsTruncated>")
	if truncated {
		// Tokens with + / = in them, as S3's are.
		b.WriteString("<NextContinuationToken>" + base64.StdEncoding.EncodeToString([]byte(keys[len(keys)-1])) + "</NextContinuationToken>")
	}
	for _, k := range keys {
		o := f.objects[k]
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>", k, len(o.data), o.mod.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	b.WriteString("</ListBucketResult>")
	w.Write([]byte(b.String()))
}

func (f *fakeS3) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// store is an S3 store on the fake, with small parts.
func (f *fakeS3) store(t *testing.T, root string) *S3 {
	t.Helper()
	s, err := NewS3(S3Config{Endpoint: f.URL, Bucket: f.bucket, Prefix: "registry", AccessKey: f.access, SecretKey: f.secret,
		PathStyle: true, Staging: root})
	if err != nil {
		t.Fatal(err)
	}
	s.partSize = 1024
	return s
}
