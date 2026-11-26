package blobstore

import (
	"net/http"
	"testing"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/blobstore/s3test"
)

// newFakeS3 is the fake S3, which here also checks each request's
// signature as it arrived: signed again, it must be the same.
func newFakeS3(t *testing.T) *s3test.Fake {
	f := s3test.New(t)
	f.Verify = func(r *http.Request) bool {
		at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if err != nil {
			return false
		}
		again := r.Clone(r.Context())
		again.Header.Del("Authorization")
		signV4(again, f.Access, f.Secret, "us-east-1", "s3", r.Header.Get("X-Amz-Content-Sha256"), at)
		return again.Header.Get("Authorization") == r.Header.Get("Authorization")
	}
	return f
}

// fakeStore is an S3 store on the fake, with small parts.
func fakeStore(t *testing.T, f *s3test.Fake, root string) *S3 {
	t.Helper()
	s, err := NewS3(S3Config{Endpoint: f.URL, Bucket: f.Bucket, Prefix: "registry", AccessKey: f.Access, SecretKey: f.Secret,
		PathStyle: true, Staging: root})
	if err != nil {
		t.Fatal(err)
	}
	s.partSize = 1024
	return s
}
