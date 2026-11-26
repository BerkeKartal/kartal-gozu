package blobstore

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The examples of Amazon S3's documentation of Signature Version 4
// ("Examples: Signature Calculations"), with its example keys.
func TestSignV4AsAmazonsExamples(t *testing.T) {
	const access, secret = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name, method, url, rawPath, payload string
		headers                             map[string]string
		signed, signature                   string
	}{
		{name: "GET object", method: "GET", url: "https://examplebucket.s3.amazonaws.com/test.txt", payload: emptySHA256,
			headers: map[string]string{"Range": "bytes=0-9"},
			signed:  "host;range;x-amz-content-sha256;x-amz-date", signature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"},
		{name: "PUT object", method: "PUT", url: "https://examplebucket.s3.amazonaws.com/test$file.text", rawPath: "/test%24file.text",
			payload: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			headers: map[string]string{"Date": "Fri, 24 May 2013 00:00:00 GMT", "X-Amz-Storage-Class": "REDUCED_REDUNDANCY"},
			signed:  "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class", signature: "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"},
		{name: "GET a bucket's lifecycle", method: "GET", url: "https://examplebucket.s3.amazonaws.com/?lifecycle", payload: emptySHA256,
			signed: "host;x-amz-content-sha256;x-amz-date", signature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
		{name: "list objects", method: "GET", url: "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", payload: emptySHA256,
			signed: "host;x-amz-content-sha256;x-amz-date", signature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"},
	} {
		req, err := http.NewRequest(c.method, c.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.rawPath != "" {
			req.URL.RawPath = c.rawPath
		}
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "not signed")
		signV4(req, access, secret, "us-east-1", "s3", c.payload, at)
		want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=" + c.signed + ", Signature=" + c.signature
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, want)
		}
	}
}

func TestURIEncode(t *testing.T) {
	if got := uriEncode("a b/c~d$é", true); got != "a%20b/c~d%24%C3%A9" {
		t.Errorf("path: %s", got)
	}
	if got := uriEncode("a/b", false); got != "a%2Fb" {
		t.Errorf("query: %s", got)
	}
	q := canonicalQuery(map[string][]string{"a-b": {"1"}, "a": {"2", "1"}, "prefix": {"x/y"}})
	if q != "a=1&a=2&a-b=1&prefix=x%2Fy" || strings.Contains(q, "/") {
		t.Errorf("query %s", q)
	}
}
