package httpx

import (
	"compress/gzip"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptsGzip(t *testing.T) {
	cases := map[string]bool{
		"":                      false,
		"gzip":                  true,
		"deflate, gzip;q=0.8":   true,
		"GZIP":                  true,
		"gzip;q=0, deflate":     false,
		"br, gzip ; q=0.0":      false,
		"x-gzip-not-really, br": false,
	}
	for header, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", header)
		if got := AcceptsGzip(r); got != want {
			t.Errorf("AcceptsGzip(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestWriteCompressesLargeBodiesOnly(t *testing.T) {
	large := strings.Repeat(`{"name":"pod"},`, 500)
	for _, c := range []struct {
		body string
		gzip bool
	}{{"small", false}, {large, true}} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		Write(rec, r, 200, "application/json", []byte(c.body))
		if got := rec.Header().Get("Content-Encoding") == "gzip"; got != c.gzip {
			t.Fatalf("len %d: gzip=%v", len(c.body), got)
		}
		body := rec.Body.String()
		if c.gzip {
			zr, err := gzip.NewReader(rec.Body)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(zr)
			body = string(b)
		}
		if body != c.body {
			t.Errorf("body changed on the way (len %d)", len(c.body))
		}
	}
}
