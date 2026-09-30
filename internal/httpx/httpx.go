// Package httpx holds small HTTP helpers shared by the API and the UI.
package httpx

import (
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// minGzip is the smallest body worth compressing.
const minGzip = 1024

var gzipPool = sync.Pool{New: func() any {
	w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
	return w
}}

// AcceptsGzip reports whether the client takes gzip-encoded responses.
func AcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		if q, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(q), 64); err == nil && f == 0 {
				return false
			}
		}
		return true
	}
	return false
}

// Write sends body with the given status, gzip-compressed when the client
// accepts it and the body is large enough to gain from it.
func Write(w http.ResponseWriter, r *http.Request, status int, contentType string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Vary", "Accept-Encoding")
	if len(body) < minGzip || !AcceptsGzip(r) {
		h.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		w.Write(body)
		return
	}
	h.Set("Content-Encoding", "gzip")
	h.Del("Content-Length")
	w.WriteHeader(status)
	zw := gzipPool.Get().(*gzip.Writer)
	zw.Reset(w)
	zw.Write(body)
	zw.Close()
	gzipPool.Put(zw)
}
