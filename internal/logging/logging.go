// Package logging sets up structured JSON logs and request logging.
package logging

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func New(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Requests logs every request. Routine agent traffic is logged at debug level
// so a busy fleet does not flood the log; errors are always visible.
func Requests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case rec.status >= 400:
			level = slog.LevelWarn
		case strings.Contains(r.URL.Path, "/agent/v1/") || strings.HasSuffix(r.URL.Path, "/healthz"):
			level = slog.LevelDebug
		}
		log.Log(r.Context(), level, "request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "took", time.Since(start).Round(time.Millisecond))
	})
}
