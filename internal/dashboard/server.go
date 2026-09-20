// Package dashboard serves one validated report over a fixed local HTTP API.
// It never scans, opens report paths, or makes outbound requests.
package dashboard

import (
	"context"
	"embed"
	"errors"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"sentinelhttp/internal/core/diffing"
	"sentinelhttp/internal/core/reporting"
)

var ErrInvalidReport = errors.New("dashboard_report_invalid")
var ErrListen = errors.New("dashboard_listen_failed")
var ErrServe = errors.New("dashboard_serve_failed")

//go:embed static
var staticAssets embed.FS

type Server struct {
	listener net.Listener
	http     *http.Server
	url      string
	report   []byte
	diff     []byte
	index    []byte
}

// New validates and snapshots the report before opening a loopback listener.
func New(doc reporting.Document) (*Server, error) {
	return newServer(doc, nil)
}

// NewWithBaseline computes a pure semantic diff before opening the listener.
// Both reports come from the CLI's bounded, validated file ingress.
func NewWithBaseline(current, baseline reporting.Document) (*Server, error) {
	result, err := diffing.Compare(baseline, current)
	if err != nil {
		return nil, ErrInvalidReport
	}
	data, err := diffing.Render(result, diffing.FormatJSON)
	if err != nil {
		return nil, ErrInvalidReport
	}
	return newServer(current, data)
}

func newServer(doc reporting.Document, diff []byte) (*Server, error) {
	data, err := reporting.Render(doc, reporting.FormatJSON)
	if err != nil {
		return nil, ErrInvalidReport
	}
	index, err := staticAssets.ReadFile("static/index.html")
	if err != nil {
		return nil, ErrServe
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, ErrListen
	}
	port := listener.Addr().(*net.TCPAddr).Port
	server := &Server{listener: listener, url: "http://127.0.0.1:" + strconv.Itoa(port), report: data, diff: diff, index: index}
	server.http = &http.Server{
		Handler:           http.HandlerFunc(server.handle),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	return server, nil
}

func (s *Server) URL() string { return s.url }

func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return ErrServe
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.http.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := s.http.Serve(s.listener)
	close(done)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return ErrServe
	}
	return nil
}

func (s *Server) Close() error { return s.http.Close() }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.Host != s.listener.Addr().String() || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.url {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/api/report":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(s.report)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(s.report)
		}
	case "/api/diff":
		if s.diff == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(s.diff)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(s.diff)
		}
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(s.index)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(s.index)
		}
	default:
		if !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/assets/")
		if !validAssetName(name) {
			http.NotFound(w, r)
			return
		}
		asset, err := staticAssets.ReadFile("static/assets/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch path.Ext(name) {
		case ".js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(asset)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(asset)
		}
	}
}

func validAssetName(name string) bool {
	if name == "" || len(name) > 128 || strings.Contains(name, "..") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
