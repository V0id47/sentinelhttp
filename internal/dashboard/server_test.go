package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/diffing"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/reporting"
)

func fixtureDocument(t *testing.T) reporting.Document {
	t.Helper()
	target, err := network.ParseTarget("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	doc, err := reporting.Build(reporting.Input{InitialTarget: target, StartedAt: at, CompletedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestServerLoopbackAndFixedRoutes(t *testing.T) {
	server, err := New(fixtureDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !strings.HasPrefix(server.URL(), "http://127.0.0.1:") {
		t.Fatalf("not a loopback URL: %s", server.URL())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	request := func(method, path, host, origin string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	good := request(http.MethodGet, "/api/report", "", "")
	data, err := io.ReadAll(good.Body)
	good.Body.Close()
	if err != nil || good.StatusCode != http.StatusOK {
		t.Fatalf("report API: %d %v", good.StatusCode, err)
	}
	if _, err := reporting.Parse(data); err != nil {
		t.Fatalf("API returned invalid report: %v", err)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Cache-Control", "X-Frame-Options", "Referrer-Policy"} {
		if good.Header.Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}
	if good.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unnecessary CORS grant")
	}
	index := request(http.MethodGet, "/", "", "")
	indexData, err := io.ReadAll(index.Body)
	index.Body.Close()
	if err != nil || index.StatusCode != http.StatusOK || !strings.Contains(string(indexData), "id=\"root\"") || strings.Contains(string(indexData), "https://") {
		t.Fatalf("bundled index invalid: %d %v", index.StatusCode, err)
	}
	if strings.Contains(index.Header.Get("Content-Security-Policy"), "unsafe-inline") || strings.Contains(index.Header.Get("Content-Security-Policy"), "unsafe-eval") {
		t.Fatal("frontend CSP permits inline execution")
	}
	assetPaths := regexp.MustCompile(`/assets/[A-Za-z0-9._-]+\.(?:js|css)`).FindAllString(string(indexData), -1)
	if len(assetPaths) < 2 {
		t.Fatalf("bundled JS/CSS missing: %q", indexData)
	}
	for _, assetPath := range assetPaths {
		asset := request(http.MethodGet, assetPath, "", "")
		body, err := io.ReadAll(asset.Body)
		asset.Body.Close()
		if err != nil || asset.StatusCode != http.StatusOK || len(body) == 0 || asset.Header.Get("Content-Type") == "" {
			t.Fatalf("asset %q not served: %d %v", assetPath, asset.StatusCode, err)
		}
	}
	for _, tc := range []struct {
		method, path, host, origin string
		want                       int
	}{
		{http.MethodPost, "/api/report", "", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/private/file", "", "", http.StatusNotFound},
		{http.MethodGet, "/api/diff", "", "", http.StatusNotFound},
		{http.MethodGet, "/api/report?file=C:/secret", "", "", http.StatusNotFound},
		{http.MethodGet, "/assets/../server.go", "", "", http.StatusNotFound},
		{http.MethodGet, "/assets/%2e%2e/server.go", "", "", http.StatusNotFound},
		{http.MethodGet, "/assets/%2fapi%2freport", "", "", http.StatusNotFound},
		{http.MethodGet, "/assets/%5cserver.go", "", "", http.StatusNotFound},
		{http.MethodGet, "//api/report", "", "", http.StatusNotFound},
		{http.MethodGet, "/api/report", "attacker.example", "", http.StatusForbidden},
		{http.MethodGet, "/api/report", "localhost", "", http.StatusForbidden},
		{http.MethodGet, "/api/report", "", "https://attacker.example", http.StatusForbidden},
		{http.MethodGet, "/api/report", "", "null", http.StatusForbidden},
		{http.MethodGet, "/api/report", "", "http://127.0.0.1:1", http.StatusForbidden},
	} {
		resp := request(tc.method, tc.path, tc.host, tc.origin)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s %s: got %d want %d", tc.method, tc.path, resp.StatusCode, tc.want)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop on cancellation")
	}
}

func TestServerServesPrecomputedBaselineDiff(t *testing.T) {
	doc := fixtureDocument(t)
	server, err := NewWithBaseline(doc, doc)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(server.URL() + "/api/diff")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var result diffing.Result
	err = json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || result.Status != diffing.StatusPartial || len(result.Changes) != 0 {
		t.Fatalf("diff API failed: %d %v %+v", resp.StatusCode, err, result)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectsInvalidDocument(t *testing.T) {
	if _, err := New(reporting.Document{}); err == nil {
		t.Fatal("invalid document was served")
	}
}
