package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelhttp/internal/core/network"
)

func parse(t *testing.T, s string) network.Target {
	t.Helper()
	v, e := network.ParseTarget(s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func makeClient(t *testing.T, url string, lab bool, cfg Config) *Client {
	t.Helper()
	b, e := network.NewBoundary(parse(t, url), network.Policy{AllowPrivate: lab})
	if e != nil {
		t.Fatal(e)
	}
	c, e := New(b, cfg)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestHTTPExchange(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.UserAgent() != UserAgent || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("wrong request headers")
		}
		if r.URL.Fragment != "" {
			t.Error("fragment sent")
		}
		w.Header().Add("Set-Cookie", "a=SECRET; Secure")
		w.Header().Add("Set-Cookie", "b=SECRET; HttpOnly")
		w.Header().Set("X-API-Key", "SECRET")
		w.Header().Set("Location", "/reset?token=SECRET")
		w.Header().Set("Server", "<script>SECRET</script>")
		switch r.URL.Path {
		case "/not-found":
			w.WriteHeader(404)
		case "/error":
			w.WriteHeader(500)
		}
		fmt.Fprint(w, "SECRET")
	}))
	defer server.Close()
	c := makeClient(t, server.URL, true, Config{})
	for _, tc := range []struct {
		path   string
		status int
	}{{"/ok?token=SECRET#fragment", 200}, {"/not-found", 404}, {"/error", 500}} {
		t.Run(tc.path, func(t *testing.T) {
			r, e := c.Do(context.Background(), parse(t, server.URL+tc.path), GET)
			if e != nil {
				t.Fatal(e)
			}
			m := r.Metadata()
			if m.StatusCode != tc.status || m.Protocol != "HTTP/1.1" || !m.Peer.Verified || m.ConnectionAttempts != 1 || m.RequestAttempts != 1 || m.ID == "" {
				t.Fatalf("bad metadata %+v", m)
			}
			if len(r.HeaderValues("set-cookie")) != 2 || !IsSensitiveHeader("SET-cookie") {
				t.Fatal("lost repeated/sensitive headers")
			}
			if string(r.Body()) != "SECRET" {
				t.Fatal("body missing")
			}
			b, _ := json.Marshal(r)
			for _, s := range []string{string(b), fmt.Sprintf("%v", r), fmt.Sprintf("%+v", *r), fmt.Sprintf("%#v", r)} {
				if strings.Contains(s, "SECRET") {
					t.Fatal("default output leaked raw response")
				}
			}
			r.DiscardBody()
			if len(r.Body()) != 0 {
				t.Fatal("body not discarded")
			}
		})
	}
	if count.Load() != 3 {
		t.Fatal("unexpected requests")
	}
}

func TestHostAndRequestSemantics(t *testing.T) {
	observed := make(chan [3]string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed <- [3]string{r.Host, r.RequestURI, r.Method} }))
	defer server.Close()
	url := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	c := makeClient(t, url, true, Config{})
	v := parse(t, url+"/app/login?token=SECRET#fragment")
	_, e := c.Do(context.Background(), v, HEAD)
	if e != nil {
		t.Fatal(e)
	}
	got := <-observed
	if got[0] != v.Authority() || got[1] != "/app/login?token=SECRET" || got[2] != "HEAD" {
		t.Fatalf("wrong host/path/method %v", got)
	}
}

func TestScopeAndRedirect(t *testing.T) {
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer destination.Close()
	var sourceHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(302)
	}))
	defer server.Close()
	blocked := makeClient(t, server.URL, false, Config{})
	r, e := blocked.Do(context.Background(), parse(t, server.URL), GET)
	if e == nil || r.Metadata().ConnectionAttempts != 0 || sourceHits.Load() != 0 {
		t.Fatal("scope bypass")
	}
	c := makeClient(t, server.URL, true, Config{})
	r, e = c.Do(context.Background(), parse(t, server.URL), GET)
	if e != nil {
		t.Fatal(e)
	}
	if r.Metadata().StatusCode != 302 || len(r.HeaderValues("Location")) != 1 || hits.Load() != 0 || sourceHits.Load() != 1 {
		t.Fatal("redirect followed")
	}
}

func TestEnvironmentProxyIgnored(t *testing.T) {
	var hits atomic.Int32
	p := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer p.Close()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, p.URL)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, e := c.Do(context.Background(), parse(t, s.URL), GET)
	if e != nil || string(r.Body()) != "ok" || hits.Load() != 0 {
		t.Fatal("proxy used", e)
	}
}

func TestBodyLimits(t *testing.T) {
	for _, size := range []int{0, 15, 16, 17, 1024} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%v", size, chunked), func(t *testing.T) {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if chunked {
						w.(http.Flusher).Flush()
					}
					fmt.Fprint(w, strings.Repeat("x", size))
				}))
				defer s.Close()
				c := makeClient(t, s.URL, true, Config{MaxResponseBytes: 16})
				r, e := c.Do(context.Background(), parse(t, s.URL), GET)
				if e != nil {
					t.Fatal(e)
				}
				m := r.Metadata()
				if len(r.Body()) > 16 || m.BodyTruncated != (size > 16) || m.BytesRead != int64(min(size, 17)) {
					t.Fatalf("bad bound %+v", m)
				}
			})
		}
	}
}

func TestNoReuseAndMethods(t *testing.T) {
	observed := make(chan string, 16)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed <- r.RemoteAddr }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	v := parse(t, s.URL)
	ids := map[string]bool{}
	for _, m := range []Method{GET, HEAD, OPTIONS} {
		r, e := c.Do(context.Background(), v, m)
		if e != nil {
			t.Fatal(e)
		}
		id := r.Metadata().ID
		if ids[id] {
			t.Fatal("duplicate id")
		}
		ids[id] = true
	}
	peers := []string{<-observed, <-observed, <-observed}
	if peers[0] == peers[1] || peers[1] == peers[2] {
		t.Fatal("reused connection")
	}
	for _, m := range []Method{"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "get", "GET\r\nX:a", ""} {
		_, e := c.Do(context.Background(), v, m)
		if ErrorCode(e) != MethodRejected {
			t.Fatal("arbitrary method accepted", e)
		}
	}
	if len(observed) != 0 {
		t.Fatal("invalid method made request")
	}
}

func TestSlowResponses(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprint(body), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body {
					w.(http.Flusher).Flush()
					fmt.Fprint(w, "x")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer s.Close()
			cfg := Config{TotalTimeout: 200 * time.Millisecond, ResponseHeaderTimeout: 30 * time.Millisecond}
			if body {
				cfg.TotalTimeout = 50 * time.Millisecond
			}
			c := makeClient(t, s.URL, true, cfg)
			r, e := c.Do(context.Background(), parse(t, s.URL), GET)
			if e == nil {
				t.Fatal("timeout missing")
			}
			if body && r.Metadata().StatusCode != 200 {
				t.Fatal("lost partial headers")
			}
			if r.Metadata().Duration > time.Second {
				t.Fatal("unbounded operation")
			}
		})
	}
}

func TestCancelled(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e := c.Do(ctx, parse(t, s.URL+"/?SECRET=x"), GET)
	if ErrorCode(e) != Cancelled || r.Metadata().ConnectionAttempts != 0 {
		t.Fatal(e)
	}
}

func TestCompressedBytesNotExpanded(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not actually gzip")
	}))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, e := c.Do(context.Background(), parse(t, s.URL), GET)
	if e != nil || string(r.Body()) != "not actually gzip" {
		t.Fatal("decompressed", e)
	}
}
