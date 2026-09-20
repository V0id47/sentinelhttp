package httpclient

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func rawServer(t *testing.T, reply string) (string, *atomic.Int32) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var count atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, e := l.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			br := bufio.NewReader(conn)
			for {
				line, e := br.ReadString('\n')
				if e != nil || line == "\r\n" {
					break
				}
			}
			_, _ = io.WriteString(conn, reply)
			conn.Close()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	return "http://" + l.Addr().String(), &count
}

func TestMalformedHTTPAndPartialBodies(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		code       Code
		status     int
	}{
		{"bad-status", "SECRET nonsense\r\n\r\n", ProtocolError, 0},
		{"bad-header", "HTTP/1.1 200 OK\r\nBad@Header: SECRET\r\n\r\n", ProtocolError, 0},
		{"oversized", "HTTP/1.1 200 OK\r\nX-Huge: " + strings.Repeat("x", 4096) + "\r\n\r\n", HeaderLimit, 0},
		{"huge-length", "HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\nx", BodyReadFailed, 200},
		{"abrupt", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx", BodyReadFailed, 200},
		{"http10", "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", OK, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, count := rawServer(t, tc.wire)
			c := makeClient(t, url, true, Config{MaxResponseHeaderBytes: 1024})
			r, e := c.Do(context.Background(), parse(t, url+"/?token=SECRET"), GET)
			if ErrorCode(e) != tc.code {
				t.Fatalf("got %v want %s", e, tc.code)
			}
			if r.Metadata().StatusCode != tc.status || count.Load() != 1 {
				t.Fatal("bad status or retried")
			}
			if e != nil && strings.Contains(fmt.Sprintf("%v %+v %#v", e, e, e), "SECRET") {
				t.Fatal("error leaked")
			}
			if tc.code == BodyReadFailed && (r.Metadata().BodyComplete || r.Metadata().BytesRead != 1) {
				t.Fatal("partial body misrepresented")
			}
		})
	}
}

func TestSingleTransportCannotDialOrReuse(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	target := parse(t, "http://example.test:8080")
	cfg, _, _ := normalize(Config{})
	tr := singleTransport(a, target, cfg)
	if tr.Proxy != nil || !tr.DisableCompression || !tr.DisableKeepAlives || tr.Protocols.HTTP2() || tr.ForceAttemptHTTP2 {
		t.Fatal("unsafe transport defaults")
	}
	if _, e := tr.DialContext(context.Background(), "tcp", "127.0.0.1:8080"); e == nil {
		t.Fatal("address mismatch accepted")
	}
	if _, e := tr.DialTLSContext(context.Background(), "tcp", "example.test:8080"); e == nil {
		t.Fatal("alternate TLS path")
	}
	if _, e := tr.DialContext(context.Background(), "tcp", "example.test:8080"); e != nil {
		t.Fatal(e)
	}
	if _, e := tr.DialContext(context.Background(), "tcp", "example.test:8080"); e == nil {
		t.Fatal("reuse")
	}
}

func TestCancelDuringBody(t *testing.T) {
	ready := make(chan struct{})
	closed := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		close(ready)
		<-r.Context().Done()
		close(closed)
	}))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-ready; cancel() }()
	r, e := c.Do(ctx, parse(t, s.URL), GET)
	if ErrorCode(e) != Cancelled || r.Metadata().BodyComplete {
		t.Fatal("cancel not propagated", e)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("socket not closed")
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := l.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	url := "https://" + l.Addr().String()
	_, ca := labCertificate(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	c := makeClient(t, url, true, Config{TLSHandshakeTimeout: 30 * time.Millisecond, LabCAPEM: ca})
	_, e = c.Do(context.Background(), parse(t, url), GET)
	if ErrorCode(e) != TLSHandshakeTimeout {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS socket leaked")
	}
}

func TestConcurrentHTTP(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	target := parse(t, s.URL)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := c.Do(context.Background(), target, GET)
			if e != nil || string(r.Body()) != "ok" {
				t.Error("concurrent failure", e)
			}
		}()
	}
	wg.Wait()
}

func TestConfigBounds(t *testing.T) {
	for _, cfg := range []Config{{MaxResponseBytes: -1}, {MaxResponseBytes: (8 << 20) + 1}, {MaxResponseHeaderBytes: 127}, {MaxResponseHeaderBytes: (128 << 10) + 1}, {TLSHandshakeTimeout: -1}, {TLSHandshakeTimeout: 11 * time.Second}, {ResponseHeaderTimeout: -1}, {ResponseHeaderTimeout: 31 * time.Second}, {TotalTimeout: -1}, {TotalTimeout: 61 * time.Second}, {LabCAPEM: []byte("SECRET invalid")}, {LabCAPEM: make([]byte, (1<<20)+1)}} {
		if _, _, e := normalize(cfg); e == nil {
			t.Fatal("invalid config allowed")
		}
	}
	if _, e := New(nil, Config{}); e == nil {
		t.Fatal("nil boundary")
	}
}

func FuzzSensitiveHeader(f *testing.F) {
	for _, s := range []string{"Set-Cookie", "Authorization", "X-API-Key", "Server", "Cookie"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if IsSensitiveHeader(strings.ToLower(s)) != IsSensitiveHeader(strings.ToUpper(s)) {
			t.Fatal("case-sensitive redaction")
		}
	})
}
