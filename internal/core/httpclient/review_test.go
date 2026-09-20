package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelhttp/internal/core/network"
)

func TestMalformedRedirectPreservesEvidence(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "http://[invalid%zz")
		w.WriteHeader(302)
		fmt.Fprint(w, "redirect evidence")
	}))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, e := c.Do(context.Background(), parse(t, s.URL), GET)
	if e != nil {
		t.Fatal("valid redirect response discarded", e)
	}
	if r.Metadata().StatusCode != 302 || calls.Load() != 1 || len(r.HeaderValues("Location")) != 1 || string(r.Body()) != "redirect evidence" {
		t.Fatal("redirect evidence lost")
	}
}

func TestRejectedMethodDoesNotLeak(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid method sent") }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, e := c.Do(context.Background(), parse(t, s.URL), Method("SECRET\r\n"))
	if ErrorCode(e) != MethodRejected {
		t.Fatal(e)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "SECRET") {
		t.Fatal("rejected arbitrary method leaked into evidence")
	}
}

func TestMetadataSnapshotIndependence(t *testing.T) {
	r := &Response{meta: Metadata{TLS: &TLSMetadata{ServerName: "localhost"}}}
	r.meta.Resolution.Addresses = append(r.meta.Resolution.Addresses, network.AddressRecord{Normalized: netip.MustParseAddr("127.0.0.1")})
	before, _ := json.Marshal(r)
	m := r.Metadata()
	m.TLS.ServerName = "changed"
	m.Resolution.Addresses[0].Normalized = netip.MustParseAddr("127.0.0.2")
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("caller can mutate retained evidence")
	}
}

func TestNativeTLSRootsFailClosed(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		return
	}
	v := parse(t, "https://127.0.0.1:1")
	c := makeClient(t, v.RequestURL(), true, Config{})
	r, e := c.Do(context.Background(), v, GET)
	if ErrorCode(e) != CABundleRequired || r.Metadata().ConnectionAttempts != 0 || r.Metadata().RequestAttempts != 0 {
		t.Fatal("native roots path was reachable", e)
	}
}

func TestBodyLimitClosesSocket(t *testing.T) {
	closed := make(chan struct{}, 1)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", 8192)) }))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	s.Start()
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{MaxResponseBytes: 16})
	r, e := c.Do(context.Background(), parse(t, s.URL), GET)
	if e != nil || !r.Metadata().BodyTruncated {
		t.Fatal(e)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("truncated response socket not closed")
	}
}

func TestHeaderAccessIsCopyAndMarked(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "first=SECRET")
		w.Header().Add("Set-Cookie", "second=SECRET")
		w.Header().Set("Server", "fixture")
	}))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, e := c.Do(context.Background(), parse(t, s.URL), GET)
	if e != nil {
		t.Fatal(e)
	}
	values := r.HeaderValues("set-cookie")
	values[0] = "changed"
	if r.HeaderValues("SET-COOKIE")[0] != "first=SECRET" {
		t.Fatal("raw accessor aliases internal values")
	}
	info := r.HeaderInfo()
	last := ""
	found := false
	for _, h := range info {
		if h.Name < last {
			t.Fatal("unstable header order")
		}
		last = h.Name
		if h.Name == "Set-Cookie" {
			found = h.Sensitive && h.Count == 2
		}
	}
	if !found {
		t.Fatal("missing sensitivity/count")
	}
}

func TestClosedPortNoRetry(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	url := "http://" + l.Addr().String()
	l.Close()
	c := makeClient(t, url, true, Config{})
	r, e := c.Do(context.Background(), parse(t, url), GET)
	if e == nil || r.Metadata().ConnectionAttempts != 1 || r.Metadata().RequestAttempts != 0 {
		t.Fatal("bad connection failure accounting", e)
	}
}

func TestCancelledTransportLease(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cfg, _, _ := normalize(Config{})
	v := parse(t, "http://example.test")
	tr := singleTransport(a, v, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := tr.DialContext(ctx, "tcp", "example.test:80"); e == nil {
		t.Fatal("cancel ignored")
	}
}
