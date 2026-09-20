package httpclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/redirectanalysis"
)

func TestTraceRedirectsFollowStatusesAndFragmentLoop(t *testing.T) {
	for _, status := range []int{303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method: %s", r.Method)
				}
				if r.URL.Path == "/start" {
					w.Header().Set("Location", "/final#not-sent")
					w.WriteHeader(status)
					return
				}
				if r.RequestURI != "/final" {
					t.Errorf("fragment leaked into request: %q", r.RequestURI)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := makeClient(t, server.URL, true, Config{})
			trace, err := client.TraceRedirects(context.Background(), parse(t, server.URL+"/start"), RedirectOptions{})
			if err != nil || trace.Stop != RedirectTerminal || hits.Load() != 2 || trace.RedirectsFollowed != 1 || trace.Hops[0].NextTarget.RequestURL() != server.URL+"/final" {
				t.Fatalf("status %d follow failed: trace=%+v err=%v", status, trace, err)
			}
		})
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "#fragment-only")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	trace, err := client.TraceRedirects(context.Background(), parse(t, server.URL+"/start"), RedirectOptions{})
	if err != nil || trace.Stop != RedirectLoop || hits.Load() != 1 || trace.Hops[0].LocationStatus != redirectanalysis.LocationValid {
		t.Fatalf("fragment-only reference should be an exact request loop: trace=%+v err=%v", trace, err)
	}
}

func TestTraceRedirectsSameHostAllowsDifferentPort(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		w.Header().Set("Location", destination.URL+"/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()
	client := makeClient(t, source.URL, true, Config{})
	trace, err := client.TraceRedirects(context.Background(), parse(t, source.URL+"/start"), RedirectOptions{SameHost: true})
	if err != nil || trace.Stop != RedirectTerminal || sourceHits.Load() != 1 || destinationHits.Load() != 1 || trace.RedirectsFollowed != 1 || len(trace.Observations) != 0 {
		t.Fatalf("same-host policy should permit another approved port: trace=%+v err=%v", trace, err)
	}
}

func TestTraceRedirectsSafetyStops(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		locations     []string
		second        string
		limit         int
		want          RedirectStop
		wantHits      int32
		wantResponses int
	}{
		{"self loop", 302, []string{"/start"}, "", 0, RedirectLoop, 1, 1},
		{"two node loop", 302, []string{"/next"}, "/start", 0, RedirectLoop, 2, 2},
		{"limit", 302, []string{"/next"}, "/final", 1, RedirectLimit, 2, 2},
		{"missing", 302, nil, "", 0, RedirectLocationMissing, 1, 1},
		{"duplicate", 302, []string{"/a", "/b"}, "", 0, RedirectLocationAmbiguous, 1, 1},
		{"malformed", 302, []string{"http://[invalid"}, "", 0, RedirectLocationInvalid, 1, 1},
		{"unsupported scheme", 302, []string{"ftp://other.invalid/"}, "", 0, RedirectTargetInvalid, 1, 1},
		{"oversized", 302, []string{strings.Repeat("a", 8193)}, "", 0, RedirectLocationInvalid, 1, 1},
		{"not modified", 304, []string{"/next"}, "", 0, RedirectTerminal, 1, 1},
		{"multiple choices", 300, []string{"/next"}, "", 0, RedirectTerminal, 1, 1},
		{"use proxy", 305, []string{"/next"}, "", 0, RedirectTerminal, 1, 1},
		{"unused", 306, []string{"/next"}, "", 0, RedirectTerminal, 1, 1},
		{"comma is URL data", 302, []string{"/next?x=a,b"}, "", 0, RedirectTerminal, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/start" {
					for _, location := range tc.locations {
						w.Header().Add("Location", location)
					}
					w.WriteHeader(tc.status)
					return
				}
				if tc.second != "" && r.URL.Path == "/next" {
					w.Header().Set("Location", tc.second)
					w.WriteHeader(302)
					return
				}
				w.WriteHeader(200)
			}))
			defer server.Close()
			client := makeClient(t, server.URL, true, Config{})
			trace, err := client.TraceRedirects(context.Background(), parse(t, server.URL+"/start"), RedirectOptions{MaxRedirects: tc.limit})
			if err != nil || trace.Stop != tc.want || hits.Load() != tc.wantHits || trace.Responses != tc.wantResponses {
				t.Fatalf("stop=%s hits=%d responses=%d err=%v, want %s/%d/%d", trace.Stop, hits.Load(), trace.Responses, err, tc.want, tc.wantHits, tc.wantResponses)
			}
			if tc.name == "unsupported scheme" && trace.Hops[0].LocationStatus != redirectanalysis.LocationValid {
				t.Fatalf("syntactically valid Location should retain its classification: %s", trace.Hops[0].LocationStatus)
			}
		})
	}
}

func TestTraceRedirectsSafetyOptionsAndScope(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", strings.Replace("http://localhost:PORT/next", "PORT", r.Host[strings.LastIndexByte(r.Host, ':')+1:], 1))
		w.WriteHeader(302)
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	initial := parse(t, server.URL+"/start")
	for _, limit := range []int{-1, 21} {
		trace, err := client.TraceRedirects(context.Background(), initial, RedirectOptions{MaxRedirects: limit})
		if ErrorCode(err) != ConfigInvalid || len(trace.Hops) != 0 || hits.Load() != 0 {
			t.Fatalf("invalid redirect limit caused traffic: %d %+v %v", limit, trace, err)
		}
	}
	trace, err := client.TraceRedirects(context.Background(), initial, RedirectOptions{SameHost: true})
	if err != nil || trace.Stop != RedirectSameHostBlocked || len(trace.Hops) != 1 || hits.Load() != 1 || len(trace.Observations) == 0 || trace.Observations[0].Code != RedirectCrossHost {
		t.Fatalf("same-host restriction failed: trace=%+v err=%v hits=%d", trace, err, hits.Load())
	}
	trace, err = client.TraceRedirects(context.Background(), initial, RedirectOptions{})
	if ErrorCode(err) != Code(network.HostChanged) || trace.Stop != RedirectRequestFailed || len(trace.Hops) != 2 || trace.Responses != 1 || hits.Load() != 2 || trace.Hops[1].Response.Metadata().ConnectionAttempts != 0 {
		t.Fatalf("boundary did not reject cross-host redirect: trace=%+v err=%v hits=%d", trace, err, hits.Load())
	}
}

func TestTraceRedirectsSafetyBlocksDowngrade(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits.Add(1) }))
	defer destination.Close()
	cert, ca := labCertificate(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	var sourceHits atomic.Int32
	source := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(302)
	}))
	source.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	source.StartTLS()
	defer source.Close()
	initialURL := strings.Replace(source.URL, "127.0.0.1", "localhost", 1)
	client := makeClient(t, initialURL, true, Config{LabCAPEM: ca})
	trace, err := client.TraceRedirects(context.Background(), parse(t, initialURL), RedirectOptions{})
	if err != nil || trace.Stop != RedirectDowngradeBlocked || sourceHits.Load() != 1 || destinationHits.Load() != 0 || len(trace.Hops) != 1 || trace.Hops[0].Response.Metadata().TLS == nil || !trace.Hops[0].Response.Metadata().TLS.Verified {
		t.Fatalf("HTTPS downgrade was not blocked before connection: trace=%+v err=%v", trace, err)
	}
}

func TestTraceRedirectsSafetyNoBodyRead(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/stall")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{TotalTimeout: 2 * time.Second})
	started := time.Now()
	trace, err := client.TraceRedirects(context.Background(), parse(t, server.URL+"/start"), RedirectOptions{})
	if err != nil || trace.Stop != RedirectTerminal || hits.Load() != 2 || time.Since(started) > time.Second || trace.Hops[1].Response.Metadata().BytesRead != 0 || len(trace.Hops[1].Response.Body()) != 0 {
		t.Fatalf("header-only journey waited for body: trace=%+v err=%v elapsed=%s", trace, err, time.Since(started))
	}
}

func TestTraceRedirectsSafetyCallerDeadline(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/stall")
			w.WriteHeader(302)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{TotalTimeout: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	started := time.Now()
	trace, err := client.TraceRedirects(ctx, parse(t, server.URL+"/start"), RedirectOptions{})
	if err == nil || trace.Stop != RedirectRequestFailed || len(trace.Hops) != 2 || trace.Responses != 1 || hits.Load() != 2 || time.Since(started) > time.Second || ErrorCode(err) != Timeout && ErrorCode(err) != HeaderTimeout {
		t.Fatalf("caller deadline did not stop later hop: trace=%+v err=%v elapsed=%s", trace, err, time.Since(started))
	}
}

func TestTraceRedirectsSafetyNoProxy(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits.Add(1) }))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(302)
		}
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	trace, err := client.TraceRedirects(context.Background(), parse(t, server.URL+"/start"), RedirectOptions{})
	if err != nil || trace.Stop != RedirectTerminal || hits.Load() != 2 || proxyHits.Load() != 0 {
		t.Fatalf("proxy used during redirect journey: trace=%+v err=%v source=%d proxy=%d", trace, err, hits.Load(), proxyHits.Load())
	}
}
