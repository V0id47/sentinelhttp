package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelhttp/internal/core/corsanalysis"
)

func TestProbeCORSFixedRequestsAndHeaderOnly(t *testing.T) {
	type seenRequest struct{ method, origin, requestMethod, requestHeaders, cookie, authorization string }
	var mu sync.Mutex
	var seen []seenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, seenRequest{r.Method, r.Header.Get("Origin"), r.Header.Get("Access-Control-Request-Method"), r.Header.Get("Access-Control-Request-Headers"), r.Header.Get("Cookie"), r.Header.Get("Authorization")})
		mu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "X-SentinelHTTP-Probe")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // A body reader would stall until the batch times out.
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{TotalTimeout: 2 * time.Second})
	started := time.Now()
	result, err := client.ProbeCORS(context.Background(), parse(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("probe waited for response bodies")
	}
	if result.Assessment.Reflection != corsanalysis.ReflectionObserved || result.Assessment.Preflight != corsanalysis.PreflightConsistent {
		t.Fatalf("fixed probe assessment mismatch: %+v", result.Assessment)
	}
	mu.Lock()
	got := append([]seenRequest(nil), seen...)
	mu.Unlock()
	if len(got) != 3 || got[0].method != "GET" || got[0].origin != corsanalysis.ProbeOriginA || got[1].method != "GET" || got[1].origin != corsanalysis.ProbeOriginB || got[2].method != "OPTIONS" || got[2].origin != corsanalysis.ProbeOriginA || got[2].requestMethod != "GET" || got[2].requestHeaders != "X-SentinelHTTP-Probe" {
		t.Fatalf("wrong probe request sequence: %+v", got)
	}
	for i, request := range got {
		if request.cookie != "" || request.authorization != "" || i < 2 && (request.requestMethod != "" || request.requestHeaders != "") {
			t.Fatalf("probe request leaked credentials/preflight headers: %+v", request)
		}
		attempt := result.Attempts[i]
		if attempt.State != ProbeCaptured || attempt.Metadata.RequestAttempts != 1 || attempt.Metadata.ConnectionAttempts != 1 || attempt.Metadata.BytesRead != 0 || attempt.Metadata.BodyComplete || attempt.Code != OK {
			t.Fatalf("probe retained body or bypassed exchange: %+v", attempt)
		}
	}
}

func TestProbeCORSDoesNotFollowRedirects(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits.Add(1) }))
	defer destination.Close()
	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sourceHits.Add(1)
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(302)
	}))
	defer source.Close()
	client := makeClient(t, source.URL, true, Config{})
	result, err := client.ProbeCORS(context.Background(), parse(t, source.URL))
	if err != nil {
		t.Fatal(err)
	}
	if sourceHits.Load() != 3 || destinationHits.Load() != 0 || result.Assessment.Reflection != corsanalysis.ReflectionIndeterminate || result.Assessment.Preflight != corsanalysis.PreflightIndeterminate {
		t.Fatalf("probe followed or misread redirect: source=%d destination=%d assessment=%+v", sourceHits.Load(), destinationHits.Load(), result.Assessment)
	}
}

func TestProbeCORSScopeFailureStopsWithoutNetworkRequest(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	client := makeClient(t, server.URL, false, Config{})
	result, err := client.ProbeCORS(context.Background(), parse(t, server.URL))
	if err == nil || hits.Load() != 0 || result.Attempts[0].State != ProbeFailed || result.Attempts[1].State != ProbeNotRun || result.Attempts[2].State != ProbeNotRun {
		t.Fatalf("scope rejection caused requests or lost partial state: err=%v hits=%d result=%+v", err, hits.Load(), result)
	}
}

func TestProbeCORSSharedDeadlineStopsLaterAttempts(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{TotalTimeout: 50 * time.Millisecond})
	result, err := client.ProbeCORS(context.Background(), parse(t, server.URL))
	if err == nil || hits.Load() != 1 || result.Attempts[0].State != ProbeFailed || result.Attempts[1].State != ProbeNotRun || result.Attempts[2].State != ProbeNotRun {
		t.Fatalf("shared deadline did not stop the batch: err=%v hits=%d result=%+v", err, hits.Load(), result)
	}
}

func TestProbeCORSDoesNotChangeOrdinaryDo(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Origin") != "" || r.Header.Get("Access-Control-Request-Method") != "" {
			t.Fatal("ordinary Do emitted probe headers")
		}
		fmt.Fprint(w, "normal-body")
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), GET)
	if err != nil || hits.Load() != 1 || string(response.Body()) != "normal-body" {
		t.Fatalf("ordinary Do changed: err=%v hits=%d", err, hits.Load())
	}
}
