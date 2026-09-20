package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"sentinelhttp/internal/core/redirectanalysis"
)

func TestTraceRedirectsChainAndExistingDo(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("redirect journey sent wrong method or credentials")
		}
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "../middle?token=SECRET")
			w.WriteHeader(301)
		case "/middle":
			w.Header().Set("Location", "/final?token=SECRET")
			w.WriteHeader(302)
		case "/final":
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
		fmt.Fprint(w, "body-SECRET")
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	initial := parse(t, server.URL+"/start?token=SECRET")
	trace, err := client.TraceRedirects(context.Background(), initial, RedirectOptions{})
	if err != nil || trace == nil || trace.Stop != RedirectTerminal || len(trace.Hops) != 3 || trace.Responses != 3 || trace.RedirectsFollowed != 2 {
		t.Fatalf("wrong redirect chain: trace=%+v err=%v", trace, err)
	}
	if hits.Load() != 3 {
		t.Fatalf("expected exactly three requests, got %d", hits.Load())
	}
	for i, status := range []int{301, 302, 200} {
		hop := trace.Hops[i]
		if hop.Response == nil || hop.Response.Metadata().StatusCode != status || !hop.Response.Metadata().Peer.Verified || hop.Response.Metadata().Protocol != "HTTP/1.1" || hop.Response.Metadata().BytesRead != 0 || hop.Response.Metadata().BodyComplete || len(hop.Response.Body()) != 0 {
			t.Fatalf("incomplete or body-reading hop %d: %+v", i, hop)
		}
	}
	if trace.Hops[0].LocationStatus != redirectanalysis.LocationValid || trace.Hops[1].LocationStatus != redirectanalysis.LocationValid || trace.Hops[2].LocationStatus != redirectanalysis.LocationNotApplicable {
		t.Fatal("location status lost")
	}
	if trace.Hops[0].NextTarget.Host() != initial.Host() || !strings.Contains(trace.Hops[0].NextTarget.RequestURL(), "/middle?token=SECRET") {
		t.Fatal("relative Location resolved incorrectly")
	}
	if trace.Hops[2].Response.HeaderAnalysis().Capture == "" {
		t.Fatal("existing header analysis not captured")
	}
	ordinary, err := client.Do(context.Background(), initial, GET)
	if err != nil || ordinary.Metadata().StatusCode != 301 || hits.Load() != 4 {
		t.Fatal("ordinary Do no longer performs exactly one exchange", err)
	}
}

func TestTraceRedirectsPrivacy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/next?token=SECRET")
		w.WriteHeader(302)
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	trace, err := client.TraceRedirects(context.Background(), parse(t, server.URL+"/start?token=SECRET"), RedirectOptions{MaxRedirects: 1})
	if err != nil || trace == nil {
		t.Fatal(err)
	}
	if len(trace.Hops[0].Response.HeaderValues("Location")) != 1 {
		t.Fatal("explicit raw Location accessor lost")
	}
	b, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(b), fmt.Sprintf("%v", trace), fmt.Sprintf("%+v", trace), fmt.Sprintf("%#v", trace), fmt.Sprintf("%+v", trace.Hops[0])} {
		if strings.Contains(rendered, "SECRET") {
			t.Fatalf("default trace output leaked URL/Location: %q", rendered)
		}
	}
}
