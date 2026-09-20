package scoring

import (
	"context"
	"net/http"
	"testing"
	"time"

	"sentinelhttp/internal/core/httpclient"
)

func TestEvaluateHTTPPrimaryStrongAndWeak(t *testing.T) {
	base, client := scoreHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/strong" {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
		}
		w.WriteHeader(http.StatusOK)
	}))
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/strong", 100},
		{"/weak", 67},
	} {
		report := Evaluate(scoreDo(t, client, base+tc.path+"?token=SECRET-query"))
		if report.Status != ScoreAvailable || report.Value == nil || *report.Value != tc.want || report.AssessedWeight != 60 || report.PossibleWeight != 60 {
			t.Fatalf("%s: score=%+v", tc.path, report)
		}
	}
}

func TestEvaluateTLSCookieAndHeaderPenalties(t *testing.T) {
	base, client := scoreTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "session_id=SECRET-cookie; SameSite=Lax")
		w.WriteHeader(http.StatusOK)
	}), time.Now().Add(20*24*time.Hour))
	report := Evaluate(scoreDo(t, client, base+"/path?token=SECRET-query"))
	if report.Status != ScoreAvailable || report.Value == nil || *report.Value != 60 || report.AssessedWeight != 70 || report.PossibleWeight != 100 || report.CoveragePercent != 70 {
		t.Fatalf("TLS/cookie/header score changed: %+v", report)
	}
}

func TestEvaluatePreheaderFailureHasNoNumericScore(t *testing.T) {
	base, client := scoreHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	response, err := client.Do(context.Background(), scoreTarget(t, base+"/broken"), httpclient.GET)
	if err == nil {
		t.Fatal("fixture should fail before headers")
	}
	for _, input := range []*httpclient.Response{nil, response} {
		report := Evaluate(input)
		if report.Status != ScoreInsufficientEvidence || report.Value != nil {
			t.Fatalf("pre-header failure scored: %+v", report)
		}
	}
}
