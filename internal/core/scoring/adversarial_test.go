package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/httpclient"
)

func TestEvaluateScoreOutputDoesNotLeakTargetControlledText(t *testing.T) {
	base, client := scoreTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "SECRET-server-banner")
		w.Header().Set("Set-Cookie", "session_id=SECRET-cookie-value; SameSite=Lax")
		w.Header().Set("Content-Security-Policy", "script-src 'unsafe-eval' https://SECRET-csp.test")
		w.WriteHeader(http.StatusOK)
	}), time.Now().Add(20*24*time.Hour))
	response := scoreDo(t, client, base+"/SECRET-path?token=SECRET-query")
	first := Evaluate(response)
	second := Evaluate(response)
	if !reflect.DeepEqual(first, second) || first.Status != ScoreAvailable {
		t.Fatalf("score unstable or unavailable: %+v %+v", first, second)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(encoded), fmt.Sprintf("%v", first), fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", first)} {
		for _, secret := range []string{"SECRET-path", "SECRET-query", "SECRET-cookie-value", "session_id", "SECRET-server-banner", "SECRET-csp.test", "SECRET-certificate-subject"} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("score output leaked %q: %s", secret, rendered)
			}
		}
	}
	first.Limitations[0] = "mutated"
	first.Components[0].Status = ComponentUnavailable
	if again := Evaluate(response); !reflect.DeepEqual(again, second) {
		t.Fatalf("score report shares mutable output state: %+v", again)
	}
}

func TestEvaluatePostHeaderFailureAndTruncatedCSP(t *testing.T) {
	base, client := scoreHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/truncated" {
			w.Header().Set("Content-Security-Policy", "script-src "+strings.Repeat("'self' ", 900))
		} else {
			w.Header().Set("Content-Length", "20")
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("short"))
	}))
	response, err := client.Do(context.Background(), scoreTarget(t, base+"/broken"), httpclient.GET)
	if err == nil {
		t.Fatal("fixture should fail after headers")
	}
	report := Evaluate(response)
	if report.Status != ScoreAvailable || report.Value == nil || *report.Value != 67 {
		t.Fatalf("post-header capture lost eligibility: %+v", report)
	}
	truncated := scoreDo(t, client, base+"/truncated")
	got := Evaluate(truncated)
	if got.Components[3].Status != ComponentUnavailable || got.Value != nil {
		t.Fatalf("truncated CSP was treated as assessed: %+v", got)
	}
}

func TestEvaluateOmittedCSPObservationsSuppressScore(t *testing.T) {
	base, client := scoreHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		for i := 0; i < 15; i++ {
			w.Header().Add("Content-Security-Policy", "default-src *; object-src *; img-src *")
		}
		w.Header().Add("Content-Security-Policy", "default-src *; object-src *, script-src 'unsafe-eval'")
		w.WriteHeader(http.StatusOK)
	}))
	response := scoreDo(t, client, base+"/many-policies")
	csp := response.CSPAnalysis()
	if !csp.Truncated || csp.Enforced.Truncated {
		t.Fatalf("fixture did not hit observation-only cap: %v", csp)
	}
	findings := findingengine.Evaluate(findingengine.Input{Exchanges: []*httpclient.Response{response}})
	if findings.Truncated {
		t.Fatalf("fixture must not rely on finding-engine output cap: %+v", findings)
	}
	report := Evaluate(response)
	if report.Components[3].Status != ComponentUnavailable || report.Value != nil {
		t.Fatalf("omitted CSP observations supported numeric score: report=%+v components=%+v", report, report.Components)
	}
}

func TestEvaluateUnknownMIMEContextDoesNotEarnHeaderDomain(t *testing.T) {
	base, client := scoreTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "not a media type")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
	}), time.Now().Add(60*24*time.Hour))
	report := Evaluate(scoreDo(t, client, base+"/unknown-type"))
	if report.Components[1].Status != ComponentUnavailable || report.Value != nil {
		t.Fatalf("unknown MIME applicability earned header weight: components=%+v score=%+v", report.Components, report)
	}
}

func TestEvaluateTruncatedFindingEvidenceRetainsPrimaryTarget(t *testing.T) {
	base, client := scoreTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for i := 0; i < 30; i++ {
			w.Header().Add("Set-Cookie", fmt.Sprintf("session_id_%d=x; SameSite=Lax", i))
		}
		w.WriteHeader(http.StatusOK)
	}), time.Now().Add(60*24*time.Hour))
	response := scoreDo(t, client, base+"/many-cookies")
	findings := findingengine.Evaluate(findingengine.Input{Exchanges: []*httpclient.Response{response}})
	if !findings.Truncated || findings.OmittedEvidence == 0 {
		t.Fatalf("fixture did not exercise finding evidence cap: %+v", findings)
	}
	report := Evaluate(response)
	if report.Status != ScoreInsufficientEvidence || report.Value != nil || report.Target != response.Metadata().Target {
		t.Fatalf("truncated evidence must retain origin and suppress score: %+v", report)
	}
}
