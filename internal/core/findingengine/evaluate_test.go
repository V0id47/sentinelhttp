package findingengine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/httpclient"
)

func TestEvaluateResponseRulesFromCapturedHTTP(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/weak":
			w.Header().Set("Content-Type", "text/html")
		case "/csp":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Security-Policy", "script-src 'unsafe-inline' 'unsafe-eval'")
		case "/strong":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		case "/not-found":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			return
		case "/unknown":
			w.Header().Set("Content-Type", "not a media type")
		}
		w.WriteHeader(http.StatusOK)
	}))
	check := func(path string, expected []string, excluded []string) {
		t.Helper()
		response, err := client.Do(context.Background(), fixtureTarget(t, base+path), httpclient.GET)
		if err != nil {
			t.Fatal(err)
		}
		report := Evaluate(Input{Exchanges: []*httpclient.Response{response}})
		for _, id := range expected {
			if !hasRule(report, id) {
				t.Fatalf("%s: missing %s: %+v", path, id, report)
			}
		}
		for _, id := range excluded {
			if hasRule(report, id) {
				t.Fatalf("%s: unexpected %s: %+v", path, id, report)
			}
		}
	}
	check("/weak", []string{"headers.nosniff_absent", "csp.no_complete_enforcement"}, []string{"headers.hsts_not_active", "csp.unsafe_inline_observed"})
	check("/csp", []string{"csp.unsafe_inline_observed", "csp.unsafe_eval_observed"}, []string{"csp.no_complete_enforcement"})
	check("/strong", nil, []string{"headers.nosniff_absent", "csp.no_complete_enforcement"})
	check("/not-found", []string{"headers.nosniff_absent"}, nil)
	check("/unknown", nil, []string{"headers.nosniff_absent", "csp.no_complete_enforcement"})
}

func TestEvaluateVerifiedTLSCookieAndHSTS(t *testing.T) {
	base, client := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/accepted" {
			w.Header().Set("Set-Cookie", "session_id=SECRET-cookie-value; SameSite=Lax")
		} else if r.URL.Path == "/rejected" {
			w.Header().Set("Set-Cookie", "session_id=SECRET-cookie-value; SameSite=None")
		} else {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.Header().Set("Set-Cookie", "session_id=SECRET-cookie-value; Secure; HttpOnly; SameSite=Lax")
		}
	}), time.Now().Add(20*24*time.Hour))
	accepted, err := client.Do(context.Background(), fixtureTarget(t, base+"/accepted?token=SECRET-query"), httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	report := Evaluate(Input{Exchanges: []*httpclient.Response{accepted}})
	for _, id := range []string{"headers.hsts_not_active", "cookies.session_like_no_secure", "cookies.session_like_no_httponly", "tls.leaf_expiring_soon"} {
		if !hasRule(report, id) {
			t.Fatalf("missing %s: %+v", id, report)
		}
	}
	if len(report.Findings) != 4 {
		t.Fatalf("unexpected extra findings: %+v", report)
	}
	for _, finding := range report.Findings {
		if finding.Target != fixtureTarget(t, base+"/accepted").SafeURL() {
			t.Fatalf("target not origin-redacted: %s", finding.Target)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET-cookie-value", "SECRET-query", "SECRET-certificate-subject", "session_id"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("finding JSON leaked %q", secret)
		}
	}
	for _, path := range []string{"/rejected", "/strong"} {
		response, err := client.Do(context.Background(), fixtureTarget(t, base+path), httpclient.GET)
		if err != nil {
			t.Fatal(err)
		}
		got := Evaluate(Input{Exchanges: []*httpclient.Response{response}})
		if hasRule(got, "cookies.session_like_no_secure") || hasRule(got, "cookies.session_like_no_httponly") {
			t.Fatalf("rejected/strong cookie became finding: %s %+v", path, got)
		}
	}
}

func TestEvaluateEmptyAndPreheaderFailure(t *testing.T) {
	if got := Evaluate(Input{}); got.EngineVersion != "1" || len(got.Findings) != 0 || got.Truncated {
		t.Fatalf("empty input produced findings: %+v", got)
	}
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	response, err := client.Do(context.Background(), fixtureTarget(t, base+"/SECRET-path"), httpclient.GET)
	if err == nil {
		t.Fatal("expected pre-header failure")
	}
	got := Evaluate(Input{Exchanges: []*httpclient.Response{response}})
	if len(got.Findings) != 0 {
		t.Fatalf("failure generated absence findings: %+v", got)
	}
}
