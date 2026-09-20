package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinelhttp/internal/core/cspanalysis"
)

func TestCSPAnalysisCapturesSeparatePoliciesAndCorrelatesXFO(t *testing.T) {
	const enforced = "default-src https://private-csp-host-canary.test; script-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
	const reportOnly = "default-src 'self'"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", enforced)
		w.Header().Set("Content-Security-Policy-Report-Only", reportOnly)
		w.Header().Set("X-Frame-Options", "DENY")
		fmt.Fprint(w, "<html></html>")
	}))
	defer server.Close()

	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), GET)
	if err != nil {
		t.Fatal(err)
	}
	report := response.CSPAnalysis()
	if report.Capture != cspanalysis.CaptureComplete || len(report.Enforced.Policies) != 1 || len(report.ReportOnly.Policies) != 1 {
		t.Fatalf("CSP capture mismatch: %+v", report)
	}
	if report.Framing.Relation != cspanalysis.CSPOverridesXFO {
		t.Fatalf("XFO correlation mismatch: %+v", report.Framing)
	}
	if report.DocumentApplicability != cspanalysis.Applicable || report.Enforced.Policies[0].Directives[0].Sources[0].Host != "private-csp-host-canary.test" || len(report.Observations) == 0 {
		t.Fatalf("CSP structure was not retained: %+v", report)
	}
	if values := response.HeaderValues("Content-Security-Policy"); len(values) != 1 || values[0] != enforced {
		t.Fatalf("explicit raw header accessor changed: %q", values)
	}

	report.Enforced.Policies[0].Directives[0].Name = "changed"
	report.Enforced.Policies[0].Directives[0].Sources[0].Host = "changed.test"
	report.Observations[0].Code = "changed"
	second := response.CSPAnalysis()
	if second.Enforced.Policies[0].Directives[0].Name == "changed" || second.Enforced.Policies[0].Directives[0].Sources[0].Host == "changed.test" || second.Observations[0].Code == "changed" {
		t.Fatal("CSP analysis accessor aliases retained response")
	}
}

func TestCSPAnalysisIsUnavailableBeforeResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("request sent") }))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), Method("PRIVATE-CANARY"))
	if ErrorCode(err) != MethodRejected || response.CSPAnalysis().Capture != cspanalysis.CaptureUnavailable || len(response.CSPAnalysis().Enforced.Policies) != 0 {
		t.Fatalf("failed exchange inferred CSP absence: %v %+v", err, response.CSPAnalysis())
	}
}

func TestCSPAnalysisSurvivesIncompleteBody(t *testing.T) {
	url, _ := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: frame-ancestors 'self'\r\nContent-Length: 10\r\n\r\nx")
	client := makeClient(t, url, true, Config{})
	response, err := client.Do(context.Background(), parse(t, url), GET)
	if ErrorCode(err) != BodyReadFailed {
		t.Fatal(err)
	}
	report := response.CSPAnalysis()
	if report.Capture != cspanalysis.CaptureComplete || len(report.Enforced.Policies) != 1 || report.Framing.Relation != cspanalysis.CSPOverridesXFO {
		t.Fatalf("captured CSP lost after body failure: %+v", report)
	}
}

func TestCSPAnalysisDoesNotLeakThroughDefaultResponseOutput(t *testing.T) {
	const nonceCanary = "'nonce-UFJJVkFURV9OT05DRV9DQU5BUlk='"
	const hashCanary = "'sha256-UFJJVkFURV9IQVNIX0NBTkFSWQ=='"
	const hostCanary = "private-csp-host-canary.test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "script-src "+nonceCanary+" "+hashCanary+" https://"+hostCanary)
	}))
	defer server.Close()

	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), GET)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(encoded) + fmt.Sprintf("%v %+v %#v", response, response, response)
	for _, canary := range []string{nonceCanary, hashCanary, hostCanary} {
		if strings.Contains(rendered, canary) {
			t.Fatalf("CSP evidence leaked through default response output: %q", canary)
		}
	}
}
