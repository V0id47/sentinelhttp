package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
)

func TestTargetScopeDoesNotRetainRawURL(t *testing.T) {
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	build := func(raw string) Document {
		target, err := network.ParseTarget(raw)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	a := build("https://example.com/login?token=canary")
	b := build("https://example.com/")
	if a.Target != b.Target || a.TargetScope != "redacted" || b.TargetScope != "root" {
		t.Fatalf("scope mismatch: %+v %+v", a, b)
	}
	data, err := json.Marshal(a)
	if err != nil || strings.Contains(string(data), "canary") || strings.Contains(string(data), "/login") {
		t.Fatal("raw request URL leaked into report")
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("scope did not round trip: %v", err)
	}
}

func reportTarget(t *testing.T, raw string) network.Target {
	t.Helper()
	target, err := network.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestBuildSafeVersionedEvidenceDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "session_id=SECRET-cookie-value; SameSite=Lax")
		w.Header().Set("Location", "/SECRET-location?token=SECRET-location-query")
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-SECRET-nonce' 'unsafe-inline'; SECRET-directive 'self'")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SECRET-body"))
	}))
	defer server.Close()
	initial := reportTarget(t, server.URL+"/SECRET-path?token=SECRET-query")
	boundary, err := network.NewBoundary(initial, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), initial, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	input := Input{InitialTarget: initial, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: response, Exchanges: []*httpclient.Response{response}, Config: ScanConfig{AllowPrivate: true, MaxRedirects: 10, TimeoutMillis: 15000, MaxResponseBytes: 2 << 20}}
	first, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(input)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("report assembly changed across identical inputs: %v", err)
	}
	if first.SchemaVersion != "1.0" || first.Tool != "SentinelHTTP" || first.ToolVersion != "0.1.0" || first.Target != initial.SafeURL() || len(first.Requests) != 1 || first.Score.Value == nil {
		t.Fatalf("versioned report shape missing: %+v", first)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET-path", "SECRET-query", "SECRET-location", "SECRET-location-query", "SECRET-cookie-value", "SECRET-body", "SECRET-nonce", "SECRET-directive"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report JSON leaked %q", secret)
		}
	}
	if !strings.Contains(string(encoded), `"schema_version":"1.0"`) || !strings.Contains(string(encoded), `"findings"`) || !strings.Contains(string(encoded), `"cookies"`) {
		t.Fatalf("report schema missing sections: %s", encoded)
	}
	first.Requests[0].Headers[0].Status = "tampered"
	if reflect.DeepEqual(first, second) {
		t.Fatal("report evaluations share output slices")
	}
}

func TestBuildRejectsConflictingOrExcessEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	initial := reportTarget(t, server.URL)
	boundary, err := network.NewBoundary(initial, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	input := Input{InitialTarget: initial, StartedAt: at, CompletedAt: at.Add(time.Second)}
	response, err := client.Do(context.Background(), initial, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	copyOfResponse := *response
	input.Exchanges = []*httpclient.Response{response, &copyOfResponse}
	if _, err := Build(input); err != ErrInvalidInput {
		t.Fatalf("different objects with one exchange ID were accepted: %v", err)
	}
	input.Exchanges = []*httpclient.Response{response}
	input.CompletedAt = at.Add(-time.Second)
	if _, err := Build(input); err != ErrInvalidInput {
		t.Fatalf("reversed timestamps were accepted: %v", err)
	}
	input.CompletedAt = at.Add(time.Second)
	input.Trace = &httpclient.RedirectTrace{Hops: make([]httpclient.RedirectHop, 22)}
	if _, err := Build(input); err != ErrInvalidInput {
		t.Fatalf("overlong trace was accepted: %v", err)
	}
	input.Trace = nil
	input.Exchanges = nil
	for i := 0; i < 33; i++ {
		next, err := client.Do(context.Background(), reportTarget(t, server.URL+"/path"), httpclient.GET)
		if err != nil {
			t.Fatal(err)
		}
		input.Exchanges = append(input.Exchanges, next)
	}
	if _, err := Build(input); err != ErrReportLimit {
		t.Fatalf("more than 32 exchanges were accepted: %v", err)
	}
}

func TestBuildPreservesProbeEvidenceIDsWithoutRequestHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Set-Cookie", "session_id=SECRET-probe-cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target := reportTarget(t, server.URL+"/SECRET-probe-path?token=SECRET-probe-token")
	boundary, err := network.NewBoundary(target, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := client.Do(context.Background(), target, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := client.ProbeCORS(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: primary, CORSProbe: probe, Config: ScanConfig{AllowPrivate: true, CORSProbeEnabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if doc.CORSProbe == nil || len(doc.CORSProbe.Attempts) != 3 {
		t.Fatal("probe attempts missing")
	}
	for _, attempt := range doc.CORSProbe.Attempts {
		if !validReportID(attempt.ID) || attempt.Target != target.SafeURL() {
			t.Fatalf("captured probe has no safe evidence identity: %+v", attempt)
		}
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET-probe-path", "SECRET-probe-token", "SECRET-probe-cookie"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("probe report leaked %q", secret)
		}
	}
}

func TestBuildRejectsUntracedCrossTargetEvidence(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer second.Close()
	initial := reportTarget(t, first.URL)
	other := reportTarget(t, second.URL)
	boundary, err := network.NewBoundary(initial, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), other, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	if _, err := Build(Input{InitialTarget: initial, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: response}); err != ErrInvalidInput {
		t.Fatalf("untraced cross-target primary accepted: %v", err)
	}
	trace := &httpclient.RedirectTrace{Stop: httpclient.RedirectTerminal, Hops: []httpclient.RedirectHop{{Target: other, Response: response}}}
	if _, err := Build(Input{InitialTarget: initial, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: response, Trace: trace}); err != ErrInvalidInput {
		t.Fatalf("trace that never starts at initial target accepted: %v", err)
	}
}

func TestBuildRejectsCallerOwnedProbeCodePayload(t *testing.T) {
	target := reportTarget(t, "https://example.invalid/")
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	probe := &httpclient.CORSProbeResult{}
	probe.Attempts[0].Kind, probe.Attempts[0].Origin, probe.Attempts[0].State = "first_get", "https://sentinelhttp-probe-a.invalid", httpclient.ProbeNotRun
	probe.Attempts[1].Kind, probe.Attempts[1].Origin, probe.Attempts[1].State = "second_get", "https://sentinelhttp-probe-b.invalid", httpclient.ProbeNotRun
	probe.Attempts[2].Kind, probe.Attempts[2].Origin, probe.Attempts[2].State = "preflight", "https://sentinelhttp-probe-a.invalid", httpclient.ProbeNotRun
	probe.Attempts[0].Code = "SECRET-cookie-value"
	if _, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at, CORSProbe: probe, Config: ScanConfig{CORSProbeEnabled: true}}); err != ErrInvalidInput {
		t.Fatalf("caller-owned probe code payload accepted: %v", err)
	}
}

func TestBuildReportsOmittedCookieFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for i := 0; i < 130; i++ {
			w.Header().Add("Set-Cookie", fmt.Sprintf("cookie%d=x", i))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target := reportTarget(t, server.URL)
	boundary, err := network.NewBoundary(target, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), target, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: response})
	if err != nil {
		t.Fatal(err)
	}
	request := doc.Requests[0]
	if !doc.Truncated || !request.CookieTruncated || request.CookieFieldCount != 130 || request.CookieAnalyzedFields != 128 || request.CookieOmittedFields != 2 {
		t.Fatalf("cookie omission not visible in report: %+v", request)
	}
	terminal, err := Render(doc, FormatTerminal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(terminal), "cookie fields=2") {
		t.Fatalf("terminal omitted cookie truncation: %s", terminal)
	}
}
