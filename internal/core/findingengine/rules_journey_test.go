package findingengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/httpclient"
)

func TestCORSFindingUsesRecomputedCapturedSamples(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Headers", "X-SentinelHTTP-Probe")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	probe, err := client.ProbeCORS(context.Background(), fixtureTarget(t, base+"/probe?token=SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	probe.Assessment = corsanalysis.ProbeAssessment{} // The engine must not trust this mutable summary.
	report := Evaluate(Input{CORSProbe: probe})
	for _, id := range []string{"cors.sampled_reflection_with_credentials", "cors.vary_origin_shared_cache"} {
		if !hasRule(report, id) {
			t.Fatalf("missing %s from recomputed samples: %+v", id, report)
		}
	}
	if len(report.Findings) != 2 {
		t.Fatalf("unexpected CORS findings: %+v", report)
	}
	probe.Attempts[1].Metadata.Target = "http://attacker.test/SECRET"
	if got := Evaluate(Input{CORSProbe: probe}); hasRule(got, "cors.sampled_reflection_with_credentials") || hasRule(got, "cors.vary_origin_shared_cache") {
		t.Fatalf("inconsistent probe target produced a finding: %+v", got)
	}
}

func TestCORSFindingRejectsWildcardOnlyAndFabricatedAssessment(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	probe, err := client.ProbeCORS(context.Background(), fixtureTarget(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if got := Evaluate(Input{CORSProbe: probe}); hasRule(got, "cors.sampled_reflection_with_credentials") || hasRule(got, "cors.vary_origin_shared_cache") {
		t.Fatalf("wildcard alone produced a risk finding: %+v", got)
	}
	fake := &httpclient.CORSProbeResult{}
	fake.Assessment.Observations = []corsanalysis.Observation{{Code: corsanalysis.ReflectionForSamples, Classification: corsanalysis.PotentialRisk}}
	if got := Evaluate(Input{CORSProbe: fake}); len(got.Findings) != 0 {
		t.Fatalf("fabricated assessment produced a finding: %+v", got)
	}
}

func TestCORSFindingUnavailableOptionalProbeIsNotSkipped(t *testing.T) {
	probe := &httpclient.CORSProbeResult{}
	probe.Attempts[0] = httpclient.CORSProbeAttempt{Kind: corsanalysis.FirstGET, Origin: corsanalysis.ProbeOriginA, State: httpclient.ProbeFailed}
	probe.Attempts[1] = httpclient.CORSProbeAttempt{Kind: corsanalysis.SecondGET, Origin: corsanalysis.ProbeOriginB, State: httpclient.ProbeNotRun}
	probe.Attempts[2] = httpclient.CORSProbeAttempt{Kind: corsanalysis.Preflight, Origin: corsanalysis.ProbeOriginA, State: httpclient.ProbeNotRun}
	if got := Evaluate(Input{CORSProbe: probe}); got.SkippedInputs != 0 || len(got.Findings) != 0 {
		t.Fatalf("unavailable optional probe was treated as inconsistent: %+v", got)
	}
}

func TestCORSFindingRejectsInconsistentCapturedGET(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	probe, err := client.ProbeCORS(context.Background(), fixtureTarget(t, base))
	if err != nil || !hasRule(Evaluate(Input{CORSProbe: probe}), "cors.sampled_reflection_with_credentials") {
		t.Fatalf("fixture: err=%v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*httpclient.CORSProbeResult)
	}{
		{"wrong_method", func(p *httpclient.CORSProbeResult) { p.Attempts[0].Metadata.Method = httpclient.OPTIONS }},
		{"wrong_result", func(p *httpclient.CORSProbeResult) { p.Attempts[0].Metadata.Result = httpclient.ProtocolError }},
		{"zero_status", func(p *httpclient.CORSProbeResult) {
			p.Attempts[0].Metadata.StatusCode = 0
			p.Attempts[0].Report.StatusCode = 0
		}},
		{"absent_origin_with_stale_value", func(p *httpclient.CORSProbeResult) { p.Attempts[0].Report.Origin.Status = corsanalysis.FieldAbsent }},
		{"invalid_credentials_with_stale_enabled", func(p *httpclient.CORSProbeResult) {
			p.Attempts[0].Report.Credentials.Status = corsanalysis.FieldInvalid
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := *probe
			tc.mutate(&changed)
			got := Evaluate(Input{CORSProbe: &changed})
			if hasRule(got, "cors.sampled_reflection_with_credentials") {
				t.Fatalf("inconsistent sample produced reflection finding: %+v", got)
			}
		})
	}
}

func TestCORSFindingPreservesDifferentCanonicalAllowlistOrigins(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == corsanalysis.ProbeOriginA {
			w.Header().Set("Access-Control-Allow-Origin", "https://allow-a.invalid")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "https://allow-b.invalid")
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	probe, err := client.ProbeCORS(context.Background(), fixtureTarget(t, base))
	if err != nil {
		t.Fatal(err)
	}
	report := Evaluate(Input{CORSProbe: probe})
	if !hasRule(report, "cors.vary_origin_shared_cache") || hasRule(report, "cors.sampled_reflection_with_credentials") {
		t.Fatalf("origin-dependent cache signal lost: %+v", report)
	}
	probe.Attempts[0].Report.Cache.Status = corsanalysis.FieldTruncated
	if got := Evaluate(Input{CORSProbe: probe}); hasRule(got, "cors.vary_origin_shared_cache") {
		t.Fatalf("truncated cache field supported its own evidence: %+v", got)
	}
	probe.Attempts[0].Report.Cache.Status = corsanalysis.FieldValid
	for _, invalid := range []string{"https://allow-a.invalid:443", "https://allow.1"} {
		probe.Attempts[0].Report.Origin.Value = invalid
		if got := Evaluate(Input{CORSProbe: probe}); hasRule(got, "cors.vary_origin_shared_cache") {
			t.Fatalf("noncanonical origin %q supported cache finding: %+v", invalid, got)
		}
	}
}

func TestRedirectFindingFromBlockedDowngrade(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits.Add(1) }))
	defer destination.Close()
	base, client := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL+"/SECRET-target")
		w.WriteHeader(http.StatusFound)
	}), time.Now().Add(60*24*time.Hour))
	trace, err := client.TraceRedirects(context.Background(), fixtureTarget(t, base+"/start?token=SECRET"), httpclient.RedirectOptions{})
	if err != nil || trace.Stop != httpclient.RedirectDowngradeBlocked || destinationHits.Load() != 0 {
		t.Fatalf("fixture failed: trace=%+v err=%v hits=%d", trace, err, destinationHits.Load())
	}
	report := Evaluate(Input{Trace: trace})
	if !hasRule(report, "redirects.https_to_http_proposed") || hasRule(report, "redirects.loop_or_limit") {
		t.Fatalf("downgrade not classified: %+v", report)
	}
}

func TestRedirectFindingLoopAndLimitOnly(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loop" {
			w.Header().Set("Location", "/loop")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/next" {
			w.Header().Set("Location", "/end")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	for _, tc := range []struct {
		path string
		opts httpclient.RedirectOptions
		stop httpclient.RedirectStop
		want bool
	}{
		{"/loop", httpclient.RedirectOptions{}, httpclient.RedirectLoop, true},
		{"/start", httpclient.RedirectOptions{MaxRedirects: 1}, httpclient.RedirectLimit, true},
		{"/end", httpclient.RedirectOptions{}, httpclient.RedirectTerminal, false},
	} {
		trace, err := client.TraceRedirects(context.Background(), fixtureTarget(t, base+tc.path), tc.opts)
		if err != nil || trace.Stop != tc.stop {
			t.Fatalf("fixture %s: trace=%+v err=%v", tc.path, trace, err)
		}
		if got := hasRule(Evaluate(Input{Trace: trace}), "redirects.loop_or_limit"); got != tc.want {
			t.Fatalf("path %s: loop/limit finding=%t, want %t", tc.path, got, tc.want)
		}
	}
}
