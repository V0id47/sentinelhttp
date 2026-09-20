package findingengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/httpclient"
)

func TestEvaluateDeterministicOwnedAndBounded(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "SECRET-server-banner")
		w.Header().Set("Content-Security-Policy", "script-src 'unsafe-eval' https://SECRET-csp.test")
		w.WriteHeader(http.StatusOK)
	}))
	var responses []*httpclient.Response
	for i := 0; i < 33; i++ {
		response, err := client.Do(context.Background(), fixtureTarget(t, fmt.Sprintf("%s/path%d?token=SECRET-query", base, i)), httpclient.GET)
		if err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	first := Evaluate(Input{Exchanges: responses[:2]})
	second := Evaluate(Input{Exchanges: []*httpclient.Response{responses[1], responses[0]}})
	if !reflect.DeepEqual(first, second) || !hasRule(first, "csp.unsafe_eval_observed") {
		t.Fatalf("order changed findings: first=%+v second=%+v", first, second)
	}
	before, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	responses[0].DiscardBody()
	after, err := json.Marshal(first)
	if err != nil || string(after) != string(before) {
		t.Fatal("finding report shared mutable response state", err)
	}
	for _, rendered := range []string{string(before), fmt.Sprintf("%v", first), fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", first), fmt.Sprintf("%+v", first.Findings[0])} {
		for _, secret := range []string{"SECRET-query", "SECRET-server-banner", "SECRET-csp.test"} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("finding output leaked %q: %s", secret, rendered)
			}
		}
	}
	bounded := Evaluate(Input{Exchanges: responses})
	if !bounded.Truncated || bounded.OmittedInputs != 1 || len(bounded.Findings) == 0 {
		t.Fatalf("32-response cap not recorded: %+v", bounded)
	}
	tooManyPositions := make([]*httpclient.Response, 257)
	for i := range tooManyPositions {
		tooManyPositions[i] = responses[0]
	}
	if got := Evaluate(Input{Exchanges: tooManyPositions}); !got.Truncated || got.OmittedInputs != 1 {
		t.Fatalf("inspection cap not recorded: %+v", got)
	}
	if got := Evaluate(Input{Exchanges: []*httpclient.Response{nil}}); got.SkippedInputs != 1 || len(got.Findings) != 0 {
		t.Fatalf("nil input not counted safely: %+v", got)
	}
}

func TestRedirectFindingRejectsTamperedNextTarget(t *testing.T) {
	base, client := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/next")
		} else {
			w.Header().Set("Location", "/final")
		}
		w.WriteHeader(http.StatusFound)
	}), time.Now().Add(60*24*time.Hour))
	trace, err := client.TraceRedirects(context.Background(), fixtureTarget(t, base+"/start"), httpclient.RedirectOptions{MaxRedirects: 1})
	if err != nil || trace.Stop != httpclient.RedirectLimit {
		t.Fatalf("fixture failed: trace=%+v err=%v", trace, err)
	}
	trace.Stop = httpclient.RedirectDowngradeBlocked
	trace.Hops[len(trace.Hops)-1].NextTarget = fixtureTarget(t, "http://localhost:8080/SECRET-fake-target")
	if got := Evaluate(Input{Trace: trace}); hasRule(got, "redirects.https_to_http_proposed") || got.SkippedInputs == 0 {
		t.Fatalf("tampered next target was trusted or not counted: %+v", got)
	}
}

func TestEvaluateReportOnlyCSPAndPostHeaderFailure(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy-Report-Only", "script-src 'unsafe-inline' 'unsafe-eval'")
		w.Header().Set("Content-Length", "20")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("short"))
	}))
	response, err := client.Do(context.Background(), fixtureTarget(t, base+"/broken-body"), httpclient.GET)
	if err == nil {
		t.Fatal("fixture should fail after capturing headers")
	}
	report := Evaluate(Input{Exchanges: []*httpclient.Response{response}})
	if !hasRule(report, "csp.no_complete_enforcement") || !hasRule(report, "headers.nosniff_absent") || hasRule(report, "csp.unsafe_inline_observed") || hasRule(report, "csp.unsafe_eval_observed") {
		t.Fatalf("post-header evidence or report-only distinction lost: %+v", report)
	}
}

func TestEvaluateOverlongCallerTraceSuppressesStopFinding(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/same")
		w.WriteHeader(http.StatusFound)
	}))
	trace, err := client.TraceRedirects(context.Background(), fixtureTarget(t, base+"/same"), httpclient.RedirectOptions{})
	if err != nil || trace.Stop != httpclient.RedirectLoop {
		t.Fatalf("fixture failed: trace=%+v err=%v", trace, err)
	}
	for len(trace.Hops) <= 21 {
		trace.Hops = append(trace.Hops, trace.Hops[0])
	}
	report := Evaluate(Input{Trace: trace})
	if !report.Truncated || report.OmittedInputs != 1 || hasRule(report, "redirects.loop_or_limit") {
		t.Fatalf("overlong trace supported an unsupported stop finding: %+v", report)
	}
}

func TestEvaluateOmittedTraceHopCannotSupportStopFinding(t *testing.T) {
	base, client := httpFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/same")
		w.WriteHeader(http.StatusFound)
	}))
	var exchanges []*httpclient.Response
	for i := 0; i < maxDistinctExchanges; i++ {
		response, err := client.Do(context.Background(), fixtureTarget(t, fmt.Sprintf("%s/exchange-%d", base, i)), httpclient.GET)
		if err != nil {
			t.Fatal(err)
		}
		exchanges = append(exchanges, response)
	}
	trace, err := client.TraceRedirects(context.Background(), fixtureTarget(t, base+"/same"), httpclient.RedirectOptions{})
	if err != nil || trace.Stop != httpclient.RedirectLoop {
		t.Fatalf("fixture: trace=%+v err=%v", trace, err)
	}
	report := Evaluate(Input{Exchanges: exchanges, Trace: trace})
	if !report.Truncated || report.OmittedInputs == 0 || hasRule(report, "redirects.loop_or_limit") {
		t.Fatalf("omitted terminal hop supported stop finding: %+v", report)
	}
}
