package corsanalysis

import (
	"net/http"
	"strings"
	"testing"
)

func sample(kind ProbeKind, origin string, status int, headers http.Header) ProbeSample {
	return ProbeSample{Kind: kind, Origin: origin, Captured: true, StatusCode: status,
		Report: Analyze(Input{Captured: true, StatusCode: status, Headers: headers})}
}

func TestAssessProbesReflection(t *testing.T) {
	first := sample(FirstGET, ProbeOriginA, 200, http.Header{
		"Access-Control-Allow-Origin":      {ProbeOriginA},
		"Access-Control-Allow-Credentials": {"true"},
	})
	second := sample(SecondGET, ProbeOriginB, 200, http.Header{
		"Access-Control-Allow-Origin":      {ProbeOriginB},
		"Access-Control-Allow-Credentials": {"true"},
	})
	got := AssessProbes([]ProbeSample{first, second})
	if got.Reflection != ReflectionObserved || !hasProbeObservation(got, ReflectionForSamples, PotentialRisk) {
		t.Fatalf("two credentialed echoes were not classified conservatively: %+v", got)
	}
	second.Report = Analyze(Input{Captured: true, StatusCode: 200, Headers: http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Credentials": {"true"}}})
	got = AssessProbes([]ProbeSample{first, second})
	if got.Reflection == ReflectionObserved || !hasProbeObservation(got, WildcardCredentialsMismatch, Misconfiguration) {
		t.Fatalf("wildcard/ACAC was mistaken for reflection or exposure: %+v", got)
	}
	second.Report = Analyze(Input{Captured: true, StatusCode: 200, Headers: http.Header{"Access-Control-Allow-Origin": {ProbeOriginB, ProbeOriginB}}})
	got = AssessProbes([]ProbeSample{first, second})
	if got.Reflection != ReflectionIndeterminate {
		t.Fatalf("ambiguous ACAO created reflection conclusion: %+v", got)
	}
	second = sample(SecondGET, ProbeOriginB, 302, http.Header{"Access-Control-Allow-Origin": {ProbeOriginB}})
	got = AssessProbes([]ProbeSample{first, second})
	if got.Reflection != ReflectionIndeterminate {
		t.Fatalf("redirect-only evidence created resource reflection conclusion: %+v", got)
	}
}

func TestAssessProbesPreflight(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		headers http.Header
		want    PreflightStatus
	}{
		{"GET safelisted, header allowed", 204, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA}, "Access-Control-Allow-Headers": {"X-SentinelHTTP-Probe"}}, PreflightConsistent},
		{"wildcards without credentials", 200, http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Headers": {"*"}, "Access-Control-Allow-Credentials": {"true"}}, PreflightConsistent},
		{"missing synthetic header", 204, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA}}, PreflightNotObservedAllowed},
		{"403", 403, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA}, "Access-Control-Allow-Headers": {"X-SentinelHTTP-Probe"}}, PreflightNotObservedAllowed},
		{"redirect", 302, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA}, "Access-Control-Allow-Headers": {"X-SentinelHTTP-Probe"}}, PreflightIndeterminate},
		{"not modified is not an ok preflight", 304, http.Header{}, PreflightNotObservedAllowed},
		{"ambiguous ACAO", 204, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA, ProbeOriginA}, "Access-Control-Allow-Headers": {"X-SentinelHTTP-Probe"}}, PreflightIndeterminate},
		{"invalid allow-methods", 204, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA}, "Access-Control-Allow-Headers": {"X-SentinelHTTP-Probe"}, "Access-Control-Allow-Methods": {"GET, BAD METHOD"}}, PreflightIndeterminate},
		{"truncated allow-methods", 204, http.Header{"Access-Control-Allow-Origin": {ProbeOriginA}, "Access-Control-Allow-Headers": {"X-SentinelHTTP-Probe"}, "Access-Control-Allow-Methods": {strings.Repeat("A", 4097)}}, PreflightIndeterminate},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := AssessProbes([]ProbeSample{sample(Preflight, ProbeOriginA, test.status, test.headers)})
			if got.Preflight != test.want {
				t.Fatalf("preflight mismatch: got %s want %s", got.Preflight, test.want)
			}
		})
	}
}

func TestAssessProbesVaryContext(t *testing.T) {
	first := sample(FirstGET, ProbeOriginA, 200, http.Header{
		"Access-Control-Allow-Origin": {ProbeOriginA},
		"Cache-Control":               {"public, max-age=60"},
	})
	second := sample(SecondGET, ProbeOriginB, 200, http.Header{
		"Access-Control-Allow-Origin": {ProbeOriginB},
		"Vary":                        {"Origin"},
	})
	got := AssessProbes([]ProbeSample{first, second})
	if !hasProbeObservation(got, VaryOriginMissing, PotentialRisk) || countProbeObservation(got, VaryOriginMissing) != 1 {
		t.Fatalf("missing Vary on cacheable varying sample not flagged: %+v", got)
	}
	first.Report = Analyze(Input{Captured: true, StatusCode: 200, Headers: http.Header{
		"Access-Control-Allow-Origin": {ProbeOriginA},
		"Vary":                        {"*"},
		"Cache-Control":               {"public, max-age=60"},
	}})
	got = AssessProbes([]ProbeSample{first, second})
	if countProbeObservation(got, VaryOriginMissing) != 0 {
		t.Fatalf("Vary star was ignored: %+v", got)
	}
	first = sample(FirstGET, ProbeOriginA, 200, http.Header{"Access-Control-Allow-Origin": {"*"}})
	second = sample(SecondGET, ProbeOriginB, 200, http.Header{"Access-Control-Allow-Origin": {"*"}})
	got = AssessProbes([]ProbeSample{first, second})
	if countProbeObservation(got, VaryOriginMissing) != 0 {
		t.Fatalf("static wildcard incorrectly required Vary Origin: %+v", got)
	}
}

func hasProbeObservation(a ProbeAssessment, code ObservationCode, level Classification) bool {
	for _, o := range a.Observations {
		if o.Code == code && o.Classification == level {
			return true
		}
	}
	return false
}

func countProbeObservation(a ProbeAssessment, code ObservationCode) int {
	n := 0
	for _, o := range a.Observations {
		if o.Code == code {
			n++
		}
	}
	return n
}
