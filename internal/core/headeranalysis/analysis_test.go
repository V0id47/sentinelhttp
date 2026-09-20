package headeranalysis

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestUnavailableCaptureDoesNotInferMissingHeaders(t *testing.T) {
	r := Analyze(Input{
		Captured: false, Scheme: "https", StatusCode: 200,
		Headers: map[string][]string{"Content-Type": {"private/type"}},
	})
	if r.Capture != CaptureUnavailable || len(r.Results) != 0 || r.Context.MediaType != "" || r.Context.Representation != RepresentationUnknown {
		t.Fatalf("unavailable capture became header conclusions: %+v", r)
	}
}

func TestHeaderLookupIsDeterministicAcrossMixedCaseKeys(t *testing.T) {
	headers := map[string][]string{
		"x-test": {"lower"},
		"X-Test": {"canonical"},
		"X-TEST": {"upper"},
	}
	want := []string{"upper", "canonical", "lower"}
	for i := 0; i < 100; i++ {
		if got := headerValues(headers, "X-Test"); !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d: got %q, want %q", i, got, want)
		}
	}
}

func TestResponseContextControlsApplicability(t *testing.T) {
	for _, tc := range []struct {
		name, contentType string
		status            int
		representation    Representation
		xfo, xcto         Applicability
	}{
		{"html", "text/html; charset=utf-8", 200, RepresentationHTML, Applicable, ApplicabilityUnknown},
		{"json", "application/problem+json", 200, RepresentationJSON, NotApplicable, ApplicabilityUnknown},
		{"redirect", "text/html", 302, RepresentationRedirect, NotApplicable, ApplicabilityUnknown},
		{"no-content", "text/html", 204, RepresentationNoContent, NotApplicable, ApplicabilityUnknown},
		{"not-modified", "text/html", 304, RepresentationNoContent, NotApplicable, ApplicabilityUnknown},
		{"unknown-missing", "", 200, RepresentationUnknown, ApplicabilityUnknown, ApplicabilityUnknown},
		{"unknown-invalid", "not a type", 200, RepresentationUnknown, ApplicabilityUnknown, ApplicabilityUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			if tc.contentType != "" {
				h.Set("Content-Type", tc.contentType)
			}
			r := Analyze(Input{Captured: true, Scheme: "https", TLSVerified: true, StatusCode: tc.status, Headers: h})
			if r.Capture != CaptureComplete || r.Context.Representation != tc.representation {
				t.Fatalf("wrong context: %+v", r.Context)
			}
			if len(r.Results) != len(allHeaderIDs) {
				t.Fatalf("missing deterministic results: %d", len(r.Results))
			}
			if got := mustResult(t, r, XFrameOptions); got.Applicability != tc.xfo || got.Status != StatusAbsent {
				t.Fatalf("wrong XFO result: %+v", got)
			}
			if got := mustResult(t, r, XContentTypeOptions); got.Applicability != tc.xcto || got.Status != StatusAbsent {
				t.Fatalf("wrong XCTO result: %+v", got)
			}
		})
	}
}

func TestRepeatedContentTypeMakesRepresentationUnknown(t *testing.T) {
	h := http.Header{"Content-Type": {"text/html", "application/json"}}
	r := Analyze(Input{Captured: true, Scheme: "https", TLSVerified: true, StatusCode: 200, Headers: h})
	if r.Context.Representation != RepresentationUnknown || r.Context.ContentTypeStatus != ContextAmbiguous || r.Context.MediaType != "" {
		t.Fatalf("multiple Content-Type values were guessed: %+v", r.Context)
	}
}

func TestOversizedContentTypeIsNotRetainedAsContext(t *testing.T) {
	h := http.Header{"Content-Type": {"application/" + strings.Repeat("x", 5000)}}
	r := Analyze(Input{Captured: true, Scheme: "https", TLSVerified: true, StatusCode: 200, Headers: h})
	if r.Context.Representation != RepresentationUnknown || r.Context.ContentTypeStatus != ContextTruncated || r.Context.MediaType != "" {
		t.Fatalf("oversized Content-Type retained or interpreted: %+v", r.Context)
	}
}

func TestSecureContextPoliciesRemainUnknownOnHTTP(t *testing.T) {
	h := http.Header{"Content-Type": {"text/html"}, "Cross-Origin-Opener-Policy": {"same-origin"}, "Cross-Origin-Embedder-Policy": {"require-corp"}}
	r := Analyze(Input{Captured: true, Scheme: "http", StatusCode: 200, Headers: h})
	for _, id := range []HeaderID{CrossOriginOpenerPolicy, CrossOriginEmbedderPolicy} {
		got := mustResult(t, r, id)
		if got.Applicability != ApplicabilityUnknown || got.Status != StatusValid {
			t.Fatalf("HTTP secure-context policy overstated: %+v", got)
		}
	}
}

func mustResult(t *testing.T, r Report, id HeaderID) Result {
	t.Helper()
	got, ok := r.Result(id)
	if !ok {
		t.Fatalf("missing result %s", id)
	}
	return got
}
