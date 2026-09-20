package headeranalysis

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestHSTSUsesFirstFieldAndSecureDNSContext(t *testing.T) {
	r := analyzeHTML(http.Header{"Strict-Transport-Security": {"max-age=31536000; includeSubDomains; preload; future", "max-age=0"}})
	got := mustResult(t, r, StrictTransportSecurity)
	if got.Status != StatusValid || got.Effective != "active" || got.Occurrences != 2 || !reflect.DeepEqual(got.Tokens, []string{"max-age=31536000", "includeSubDomains", "preload"}) {
		t.Fatalf("wrong first-field HSTS semantics: %+v", got)
	}

	for _, tc := range []struct {
		name, value, scheme string
		isIP                bool
		wantStatus          ResultStatus
		wantEffective       string
		wantApplicability   Applicability
	}{
		{"disable", "max-age=0; includeSubDomains", "https", false, StatusValid, "inactive", Applicable},
		{"http-ignored", "max-age=10", "http", false, StatusIgnored, "", NotApplicable},
		{"ip-ignored", "max-age=10", "https", true, StatusIgnored, "", NotApplicable},
		{"missing-max-age", "includeSubDomains", "https", false, StatusInvalid, "", Applicable},
		{"duplicate-max-age", "max-age=1; MAX-AGE=2", "https", false, StatusInvalid, "", Applicable},
		{"bad-max-age", "max-age=-1", "https", false, StatusInvalid, "", Applicable},
		{"bad-include-subdomains", "max-age=1; includeSubDomains=yes", "https", false, StatusInvalid, "", Applicable},
		{"numeric-extension-token", "max-age=1; 1future=123", "https", false, StatusValid, "active", Applicable},
		{"quoted-max-age", `max-age="31536000"`, "https", false, StatusValid, "active", Applicable},
		{"empty-quoted-max-age", `max-age=""`, "https", false, StatusInvalid, "", Applicable},
		{"quoted-extension-semicolon", `max-age=1; future="a;b"`, "https", false, StatusValid, "active", Applicable},
		{"duplicate-extension", "max-age=1; future=yes; FUTURE=no", "https", false, StatusInvalid, "", Applicable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Strict-Transport-Security": {tc.value}, "Content-Type": {"text/html"}}
			out := Analyze(Input{Captured: true, Scheme: tc.scheme, TLSVerified: tc.scheme == "https", HostIsIP: tc.isIP, StatusCode: 200, Headers: h})
			got := mustResult(t, out, StrictTransportSecurity)
			if got.Status != tc.wantStatus || got.Effective != tc.wantEffective || got.Applicability != tc.wantApplicability {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestSimplePolicyHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		values       []string
		id           HeaderID
		status       ResultStatus
		effective    string
	}{
		{"xcto", "X-Content-Type-Options", []string{"NoSnIfF"}, XContentTypeOptions, StatusValid, "nosniff"},
		{"xcto-effective-but-nonconforming", "X-Content-Type-Options", []string{"nosniff, sniff"}, XContentTypeOptions, StatusInvalid, "nosniff"},
		{"xcto-invalid", "X-Content-Type-Options", []string{"sniff"}, XContentTypeOptions, StatusInvalid, ""},
		{"xfo-deny", "X-Frame-Options", []string{"deny"}, XFrameOptions, StatusValid, "DENY"},
		{"xfo-sameorigin", "X-Frame-Options", []string{"SAMEORIGIN"}, XFrameOptions, StatusValid, "SAMEORIGIN"},
		{"xfo-obsolete", "X-Frame-Options", []string{"ALLOW-FROM https://example.test"}, XFrameOptions, StatusInvalid, ""},
		{"xfo-duplicate-same", "X-Frame-Options", []string{"SAMEORIGIN", "SAMEORIGIN"}, XFrameOptions, StatusValid, "SAMEORIGIN"},
		{"xfo-conflict", "X-Frame-Options", []string{"DENY", "SAMEORIGIN"}, XFrameOptions, StatusAmbiguous, "DENY"},
		{"xfo-valid-plus-invalid", "X-Frame-Options", []string{"SAMEORIGIN", "INVALID"}, XFrameOptions, StatusAmbiguous, "DENY"},
		{"xfo-invalid-set", "X-Frame-Options", []string{"INVALID", "OTHER"}, XFrameOptions, StatusInvalid, ""},
		{"coop", "Cross-Origin-Opener-Policy", []string{"same-origin; report-to=\"private\""}, CrossOriginOpenerPolicy, StatusValid, "same-origin"},
		{"coop-extension-parameters", "Cross-Origin-Opener-Policy", []string{`same-origin; future=?1; count=1; ratio=1.2; when=@1659578233; bytes=:YQ==:; label="a;b"; flag`}, CrossOriginOpenerPolicy, StatusValid, "same-origin"},
		{"coop-unknown", "Cross-Origin-Opener-Policy", []string{"future"}, CrossOriginOpenerPolicy, StatusUnrecognized, "unsafe-none"},
		{"coop-list-invalid", "Cross-Origin-Opener-Policy", []string{"same-origin, same-origin"}, CrossOriginOpenerPolicy, StatusInvalid, "unsafe-none"},
		{"corp", "Cross-Origin-Resource-Policy", []string{"same-site"}, CrossOriginResourcePolicy, StatusValid, "same-site"},
		{"corp-case-sensitive", "Cross-Origin-Resource-Policy", []string{"Same-Site"}, CrossOriginResourcePolicy, StatusInvalid, ""},
		{"corp-duplicate", "Cross-Origin-Resource-Policy", []string{"same-site", "same-site"}, CrossOriginResourcePolicy, StatusInvalid, ""},
		{"coep", "Cross-Origin-Embedder-Policy", []string{"credentialless"}, CrossOriginEmbedderPolicy, StatusValid, "credentialless"},
		{"coep-duplicate-fails-open", "Cross-Origin-Embedder-Policy", []string{"require-corp", "require-corp"}, CrossOriginEmbedderPolicy, StatusInvalid, "unsafe-none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := analyzeHTML(http.Header{tc.header: tc.values})
			got := mustResult(t, r, tc.id)
			if got.Status != tc.status || got.Effective != tc.effective {
				t.Fatalf("wrong result: %+v", got)
			}
		})
	}
}

func TestValidHTABWhitespaceDoesNotSuppressSemantics(t *testing.T) {
	for _, tc := range []struct {
		header, value string
		id            HeaderID
		status        ResultStatus
		effective     string
	}{
		{"X-Content-Type-Options", "nosniff,\tsniff", XContentTypeOptions, StatusInvalid, "nosniff"},
		{"Referrer-Policy", "origin,\tno-referrer", ReferrerPolicy, StatusValid, "no-referrer"},
		{"Strict-Transport-Security", "max-age=1;\tincludeSubDomains", StrictTransportSecurity, StatusValid, "active"},
	} {
		r := analyzeHTML(http.Header{tc.header: {tc.value}})
		got := mustResult(t, r, tc.id)
		if got.Status != tc.status || got.Effective != tc.effective {
			t.Fatalf("%s: valid HTAB suppressed semantics: %+v", tc.header, got)
		}
		if retained := r.Values(tc.id); len(retained) != 1 || strings.ContainsRune(retained[0], '\t') {
			t.Fatalf("%s: explicit evidence was not sanitized: %q", tc.header, retained)
		}
	}

	r := analyzeHTML(http.Header{"X-Content-Type-Options": {"nosniff,\x00sniff"}})
	if got := mustResult(t, r, XContentTypeOptions); got.Status != StatusInvalid || got.Effective != "" {
		t.Fatalf("unsafe control produced semantics: %+v", got)
	}
}

func TestReferrerPolicyUsesLastRecognizedToken(t *testing.T) {
	for _, tc := range []struct {
		value, effective string
		status           ResultStatus
	}{
		{"origin, future-policy, strict-origin-when-cross-origin", "strict-origin-when-cross-origin", StatusValid},
		{"future-policy", "", StatusUnrecognized},
		{"no-referrer,", "no-referrer", StatusValid},
		{"", "", StatusInvalid},
	} {
		r := analyzeHTML(http.Header{"Referrer-Policy": {tc.value}})
		got := mustResult(t, r, ReferrerPolicy)
		if got.Status != tc.status || got.Effective != tc.effective {
			t.Fatalf("%q: %+v", tc.value, got)
		}
	}
}

func TestPermissionsPolicyStructuralParsing(t *testing.T) {
	r := analyzeHTML(http.Header{"Permissions-Policy": {`geolocation=(self "https://example.test"), camera=()`}})
	got := mustResult(t, r, PermissionsPolicy)
	want := []Directive{
		{Name: "geolocation", Status: StatusValid, Items: []DirectiveItem{{Kind: DirectiveToken, Value: "self"}, {Kind: DirectiveString, Value: "https://example.test"}}},
		{Name: "camera", Status: StatusValid},
	}
	if got.Status != StatusValid || !reflect.DeepEqual(got.Tokens, []string{"geolocation", "camera"}) || !reflect.DeepEqual(got.Directives, want) {
		t.Fatalf("valid policy lost: %+v", got)
	}

	r = analyzeHTML(http.Header{"Permissions-Policy": {`camera=(self), camera=();report-to="endpoint"`}})
	got = mustResult(t, r, PermissionsPolicy)
	want = []Directive{{Name: "camera", Status: StatusValid, Repeated: true, ReportToStatus: StatusValid}}
	if got.Status != StatusValid || !reflect.DeepEqual(got.Directives, want) || !reflect.DeepEqual(got.Tokens, []string{"camera"}) {
		t.Fatalf("last repeated dictionary member did not win: %+v", got)
	}

	r = analyzeHTML(http.Header{"Permissions-Policy": {`camera=self;report-to="end;point";future=?1;count=1, microphone=*, geolocation="https://example.test"`}})
	got = mustResult(t, r, PermissionsPolicy)
	want = []Directive{
		{Name: "camera", Status: StatusValid, Items: []DirectiveItem{{Kind: DirectiveToken, Value: "self"}}, ReportToStatus: StatusValid},
		{Name: "microphone", Status: StatusValid, Items: []DirectiveItem{{Kind: DirectiveToken, Value: "*"}}},
		{Name: "geolocation", Status: StatusValid, Items: []DirectiveItem{{Kind: DirectiveString, Value: "https://example.test"}}},
	}
	if got.Status != StatusValid || !reflect.DeepEqual(got.Directives, want) {
		t.Fatalf("direct member values or typed items lost: %+v", got)
	}

	r = analyzeHTML(http.Header{"Permissions-Policy": {`camera=(self ?1 123 "https://example.test" "not a source"), microphone=?1, geolocation=self;report-to=?0`}})
	got = mustResult(t, r, PermissionsPolicy)
	want = []Directive{
		{Name: "camera", Status: StatusValid, Items: []DirectiveItem{{Kind: DirectiveToken, Value: "self"}, {Kind: DirectiveString, Value: "https://example.test"}}, IgnoredItems: 3},
		{Name: "microphone", Status: StatusIgnored, IgnoredItems: 1},
		{Name: "geolocation", Status: StatusValid, Items: []DirectiveItem{{Kind: DirectiveToken, Value: "self"}}, ReportToStatus: StatusIgnored},
	}
	if got.Status != StatusValid || !reflect.DeepEqual(got.Directives, want) {
		t.Fatalf("unsupported member items were not isolated: %+v", got)
	}

	for _, value := range []string{`camera=(`, `camera=(); geolocation=()`} {
		r = analyzeHTML(http.Header{"Permissions-Policy": {value}})
		if got := mustResult(t, r, PermissionsPolicy); got.Status != StatusInvalid {
			t.Fatalf("accepted malformed policy %q: %+v", value, got)
		}
	}
	for _, value := range []string{`camera=("unterminated)`, `camera=("ok"garbage)`} {
		r = analyzeHTML(http.Header{"Permissions-Policy": {value}})
		if got := mustResult(t, r, PermissionsPolicy); got.Status != StatusInvalid {
			t.Fatalf("accepted malformed structured field %q: %+v", value, got)
		}
	}
}

func TestPermissionsSourceExpressionGrammar(t *testing.T) {
	for _, value := range []string{
		"https:", "https://example.test", "*.example.test", "https://*.example.test:*/path/to%3Fq", "example.test/path://segment",
	} {
		if !validPermissionsSourceExpression(value) {
			t.Fatalf("rejected valid source expression %q", value)
		}
	}
	for _, value := range []string{
		"", "not a source", "://example.test", "https://", "https://exa_mple.test", "https://example.test//double", "https://example.test/path;bad", "https://example.test/path,bad", "https://example.test/path?query",
	} {
		if validPermissionsSourceExpression(value) {
			t.Fatalf("accepted invalid source expression %q", value)
		}
	}
}

func TestCSPIsObservedWithoutDuplicatingDedicatedAnalysis(t *testing.T) {
	r := analyzeHTML(http.Header{"Content-Security-Policy": {"default-src 'self'", "script-src 'unsafe-inline' NONCE-private"}})
	got := mustResult(t, r, ContentSecurityPolicy)
	if got.Status != StatusObserved || got.Effective != "" || got.Occurrences != 2 || len(got.Tokens) != 0 {
		t.Fatalf("CSP was naively interpreted: %+v", got)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "unsafe-inline") || strings.Contains(string(encoded), "NONCE-private") {
		t.Fatal("raw CSP leaked into structured result")
	}
}

func TestEvidenceIsBoundedSanitizedAndExplicit(t *testing.T) {
	values := make([]string, 20)
	for i := range values {
		values[i] = strings.Repeat("x", 5000) + "SECRET\x1b\n\u202e"
	}
	r := analyzeHTML(http.Header{"Server": values})
	got := mustResult(t, r, Server)
	if got.Status != StatusTruncated || !got.Truncated || got.Occurrences != 20 {
		t.Fatalf("missing truncation state: %+v", got)
	}
	retained := r.Values(Server)
	if len(retained) > 16 {
		t.Fatalf("retained too many values: %d", len(retained))
	}
	for _, value := range retained {
		if len(value) > 4096 || !utf8.ValidString(value) {
			t.Fatal("unbounded or invalid evidence")
		}
		for _, current := range value {
			if unicode.IsControl(current) || unicode.Is(unicode.Cf, current) {
				t.Fatal("unsafe character retained")
			}
		}
	}
	formatted := fmt.Sprintf("%v %+v %#v", r, r, r)
	encoded, _ := json.Marshal(r)
	if strings.Contains(formatted+string(encoded), "SECRET") {
		t.Fatal("explicit raw evidence leaked through default output")
	}
	copy := r.Clone()
	copy.Results[0].Tokens = append(copy.Results[0].Tokens, "changed")
	copy.values[Server][0] = "changed"
	if strings.Contains(strings.Join(r.Values(Server), ""), "changed") || len(r.Results[0].Tokens) != 0 {
		t.Fatal("clone aliases retained report")
	}

	policy := analyzeHTML(http.Header{"Permissions-Policy": {"camera=(self)"}})
	policyCopy := policy.Clone()
	policyCopy.Results[4].Directives[0].Items[0].Value = "changed"
	if got := mustResult(t, policy, PermissionsPolicy); got.Directives[0].Items[0].Value != "self" {
		t.Fatal("clone aliases parsed directive values")
	}
}

func TestGlobalEvidenceBudgetStopsSemanticClaims(t *testing.T) {
	headers := make(http.Header)
	for _, name := range names {
		headers[name] = []string{strings.Repeat("x", maxEvidenceBytes)}
	}
	r := analyzeHTML(headers)

	total := 0
	for _, id := range allHeaderIDs {
		for _, value := range r.Values(id) {
			total += len(value)
		}
		got := mustResult(t, r, id)
		if got.Status != StatusTruncated || !got.Truncated {
			t.Fatalf("%s made a semantic claim after truncation: %+v", id, got)
		}
	}
	if total > maxEvidenceBytes {
		t.Fatalf("retained %d bytes beyond %d-byte budget", total, maxEvidenceBytes)
	}
}

func analyzeHTML(headers http.Header) Report {
	if headers == nil {
		headers = make(http.Header)
	}
	if len(headerValues(headers, "Content-Type")) == 0 {
		headers = headers.Clone()
		headers.Set("Content-Type", "text/html")
	}
	return Analyze(Input{Captured: true, Scheme: "https", TLSVerified: true, StatusCode: 200, Headers: headers})
}
