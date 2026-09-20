package cspanalysis

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestParseSourceKinds(t *testing.T) {
	tests := []struct {
		raw       string
		kind      SourceKind
		valid     bool
		keyword   string
		algorithm string
		host      string
	}{
		{"'self'", SourceKeyword, true, "self", "", ""},
		{"'unsafe-inline'", SourceKeyword, true, "unsafe-inline", "", ""},
		{"https:", SourceScheme, true, "", "", ""},
		{"*", SourceWildcard, true, "", "", ""},
		{"https://*.example.test:443/assets", SourceHost, true, "", "", "example.test"},
		{"'nonce-YWJjZA=='", SourceNonce, true, "", "", ""},
		{"'sha256-YWJjZA=='", SourceHash, true, "", "sha256", ""},
		{"unsafe-inline", SourceInvalid, false, "", "", ""},
		{"'nonce-'", SourceInvalid, false, "", "", ""},
		{"https://bücher.example", SourceInvalid, false, "", "", ""},
		{"'none'", SourceKeyword, true, "none", "", ""},
		{"'sha1-YWJjZA=='", SourceInvalid, false, "", "", ""},
		{"https://example.test:*", SourceHost, true, "", "", "example.test"},
		{"https://example.test:*/assets", SourceHost, true, "", "", "example.test"},
		{"https://xn--bcher-kva.example", SourceHost, true, "", "", "xn--bcher-kva.example"},
		{"https://example.test.", SourceHost, true, "", "", "example.test."},
		{"https://-example.test", SourceInvalid, false, "", "", ""},
		{"https://example-.test", SourceInvalid, false, "", "", ""},
		{"https://example..test", SourceInvalid, false, "", "", ""},
		{"https://example.test/a?b", SourceInvalid, false, "", "", ""},
		{"https://example.test/a;b", SourceInvalid, false, "", "", ""},
		{"https://example.test/a,b", SourceInvalid, false, "", "", ""},
		{"https://example.test/a%zz", SourceInvalid, false, "", "", ""},
		{"https://example.test/a[bad]", SourceInvalid, false, "", "", ""},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			source := parseSource(test.raw)
			if source.Kind != test.kind || source.Valid != test.valid || source.Keyword != test.keyword || source.Algorithm != test.algorithm || source.Host != test.host {
				t.Fatalf("parseSource(%q) = %+v", test.raw, source)
			}
		})
	}

	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"frame-ancestors 'nonce-YQ=='"},
		XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"},
	})
	if !report.Framing.CSPFrameAncestors || report.Framing.Relation != CSPOverridesXFO {
		t.Fatalf("retained frame-ancestors did not preserve XFO precedence: %+v", report.Framing)
	}
}

func TestParseSourceRequiresCompleteKeywords(t *testing.T) {
	for _, raw := range []string{"'self'-suffix", "'unsafe-inline", "'unsafe-inline-extra'", "'none'foo"} {
		if source := parseSource(raw); source.Valid {
			t.Fatalf("partial keyword %q was accepted: %+v", raw, source)
		}
	}
}

func TestParseKeywordSet(t *testing.T) {
	keywords := []string{
		"self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic",
		"unsafe-hashes", "report-sample", "unsafe-allow-redirects",
		"wasm-unsafe-eval", "trusted-types-eval", "report-sha256",
		"report-sha384", "report-sha512", "unsafe-webtransport-hashes",
	}
	for _, keyword := range keywords {
		t.Run(keyword, func(t *testing.T) {
			source := parseSource("'" + strings.ToUpper(keyword) + "'")
			if source.Kind != SourceKeyword || !source.Valid || source.Keyword != keyword {
				t.Fatalf("keyword %q = %+v", keyword, source)
			}
		})
	}
}

func TestParseNonceAndHashPrefixesAreCaseInsensitive(t *testing.T) {
	for _, test := range []struct {
		raw       string
		kind      SourceKind
		algorithm string
	}{
		{"'NONCE-YWJjZA=='", SourceNonce, ""},
		{"'SHA256-YWJjZA=='", SourceHash, "sha256"},
		{"'sHa512-YWJjZA=='", SourceHash, "sha512"},
	} {
		t.Run(test.raw, func(t *testing.T) {
			source := parseSource(test.raw)
			if source.Kind != test.kind || !source.Valid || !source.Redacted || source.Algorithm != test.algorithm {
				t.Fatalf("parseSource(%q) = %+v", test.raw, source)
			}
		})
	}
}

func TestParseHostSourcePathAbsolute(t *testing.T) {
	valid := parseSource("https://example.test/a://b")
	if valid.Kind != SourceHost || !valid.Valid || valid.Path != "/a://b" {
		t.Fatalf("valid absolute path rejected: %+v", valid)
	}
	if invalid := parseSource("https://example.test//a"); invalid.Valid {
		t.Fatalf("double-slash path accepted: %+v", invalid)
	}
}

func TestParseHostSourceAcceptsMaxDNSNameWithTrailingDot(t *testing.T) {
	maxDNSName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(maxDNSName) != 253 {
		t.Fatalf("test DNS name length = %d", len(maxDNSName))
	}
	if source := parseSource("https://" + maxDNSName + "."); !source.Valid || source.Kind != SourceHost {
		t.Fatalf("253-byte DNS name with trailing dot rejected: %+v", source)
	}
	if source := parseSource("https://" + maxDNSName + "e"); source.Valid {
		t.Fatalf("overlong DNS name accepted: %+v", source)
	}
}

func TestRetainedSourcePortDoesNotAliasRawCSPField(t *testing.T) {
	field := "img-src https://images.example.test:8443 'nonce-" + strings.Repeat("A", 512) + "'"
	report := Analyze(Input{Captured: true, EnforcedFields: []string{field}})
	source := report.Enforced.Policies[0].Directives[0].Sources[0]
	fieldStart := uintptr(unsafe.Pointer(unsafe.StringData(field)))
	fieldEnd := fieldStart + uintptr(len(field))
	portStart := uintptr(unsafe.Pointer(unsafe.StringData(source.Port)))
	runtime.KeepAlive(field)
	if portStart >= fieldStart && portStart < fieldEnd {
		t.Fatalf("retained port aliases raw CSP field backing storage: %q", source.Port)
	}
}

func TestNonceAndHashPayloadsAreRedacted(t *testing.T) {
	const nonceCanary = "nonce-UNIQUE_NONCE_CANARY_4A7"
	const hashCanary = "UNIQUE_HASH_CANARY_9F2"
	report := Analyze(Input{Captured: true, EnforcedFields: []string{
		"script-src '" + nonceCanary + "' 'sha256-" + hashCanary + "'",
	}})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(encoded) + fmt.Sprintf("%+v %#v", report, report)
	for _, canary := range []string{nonceCanary, hashCanary} {
		if strings.Contains(rendered, canary) {
			t.Fatalf("rendered report retained payload %q: %s", canary, rendered)
		}
	}
	sources := report.Enforced.Policies[0].Directives[0].Sources
	if len(sources) != 2 || !sources[0].Redacted || !sources[1].Redacted {
		t.Fatalf("nonce/hash sources were not redacted: %+v", sources)
	}
}

func TestAnalyzeParsesRecognizedSourceListsAndMarksMixedNoneNonconforming(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{
		"script-src 'none' https://example.test; report-uri /reports",
	}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseValid || policy.SyntaxIssues != 0 {
		t.Fatalf("valid mixed-none list was not retained: %+v", policy)
	}
	directive := policy.Directives[0]
	if directive.Kind != DirectiveSourceList || !directive.Nonconforming || directive.OpaqueTokens != 0 || len(directive.Sources) != 2 || !directive.Sources[0].Valid || !directive.Sources[1].Valid {
		t.Fatalf("source list was not structurally parsed: %+v", directive)
	}
	if policy.Directives[1].Kind != DirectiveOpaque || policy.Directives[1].OpaqueTokens != 1 {
		t.Fatalf("opaque directive changed: %+v", policy.Directives[1])
	}
	if !isSourceListDirective("script-src") || isSourceListDirective("report-uri") {
		t.Fatal("source-list directive recognition mismatch")
	}
}

func TestFrameAncestorsUsesAncestorSourceGrammar(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		valid         bool
		status        DirectiveStatus
		nonconforming bool
	}{
		{"self", "'self'", true, DirectiveValid, false},
		{"scheme", "https:", true, DirectiveValid, false},
		{"host", "https://ancestors.example.test", true, DirectiveValid, false},
		{"sole none", "'none'", true, DirectiveValid, false},
		{"nonce", "'nonce-YQ=='", false, DirectivePartial, true},
		{"hash", "'sha256-YQ=='", false, DirectivePartial, true},
		{"other keyword", "'unsafe-inline'", false, DirectivePartial, true},
		{"wildcard", "*", true, DirectiveValid, false},
		{"mixed none", "'none' https:", true, DirectivePartial, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := Analyze(Input{Captured: true, EnforcedFields: []string{"frame-ancestors " + test.value}})
			directive := report.Enforced.Policies[0].Directives[0]
			if directive.Status != test.status || directive.Nonconforming != test.nonconforming || directive.Sources[0].Valid != test.valid {
				t.Fatalf("frame-ancestors %q = %+v", test.value, directive)
			}
		})
	}
}

func TestAnalyzeEmptySourceListRemainsPresent(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src; default-src"}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseValid || len(policy.Directives) != 2 {
		t.Fatalf("empty source lists were not retained: %+v", policy)
	}
	for _, directive := range policy.Directives {
		if directive.Kind != DirectiveSourceList || directive.Status != DirectiveValid || directive.Nonconforming || len(directive.Sources) != 0 {
			t.Fatalf("empty source list changed structure: %+v", directive)
		}
	}
}

func TestAnalyzeInvalidSourceListExpressionIsPartial(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src unsafe-inline"}})
	policy := report.Enforced.Policies[0]
	directive := policy.Directives[0]
	if policy.Parse != ParsePartial || !directive.Nonconforming || len(directive.Sources) != 1 || directive.Sources[0].Valid {
		t.Fatalf("invalid source expression was not marked partial: %+v", policy)
	}
}

func TestBoundsRetainedPathBytesTruncatesPolicy(t *testing.T) {
	path := "/" + strings.Repeat("a", maxSourcePathBytes)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"img-src https://images.example.test" + path}})
	if len(report.Enforced.Policies) != 1 {
		t.Fatalf("expected one policy: %+v", report.Enforced)
	}
	policy := report.Enforced.Policies[0]
	if !report.Truncated || !report.Enforced.Truncated || !policy.Truncated || policy.Parse != ParseTruncated {
		t.Fatalf("retained-path limit did not truncate policy: %+v", report)
	}
	if len(policy.EffectiveControls) != 0 {
		t.Fatalf("truncated path policy retained effective controls: %+v", policy.EffectiveControls)
	}
	for _, observation := range report.Observations {
		if observation.Disposition == policy.Disposition && observation.FieldIndex == policy.FieldIndex && observation.MemberIndex == policy.MemberIndex {
			t.Fatalf("truncated path policy retained an assessment observation: %+v", observation)
		}
	}
}

func TestBoundsRetainedPortBytesTruncatesPolicy(t *testing.T) {
	port := strings.Repeat("1", maxSourceComponentBytes+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"img-src https://images.example.test:" + port}})
	if len(report.Enforced.Policies) != 1 {
		t.Fatalf("expected one policy: %+v", report.Enforced)
	}
	policy := report.Enforced.Policies[0]
	if !report.Truncated || !report.Enforced.Truncated || !policy.Truncated || policy.Parse != ParseTruncated {
		t.Fatalf("retained-port limit did not truncate policy: %+v", report)
	}
	if len(policy.EffectiveControls) != 0 {
		t.Fatalf("truncated port policy retained effective controls: %+v", policy.EffectiveControls)
	}
}
