// Package cspanalysis parses bounded HTTP Content Security Policy evidence.
package cspanalysis

import (
	"strings"
	"testing"
)

func TestAnalyzeSeparatesFieldsMembersAndDispositions(t *testing.T) {
	report := Analyze(Input{
		Captured:              true,
		DocumentApplicability: Applicable,
		EnforcedFields: []string{
			"default-src 'self', script-src https:",
			"object-src 'none'",
		},
		ReportOnlyFields: []string{"script-src 'unsafe-inline'"},
	})
	if report.Capture != CaptureComplete || len(report.Enforced.Policies) != 3 || len(report.ReportOnly.Policies) != 1 {
		t.Fatalf("policy boundaries lost: %+v", report)
	}
	if report.Enforced.Policies[0].Disposition != Enforce || report.ReportOnly.Policies[0].Disposition != ReportOnly {
		t.Fatalf("dispositions conflated: %+v", report)
	}
}

func TestAnalyzeFirstDirectiveWins(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{
		"SCRIPT-SRC 'self'; script-src *; object-src 'none'",
	}})
	policy := report.Enforced.Policies[0]
	if len(policy.Directives) != 2 || policy.Directives[0].Name != "script-src" || policy.Directives[0].IgnoredDuplicates != 1 {
		t.Fatalf("duplicate processing mismatch: %+v", policy)
	}
}

func TestAnalyzeCaptureUnavailableHasNoAbsenceConclusions(t *testing.T) {
	report := Analyze(Input{EnforcedFields: []string{"default-src *"}})
	if report.Capture != CaptureUnavailable || len(report.Enforced.Policies) != 0 || len(report.Observations) != 0 {
		t.Fatalf("unavailable capture inferred CSP state: %+v", report)
	}
}

func TestAnalyzeMarksUnsafeDirectiveAndValueTokensPartial(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src 'self' \u00e9; object_src *"}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParsePartial || policy.SyntaxIssues != 2 || len(policy.Directives) != 1 || policy.Directives[0].OpaqueTokens != 0 || len(policy.Directives[0].Sources) != 2 || !policy.Directives[0].Nonconforming {
		t.Fatalf("unsafe tokens were not safely represented: %+v", policy)
	}
}

func TestAnalyzeRejectsHTTPInvalidControls(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src 'self'\r\nobject-src 'none'"}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseInvalid || policy.SyntaxIssues != 1 || len(policy.Directives) != 0 {
		t.Fatalf("HTTP-invalid controls entered semantic parsing: %+v", policy)
	}
}

func TestTruncationAccountingHandlesControlOnlyDirective(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"\f"}})
	if len(report.Enforced.Policies) != 1 || report.Enforced.Policies[0].Parse != ParseInvalid {
		t.Fatalf("control-only directive was not rejected safely: %+v", report.Enforced)
	}
}

func TestAnalyzeBoundedPolicySetMarksOmissionsTruncated(t *testing.T) {
	fields := make([]string, maxFieldsPerDisposition+1)
	for i := range fields {
		fields[i] = "default-src 'self'"
	}
	report := Analyze(Input{Captured: true, EnforcedFields: fields})
	if !report.Truncated || !report.Enforced.Truncated || report.Enforced.FieldCount != len(fields) || report.Enforced.OmittedPolicies == 0 {
		t.Fatalf("field limit did not preserve uncertainty: %+v", report)
	}
}

func TestAnalyzeRejectsOversizedFieldBeforeMemberSplitting(t *testing.T) {
	field := strings.Repeat(",", maxFieldBytes+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{field}})
	if len(report.Enforced.Policies) != 0 || !report.Enforced.Truncated || report.Enforced.OmittedPolicies != 1 {
		t.Fatalf("oversized field was traversed as a policy list: %+v", report.Enforced)
	}
}

func TestAnalyzeStopsAtFieldCapWithoutInspectingLaterFields(t *testing.T) {
	fields := make([]string, maxFieldsPerDisposition+2)
	for i := 0; i < maxFieldsPerDisposition; i++ {
		fields[i] = "default-src 'self'"
	}
	fields[maxFieldsPerDisposition] = strings.Repeat(",", maxFieldBytes+1)
	fields[maxFieldsPerDisposition+1] = strings.Repeat(",", maxFieldBytes+1)
	report := Analyze(Input{Captured: true, EnforcedFields: fields})
	if !report.Enforced.Truncated || report.Enforced.OmittedPolicies != 2 {
		t.Fatalf("field-cap omissions were not bounded conservatively: %+v", report.Enforced)
	}
}

func TestAnalyzeTruncatesOversizedDirectiveName(t *testing.T) {
	name := strings.Repeat("a", maxTokenBytes+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{name + " 'self'"}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseTruncated || !policy.Truncated || len(policy.Directives) != 0 {
		t.Fatalf("oversized directive name was retained: %+v", policy)
	}
}

func TestAnalyzeTruncatesOversizedUnsafeValue(t *testing.T) {
	unsafeValue := strings.Repeat("\u00e9", (maxTokenBytes/2)+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src " + unsafeValue}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseTruncated || !policy.Truncated || policy.Directives[0].Status != DirectiveTruncated {
		t.Fatalf("oversized unsafe value bypassed truncation: %+v", policy)
	}
}

func TestAnalyzeTruncatesOversizedControlContainingDirectiveName(t *testing.T) {
	name := strings.Repeat("a", maxTokenBytes+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{name + "\r"}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseTruncated || !policy.Truncated || len(policy.Directives) != 0 {
		t.Fatalf("oversized control-containing directive name bypassed truncation: %+v", policy)
	}
}

func TestAnalyzeTruncatesOversizedControlContainingValue(t *testing.T) {
	value := strings.Repeat("a", maxTokenBytes+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src " + value + "\x7f"}})
	policy := report.Enforced.Policies[0]
	if policy.Parse != ParseTruncated || !policy.Truncated || len(policy.Directives) != 0 {
		t.Fatalf("oversized control-containing value bypassed truncation: %+v", policy)
	}
}

func TestAnalyzeTruncatesAfterUnsafeSourceTokens(t *testing.T) {
	values := strings.Repeat("\u00e9 ", maxTokensPerPolicy+1)
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src " + values}})
	policy := report.Enforced.Policies[0]
	if !policy.Truncated || policy.Parse != ParseTruncated || policy.Directives[0].Status != DirectiveTruncated || len(policy.Directives[0].Sources) != maxTokensPerPolicy {
		t.Fatalf("unsafe source tokens bypassed the value cap: %+v", policy)
	}
}

func TestReportCloneOwnsNestedSlices(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src 'self'; object-src 'none'"}})
	clone := report.Clone()
	clone.Enforced.Policies[0].Directives[0].Name = "changed"
	if report.Enforced.Policies[0].Directives[0].Name == "changed" {
		t.Fatal("clone shares directive storage")
	}
}

func TestBoundsFieldCountSuppressesGlobalConclusions(t *testing.T) {
	fields := make([]string, maxFieldsPerDisposition+1)
	for index := range fields {
		fields[index] = "script-src 'self'"
	}
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable, EnforcedFields: fields,
		XFrameOptions: XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if !report.Truncated || !report.Enforced.Truncated || report.Framing.Relation != FramingIndeterminate {
		t.Fatalf("field-count truncation did not suppress global conclusions: %+v", report)
	}
	assertNoGlobalAbsenceObservations(t, report)
}

func TestBoundsFieldBytesSuppressesGlobalConclusions(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{strings.Repeat("a", maxFieldBytes+1)},
		XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if !report.Truncated || !report.Enforced.Truncated || report.Framing.Relation != FramingIndeterminate {
		t.Fatalf("field-byte truncation did not suppress global conclusions: %+v", report)
	}
	assertNoGlobalAbsenceObservations(t, report)
}

func TestBoundsAggregateBytesSuppressesOmittedDisposition(t *testing.T) {
	policy := "default-src 'self'"
	field := strings.Repeat(" ", maxFieldBytes-len(policy)) + policy
	fields := make([]string, maxFieldsPerDisposition)
	for index := range fields {
		fields[index] = field
	}
	report := Analyze(Input{Captured: true, EnforcedFields: fields, ReportOnlyFields: []string{"script-src 'unsafe-inline'"}})
	if !report.Truncated || !report.ReportOnly.Truncated || len(report.ReportOnly.Policies) != 0 || report.ReportOnly.OmittedPolicies != 1 {
		t.Fatalf("aggregate-byte truncation did not omit the unparsed disposition: %+v", report)
	}
}

func TestBoundsPolicyCountSuppressesGlobalConclusions(t *testing.T) {
	policies := make([]string, maxPoliciesPerDisposition+1)
	for index := range policies {
		policies[index] = "script-src 'self'"
	}
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable, EnforcedFields: []string{strings.Join(policies, ",")},
		XFrameOptions: XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if !report.Truncated || !report.Enforced.Truncated || report.Framing.Relation != FramingIndeterminate {
		t.Fatalf("policy-count truncation did not suppress global conclusions: %+v", report)
	}
	assertNoGlobalAbsenceObservations(t, report)
}

func TestBoundsDirectiveCountClearsDerivedEvidence(t *testing.T) {
	directives := make([]string, maxDirectivesPerPolicy+1)
	directives[0] = "script-src unsafe-inline"
	for index := 1; index < maxDirectivesPerPolicy; index++ {
		directives[index] = "x" + string(rune('a'+index%26)) + string(rune('a'+index/26))
	}
	directives[maxDirectivesPerPolicy] = "overflow"
	report := Analyze(Input{Captured: true, EnforcedFields: []string{strings.Join(directives, ";")}})
	assertTruncatedPolicyHasNoDerivedEvidence(t, report)
}

func TestBoundsTokenCountClearsDerivedEvidence(t *testing.T) {
	values := strings.TrimSpace(strings.Repeat("unsafe-inline ", maxTokensPerPolicy+1))
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src " + values}})
	assertTruncatedPolicyHasNoDerivedEvidence(t, report)
}

func TestBoundsTokenBytesClearsDerivedEvidence(t *testing.T) {
	report := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src unsafe-inline; report-uri " + strings.Repeat("a", maxTokenBytes+1)}})
	assertTruncatedPolicyHasNoDerivedEvidence(t, report)
}

func TestTruncationAccountsValueBoundsBeforeSemanticRejection(t *testing.T) {
	longValue := strings.Repeat("a", maxTokenBytes+1)
	manyValues := strings.TrimSpace(strings.Repeat("a ", maxTokensPerPolicy+1))
	for _, test := range []struct {
		name          string
		field         string
		retainedFirst bool
	}{
		{"invalid_name_byte_limit", "invalid_name " + longValue, false},
		{"invalid_name_count_limit", "invalid_name " + manyValues, false},
		{"duplicate_byte_limit", "script-src 'self'; script-src " + longValue, true},
		{"duplicate_count_limit", "script-src 'self'; script-src " + manyValues, true},
		{"control_byte_limit", "script-src " + longValue + "\x7f", false},
		{"control_count_limit", "script-src " + manyValues + "\x7f", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := Analyze(Input{Captured: true, EnforcedFields: []string{test.field}})
			assertTruncatedPolicyHasNoDerivedEvidence(t, report)
			policy := report.Enforced.Policies[0]
			if test.retainedFirst {
				if len(policy.Directives) != 1 || policy.Directives[0].Name != "script-src" || policy.Directives[0].IgnoredDuplicates != 1 {
					t.Fatalf("duplicate bound changed first-directive-wins: %+v", policy.Directives)
				}
				return
			}
			if len(policy.Directives) != 0 {
				t.Fatalf("rejected directive retained malformed values: %+v", policy.Directives)
			}
		})
	}
}

func TestBoundsObservationCountIsExplicit(t *testing.T) {
	policies := make([]string, maxPoliciesPerDisposition)
	for index := range policies {
		policies[index] = "script-src 'unsafe-inline' *"
	}
	report := Analyze(Input{Captured: true, EnforcedFields: []string{strings.Join(policies, ",")}})
	if len(report.Observations) != maxObservations || !report.Truncated {
		t.Fatalf("observation cap was not explicit: %+v", report)
	}
}

func TestCloneOwnsAllPopulatedNestedPublicSlices(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"script-src 'unsafe-inline' https://scripts.example.test; img-src https://images.example.test"}})
	clone := report.Clone()
	policy := &clone.Enforced.Policies[0]
	policy.Directives[0].Sources[0].Keyword = "changed-directive-source"
	for index := range policy.EffectiveControls {
		if policy.EffectiveControls[index].Control == "script-element" {
			policy.EffectiveControls[index].Sources[0].Keyword = "changed-effective-source"
			break
		}
	}
	clone.Observations[0].Code = ObjectControlAbsent

	original := report.Enforced.Policies[0]
	if original.Directives[0].Sources[0].Keyword == "changed-directive-source" {
		t.Fatal("clone shares directive source storage")
	}
	for index := range original.EffectiveControls {
		if original.EffectiveControls[index].Control == "script-element" && original.EffectiveControls[index].Sources[0].Keyword == "changed-effective-source" {
			t.Fatal("clone shares effective source storage")
		}
	}
	if report.Observations[0].Code == ObjectControlAbsent {
		t.Fatal("clone shares observation storage")
	}
}

func assertTruncatedPolicyHasNoDerivedEvidence(t *testing.T, report Report) {
	t.Helper()
	if len(report.Enforced.Policies) != 1 {
		t.Fatalf("expected one policy: %+v", report.Enforced)
	}
	policy := report.Enforced.Policies[0]
	if !report.Truncated || !report.Enforced.Truncated || !policy.Truncated || policy.Parse != ParseTruncated {
		t.Fatalf("limit did not produce a truncated policy: %+v", report)
	}
	if len(policy.EffectiveControls) != 0 {
		t.Fatalf("truncated policy retained effective controls: %+v", policy.EffectiveControls)
	}
	for _, observation := range report.Observations {
		if observation.Disposition == policy.Disposition && observation.FieldIndex == policy.FieldIndex && observation.MemberIndex == policy.MemberIndex {
			t.Fatalf("truncated policy retained an assessment observation: %+v", observation)
		}
	}
}

func assertNoGlobalAbsenceObservations(t *testing.T, report Report) {
	t.Helper()
	for _, observation := range report.Observations {
		switch observation.Code {
		case ObjectControlAbsent, BaseURIControlAbsent, FrameAncestorsControlAbsent, FormActionControlAbsent:
			t.Fatalf("truncated evidence emitted global absence observation: %+v", observation)
		}
	}
}
