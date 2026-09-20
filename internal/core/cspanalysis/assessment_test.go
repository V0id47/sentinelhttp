package cspanalysis

import (
	"strconv"
	"strings"
	"testing"
)

func TestUnsafeInlineRequiresEffectiveAllowAllInline(t *testing.T) {
	assertObservation(t, "script-src 'unsafe-inline'", UnsafeInlineEffective, true)
	assertObservation(t, "script-src 'unsafe-inline' 'nonce-YWJjZA=='", UnsafeInlineEffective, false)
	assertObservation(t, "script-src 'unsafe-inline' 'sha256-YWJjZA=='", UnsafeInlineEffective, false)
	assertObservation(t, "script-src 'unsafe-inline' 'strict-dynamic'", UnsafeInlineEffective, false)
	assertObservation(t, "style-src 'unsafe-inline' 'strict-dynamic'", UnsafeInlineEffective, true)
}

func TestUnsafeEvalRequiresExactKeyword(t *testing.T) {
	assertObservation(t, "script-src 'unsafe-eval'", UnsafeEvalPresent, true)
	assertObservation(t, "script-src 'unsafe-evaluate'", UnsafeEvalPresent, false)
}

func TestWildcardObservationExcludesHostWildcards(t *testing.T) {
	assertObservation(t, "img-src *", GeneralWildcardPresent, true)
	assertObservation(t, "img-src *.example.test", GeneralWildcardPresent, false)
}

func TestObjectSourcesObservationRequiresPermittedSource(t *testing.T) {
	assertObservation(t, "object-src https:", ObjectSourcesPermitted, true)
	assertObservation(t, "object-src 'none'", ObjectSourcesPermitted, false)
}

func TestReportOnlyDoesNotBecomeEnforcement(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		ReportOnlyFields: []string{"frame-ancestors 'none'; script-src 'unsafe-inline'"}})
	if !hasObservation(report, ReportOnlyWithoutEnforcement) || report.Framing.Relation == CSPOverridesXFO {
		t.Fatalf("report-only policy was treated as enforcement: %+v", report)
	}
}

func TestTruncatedEnforcementDoesNotProduceAbsenceObservations(t *testing.T) {
	truncated := Analyze(Input{Captured: true, EnforcedFields: []string{strings.Repeat("a", maxFieldBytes+1)}})
	if hasObservation(truncated, EnforcementAbsent) {
		t.Fatalf("truncated enforcement produced false absence: %+v", truncated.Observations)
	}

	withReportOnly := Analyze(Input{Captured: true,
		EnforcedFields:   []string{strings.Repeat("a", maxFieldBytes+1)},
		ReportOnlyFields: []string{"script-src 'self'"},
	})
	if hasObservation(withReportOnly, ReportOnlyWithoutEnforcement) {
		t.Fatalf("truncated enforcement produced false report-only absence: %+v", withReportOnly.Observations)
	}

	fullyAnalyzed := Analyze(Input{Captured: true, EnforcedFields: []string{"x_bad"}})
	if !hasObservation(fullyAnalyzed, EnforcementAbsent) {
		t.Fatalf("fully analyzed invalid enforcement lost absence observation: %+v", fullyAnalyzed.Observations)
	}
}

func TestPartialPolicyRetainsStructuralAndUnaffectedControlObservations(t *testing.T) {
	nonconforming := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src ???"}})
	if !hasObservation(nonconforming, SourceListNonconforming) {
		t.Fatalf("partial source list lost structural observation: %+v", nonconforming.Observations)
	}

	unaffected := Analyze(Input{Captured: true, EnforcedFields: []string{"script-src 'unsafe-inline'; x_bad"}})
	if !hasObservation(unaffected, UnsafeInlineEffective) {
		t.Fatalf("unrelated parse issue suppressed complete script control: %+v", unaffected.Observations)
	}
}

func TestEnforcedFrameAncestorsOverridesXFO(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"frame-ancestors 'self'"},
		XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if report.Framing.Relation != CSPOverridesXFO {
		t.Fatalf("wrong framing relation: %+v", report.Framing)
	}
}

func TestPartialPolicyFrameAncestorsStillOverridesXFO(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"frame-ancestors 'self'; x_bad"},
		XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"},
	})
	if !report.Framing.CSPFrameAncestors || report.Framing.Relation != CSPOverridesXFO {
		t.Fatalf("retained frame-ancestors lost precedence after unrelated parse issue: %+v", report.Framing)
	}
}

func TestRetainedFrameAncestorsOverridesXFOAfterLaterTruncation(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"frame-ancestors 'self'; report-uri " + strings.Repeat("a", maxTokenBytes+1)},
		XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"},
	})
	if !report.Framing.CSPFrameAncestors || report.Framing.Relation != CSPOverridesXFO {
		t.Fatalf("later truncation undid retained frame-ancestors precedence: %+v", report.Framing)
	}
}

func TestTruncationBeforeOrInsideFrameAncestorsKeepsFramingIndeterminate(t *testing.T) {
	for _, field := range []string{
		"report-uri " + strings.Repeat("a", maxTokenBytes+1) + "; frame-ancestors 'self'",
		"frame-ancestors " + strings.Repeat("a", maxTokenBytes+1),
	} {
		report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
			EnforcedFields: []string{field},
			XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"},
		})
		if report.Framing.CSPFrameAncestors || report.Framing.Relation != FramingIndeterminate {
			t.Fatalf("incomplete frame-ancestors evidence made precedence claim: %+v", report.Framing)
		}
	}
}

func TestFramingFallbackUsesCompleteFrameAncestorsEvidence(t *testing.T) {
	longToken := strings.Repeat("a", maxTokenBytes+1)
	for _, test := range []struct {
		name     string
		field    string
		relation FramingRelation
	}{
		{"invalid unrelated directive", "x_bad", XFOFallbackObserved},
		{"partial unrelated directive", "script-src 'self'; x_bad", XFOFallbackObserved},
		{"discarded frame ancestors candidate", "frame-ancestors\x7f", FramingIndeterminate},
		{"truncation before frame ancestors", "report-uri " + longToken + "; frame-ancestors 'self'", FramingIndeterminate},
		{"truncation inside frame ancestors", "frame-ancestors " + longToken, FramingIndeterminate},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
				EnforcedFields: []string{test.field},
				XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"},
			})
			if report.Framing.CSPFrameAncestors || report.Framing.Relation != test.relation {
				t.Fatalf("framing for %q = %+v, want %s", test.field, report.Framing, test.relation)
			}
		})
	}
}

func TestMissingNavigationControlsRequireApplicableCompleteEnforcement(t *testing.T) {
	applicable := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"script-src 'self'"}})
	for _, code := range []ObservationCode{ObjectControlAbsent, BaseURIControlAbsent, FrameAncestorsControlAbsent, FormActionControlAbsent} {
		if !hasObservation(applicable, code) {
			t.Fatalf("applicable complete policy omitted %s: %+v", code, applicable.Observations)
		}
	}

	notApplicable := Analyze(Input{Captured: true, DocumentApplicability: NotApplicable,
		EnforcedFields: []string{"script-src 'self'"}})
	if !hasObservation(notApplicable, ObjectControlAbsent) {
		t.Fatalf("non-document response omitted object absence: %+v", notApplicable.Observations)
	}
	for _, code := range []ObservationCode{BaseURIControlAbsent, FrameAncestorsControlAbsent, FormActionControlAbsent} {
		if hasObservation(notApplicable, code) {
			t.Fatalf("non-document response emitted %s: %+v", code, notApplicable.Observations)
		}
	}

	unknown := Analyze(Input{Captured: true, DocumentApplicability: ApplicabilityUnknown,
		EnforcedFields: []string{"script-src 'self'"}})
	if !hasObservation(unknown, ObjectControlAbsent) {
		t.Fatalf("unknown document context omitted object absence: %+v", unknown.Observations)
	}
	for _, code := range []ObservationCode{BaseURIControlAbsent, FrameAncestorsControlAbsent, FormActionControlAbsent} {
		if hasObservation(unknown, code) {
			t.Fatalf("unknown document context emitted %s: %+v", code, unknown.Observations)
		}
	}
}

func TestMultipleEnforcedPoliciesRemainPolicyScoped(t *testing.T) {
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{"script-src 'unsafe-inline'", "script-src 'self'"}})
	if len(report.Enforced.Policies) != 2 {
		t.Fatalf("enforced policies were merged: %+v", report.Enforced)
	}
	for _, observation := range report.Observations {
		if observation.Code == UnsafeInlineEffective && observation.FieldIndex != 0 {
			t.Fatalf("unsafe-inline observation lost policy context: %+v", observation)
		}
	}
	if !hasObservation(report, UnsafeInlineEffective) {
		t.Fatalf("per-policy observation missing: %+v", report.Observations)
	}
}

func TestXFOFallbackAndAbsentControls(t *testing.T) {
	fallback := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		XFrameOptions: XFOEvidence{Present: true, Valid: true, Effective: "SAMEORIGIN"}})
	if fallback.Framing.Relation != XFOFallbackObserved {
		t.Fatalf("expected XFO fallback, got %+v", fallback.Framing)
	}

	neither := Analyze(Input{Captured: true, DocumentApplicability: Applicable})
	if neither.Framing.Relation != NoObservedFramingControl {
		t.Fatalf("expected no observed control, got %+v", neither.Framing)
	}
}

func TestUnknownApplicabilityAndTruncationMakeFramingIndeterminate(t *testing.T) {
	unknown := Analyze(Input{Captured: true, DocumentApplicability: ApplicabilityUnknown,
		XFrameOptions: XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if unknown.Framing.Relation != FramingIndeterminate {
		t.Fatalf("unknown applicability produced framing conclusion: %+v", unknown.Framing)
	}

	truncated := Analyze(Input{Captured: true, DocumentApplicability: Applicable,
		EnforcedFields: []string{strings.Repeat("a", maxFieldBytes+1)},
		XFrameOptions:  XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if truncated.Framing.Relation != FramingIndeterminate {
		t.Fatalf("truncated CSP produced framing conclusion: %+v", truncated.Framing)
	}
}

func TestUnavailableCaptureMakesFramingIndeterminate(t *testing.T) {
	report := Analyze(Input{DocumentApplicability: Applicable,
		XFrameOptions: XFOEvidence{Present: true, Valid: true, Effective: "DENY"}})
	if report.Framing.Relation != FramingIndeterminate {
		t.Fatalf("unavailable capture produced framing conclusion: %+v", report.Framing)
	}
}

func TestObservationsAreBounded(t *testing.T) {
	policies := make([]string, maxPoliciesPerDisposition)
	for index := range policies {
		policies[index] = "script-src 'unsafe-inline' *"
	}
	report := Analyze(Input{Captured: true, EnforcedFields: []string{strings.Join(policies, ",")}})
	if len(report.Observations) != maxObservations {
		t.Fatalf("observation limit = %d, want %d", len(report.Observations), maxObservations)
	}
	if !report.Truncated {
		t.Fatal("suppressed observations did not mark the report truncated")
	}
}

func TestObservationCapDoesNotTruncateAtExactCapacity(t *testing.T) {
	policies := make([]string, maxObservations/2)
	for index := range policies {
		policies[index] = "script-src 'unsafe-inline'; object-src 'none'"
	}
	report := Analyze(Input{Captured: true, EnforcedFields: []string{strings.Join(policies, ",")}})
	if len(report.Observations) != maxObservations {
		t.Fatalf("observation count = %d, want %d", len(report.Observations), maxObservations)
	}
	if report.Truncated {
		t.Fatal("exact observation capacity incorrectly marked the report truncated")
	}
}

func TestFallbackChainsSelectMostSpecificDirective(t *testing.T) {
	policy := onePolicy(t, "default-src 'none'; script-src 'self'; script-src-elem https:; style-src 'self'")
	assertControl(t, policy, "script-element", "script-src-elem", EffectiveExplicit)
	assertControl(t, policy, "script-attribute", "script-src", EffectiveFallback)
	assertControl(t, policy, "style-element", "style-src", EffectiveFallback)
	assertControl(t, policy, "image", "default-src", EffectiveFallback)
}

func TestNavigationDirectivesDoNotUseDefaultSrc(t *testing.T) {
	policy := onePolicy(t, "default-src 'none'")
	for _, control := range []string{"base-uri", "frame-ancestors", "form-action"} {
		assertControl(t, policy, control, "", EffectiveUnrestricted)
	}
}

func TestWorkerFallbackChainSelectsChildSrcBeforeScriptSrc(t *testing.T) {
	policy := onePolicy(t, "default-src 'none'; script-src https:; child-src 'self'")
	assertControl(t, policy, "worker", "child-src", EffectiveFallback)
}

func TestFrameFallbackChainSelectsChildSrcBeforeDefaultSrc(t *testing.T) {
	policy := onePolicy(t, "default-src 'none'; child-src 'self'")
	assertControl(t, policy, "frame", "child-src", EffectiveFallback)
}

func TestEffectiveControlSelectsEmptySourceList(t *testing.T) {
	policy := onePolicy(t, "default-src 'self'; img-src")
	control := assertControl(t, policy, "image", "img-src", EffectiveExplicit)
	if len(control.Sources) != 0 {
		t.Fatalf("empty source list was not retained as an explicit control: %+v", control)
	}
}

func TestEffectiveControlIsIndeterminateForInvalidSourceList(t *testing.T) {
	policy := onePolicy(t, "default-src 'self'; img-src unsafe-inline")
	assertControl(t, policy, "image", "", EffectiveIndeterminate)
}

func TestTruncatedPolicyHasNoEffectiveControls(t *testing.T) {
	policy := onePolicy(t, "default-src 'self'; script-src "+longToken())
	if len(policy.EffectiveControls) != 0 {
		t.Fatalf("truncated policy retained effective controls: %+v", policy.EffectiveControls)
	}
}

func TestEffectiveControlsUseEachNamedFetchDirective(t *testing.T) {
	policy := onePolicy(t, "script-src-attr 'self'; style-src-attr 'self'; worker-src 'self'; frame-src 'self'; object-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; media-src 'self'; manifest-src 'self'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")
	for control, directive := range map[string]string{
		"script-attribute": "script-src-attr",
		"style-attribute":  "style-src-attr",
		"worker":           "worker-src",
		"frame":            "frame-src",
		"object":           "object-src",
		"connect":          "connect-src",
		"image":            "img-src",
		"font":             "font-src",
		"media":            "media-src",
		"manifest":         "manifest-src",
		"base-uri":         "base-uri",
		"frame-ancestors":  "frame-ancestors",
		"form-action":      "form-action",
	} {
		assertControl(t, policy, control, directive, EffectiveExplicit)
	}
}

func TestEffectiveControlOwnsItsSourceList(t *testing.T) {
	policy := onePolicy(t, "img-src https://images.example.test")
	control := assertControl(t, policy, "image", "img-src", EffectiveExplicit)
	control.Sources[0].Host = "changed.example.test"
	if policy.Directives[0].Sources[0].Host == "changed.example.test" {
		t.Fatal("effective control shares source storage with its directive")
	}
}

func TestEffectiveControlIsIndeterminateForDiscardedNavigationCandidate(t *testing.T) {
	policy := onePolicy(t, "default-src 'self'; base-uri\x7f")
	if len(policy.Directives) != 1 || policy.Directives[0].Name != "default-src" {
		t.Fatalf("control-containing directive entered semantic parsing: %+v", policy.Directives)
	}
	assertControl(t, policy, "base-uri", "", EffectiveIndeterminate)
	assertControl(t, policy, "image", "default-src", EffectiveFallback)
}

func TestEffectiveControlIsIndeterminateForDiscardedImageCandidate(t *testing.T) {
	policy := onePolicy(t, "default-src 'self'; img-src\x7f")
	if len(policy.Directives) != 1 || policy.Directives[0].Name != "default-src" {
		t.Fatalf("control-containing directive entered semantic parsing: %+v", policy.Directives)
	}
	assertControl(t, policy, "image", "", EffectiveIndeterminate)
	assertControl(t, policy, "base-uri", "", EffectiveUnrestricted)
}

func TestEffectiveControlKeepsFirstValidDirectiveWhenMalformedDuplicateFollows(t *testing.T) {
	policy := onePolicy(t, "default-src 'self'; default-src\x7f; img-src 'self'; img-src\x7f")
	assertControl(t, policy, "image", "img-src", EffectiveExplicit)
	assertControl(t, policy, "script-element", "default-src", EffectiveFallback)
}

func TestEffectiveControlRemainsIndeterminateWhenDiscardedCandidateComesFirst(t *testing.T) {
	policy := onePolicy(t, "img-src\x7f; img-src 'self'")
	assertControl(t, policy, "image", "", EffectiveIndeterminate)
}

func TestDiscardedCandidateRespectsTokenBound(t *testing.T) {
	policy := onePolicy(t, strings.Repeat("a", maxFieldBytes-1)+"\x7f")
	if !policy.Truncated || len(policy.discardedDirectives) != 0 {
		t.Fatalf("overlong discarded name retained without truncation: %+v", policy)
	}
}

func TestDiscardedCandidatesRespectDirectiveCapacity(t *testing.T) {
	directives := make([]string, maxDirectivesPerPolicy-1)
	for index := range directives {
		directives[index] = "x" + strconv.Itoa(index)
	}
	field := strings.Join(directives, ";") + ";img-src\x7f;base-uri\x7f"
	policy := onePolicy(t, field)
	if !policy.Truncated || len(policy.discardedDirectives) != 1 || policy.discardedDirectives[0] != "img-src" {
		t.Fatalf("discarded candidates exceeded directive capacity: %+v", policy)
	}
}

func TestEffectiveControlStopsAtCompleteHigherPriorityDirective(t *testing.T) {
	policy := onePolicy(t, "img-src 'self'; default-src\x7f")
	assertControl(t, policy, "image", "img-src", EffectiveExplicit)

	policy = onePolicy(t, "script-src-elem 'self'; script-src\x7f; default-src\x7f")
	assertControl(t, policy, "script-element", "script-src-elem", EffectiveExplicit)
}

func TestRetainedDirectiveRespectsCombinedDirectiveCapacity(t *testing.T) {
	directives := make([]string, maxDirectivesPerPolicy-1)
	for index := range directives {
		directives[index] = "x" + strconv.Itoa(index)
	}
	field := strings.Join(directives, ";") + ";img-src\x7f;later-directive"
	policy := onePolicy(t, field)
	if !policy.Truncated || len(policy.Directives) != maxDirectivesPerPolicy-1 || len(policy.discardedDirectives) != 1 {
		t.Fatalf("retained directive exceeded combined capacity: %+v", policy)
	}
}

func onePolicy(t *testing.T, field string) Policy {
	t.Helper()
	report := Analyze(Input{Captured: true, EnforcedFields: []string{field}})
	if len(report.Enforced.Policies) != 1 {
		t.Fatalf("expected one policy, got %+v", report.Enforced)
	}
	return report.Enforced.Policies[0]
}

func assertControl(t *testing.T, policy Policy, control, directive string, status EffectiveStatus) EffectiveControl {
	t.Helper()
	for _, actual := range policy.EffectiveControls {
		if actual.Control == control {
			if actual.Directive != directive || actual.Status != status {
				t.Fatalf("control %q = %+v, want directive %q and status %q", control, actual, directive, status)
			}
			return actual
		}
	}
	t.Fatalf("control %q missing from %+v", control, policy.EffectiveControls)
	return EffectiveControl{}
}

func assertObservation(t *testing.T, field string, code ObservationCode, want bool) {
	t.Helper()
	report := Analyze(Input{Captured: true, DocumentApplicability: Applicable, EnforcedFields: []string{field}})
	if got := hasObservation(report, code); got != want {
		t.Fatalf("observation %q for %q = %t, want %t: %+v", code, field, got, want, report.Observations)
	}
}

func hasObservation(report Report, code ObservationCode) bool {
	for _, observation := range report.Observations {
		if observation.Code == code {
			return true
		}
	}
	return false
}

func longToken() string {
	return strings.Repeat("a", maxTokenBytes+1)
}
