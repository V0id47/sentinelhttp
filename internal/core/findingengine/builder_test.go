package findingengine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCatalogIsVersionedAndConservative(t *testing.T) {
	rules := allRules()
	if len(rules) != 12 {
		t.Fatalf("catalog size=%d, want 12", len(rules))
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.ID == "" || seen[rule.ID] || rule.Version != "1" || rule.Severity != SeverityInfo && rule.Severity != SeverityLow {
			t.Fatalf("invalid catalog rule: %+v", rule)
		}
		if rule.Observation == "" || rule.Inference == "" || rule.Hypothesis == "" || rule.Impact == "" || rule.Remediation == "" || len(rule.Limitations) == 0 || len(rule.References) == 0 {
			t.Fatalf("rule lacks a complete explanatory contract: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
}

func TestBuilderStableIdentityAggregationAndPrivacy(t *testing.T) {
	const origin = "https://example.test/[REDACTED]"
	first := EvidenceRef{ExchangeID: strings.Repeat("a", 32), Source: HeaderEvidence, Code: "hsts_absent", HopIndex: -1, ItemIndex: -1}
	second := EvidenceRef{ExchangeID: strings.Repeat("b", 32), Source: HeaderEvidence, Code: "hsts_absent", HopIndex: 0, ItemIndex: -1}
	b := newBuilder()
	b.add("headers.hsts_not_active", origin, ConfidenceHigh, second)
	b.add("headers.hsts_not_active", origin, ConfidenceHigh, first)
	b.add("headers.hsts_not_active", origin, ConfidenceHigh, first)
	report := Report{EngineVersion: "1"}
	b.finish(&report)
	if len(report.Findings) != 1 || len(report.Findings[0].Evidence) != 2 || report.Findings[0].FindingID != stableID("headers.hsts_not_active", origin) {
		t.Fatalf("aggregation failed: %+v", report)
	}
	if report.Findings[0].Evidence[0] != first || report.Findings[0].Evidence[1] != second {
		t.Fatalf("evidence is not sorted: %+v", report.Findings[0].Evidence)
	}
	if stableID("headers.hsts_not_active", origin) == stableID("headers.nosniff_absent", origin) || stableID("headers.hsts_not_active", origin) == stableID("headers.hsts_not_active", "https://other.test/[REDACTED]") || len(report.Findings[0].FindingID) != 64 {
		t.Fatal("finding ID does not distinguish rule and origin")
	}
	other := newBuilder()
	other.add("headers.hsts_not_active", origin, ConfidenceHigh, first)
	other.add("headers.hsts_not_active", origin, ConfidenceHigh, second)
	reversed := Report{EngineVersion: "1"}
	other.finish(&reversed)
	if fmt.Sprintf("%+v", report.Findings) != fmt.Sprintf("%+v", reversed.Findings) {
		t.Fatal("insertion order changed output")
	}
	b.add("headers.hsts_not_active", "https://example.test/SECRET", ConfidenceHigh, first)
	unsafe := Report{EngineVersion: "1"}
	b.finish(&unsafe)
	encoded, err := json.Marshal(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(encoded), fmt.Sprintf("%v", unsafe), fmt.Sprintf("%+v", unsafe), fmt.Sprintf("%#v", unsafe)} {
		if strings.Contains(rendered, "SECRET") {
			t.Fatalf("unsafe origin leaked into finding output: %s", rendered)
		}
	}
}

func TestBuilderLimitsAreCounted(t *testing.T) {
	b := newBuilder()
	for i := 0; i < 17; i++ {
		ref := EvidenceRef{ExchangeID: fmt.Sprintf("%032x", i), Source: HeaderEvidence, Code: "absent", HopIndex: -1, ItemIndex: -1}
		b.add("headers.hsts_not_active", "https://example.test/[REDACTED]", ConfidenceHigh, ref)
	}
	for i := 0; i < 257; i++ {
		ref := EvidenceRef{ExchangeID: fmt.Sprintf("%032x", i), Source: HeaderEvidence, Code: "absent", HopIndex: -1, ItemIndex: -1}
		b.add("headers.hsts_not_active", fmt.Sprintf("https://host%03d.example/[REDACTED]", i), ConfidenceHigh, ref)
	}
	report := Report{EngineVersion: "1"}
	b.finish(&report)
	if len(report.Findings) != 256 || report.OmittedFindings != 2 || report.OmittedEvidence != 1 || !report.Truncated {
		t.Fatalf("caps not recorded: count=%d omittedFindings=%d omittedEvidence=%d truncated=%t", len(report.Findings), report.OmittedFindings, report.OmittedEvidence, report.Truncated)
	}
}
