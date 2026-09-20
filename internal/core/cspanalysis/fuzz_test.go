package cspanalysis

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func FuzzAnalyze(f *testing.F) {
	for _, seed := range [][2]string{
		{"script-src 'self'", ""},
		{"script-src 'self'; script-src *", "report-uri /reports"},
		{"default-src 'none', img-src https://images.example.test/assets", "img-src *"},
		{"script-src unsafe-inline\x7f", "img-src \xff"},
		{"script-src " + strings.Repeat("a", maxTokenBytes+1), ""},
		{"img-src https://images.example.test:" + strings.Repeat("1", maxSourceComponentBytes+1), ""},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, enforced, reportOnly string) {
		input := Input{Captured: true, DocumentApplicability: Applicable,
			EnforcedFields: []string{enforced}, ReportOnlyFields: []string{reportOnly}}
		first, second := Analyze(input), Analyze(input)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("analysis is not deterministic")
		}
		assertReportBounds(t, first)
	})
}

func FuzzNonceHashPayloadsAreNeverRetained(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte("privacy-canary"))
	f.Add([]byte{0xff, 0x00, 0x7f})

	f.Fuzz(func(t *testing.T, payload []byte) {
		encoded := hex.EncodeToString(payload)
		if encoded == "" {
			encoded = "00"
		}
		nonceCanary := "CSPNONCE" + encoded
		hashCanary := "CSPHASH" + encoded
		report := Analyze(Input{Captured: true, EnforcedFields: []string{
			"script-src 'nonce-" + nonceCanary + "' 'sha256-" + hashCanary + "'",
		}})
		jsonReport, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		rendered := string(jsonReport) + fmt.Sprintf("%+v %#v", report, report)
		for _, canary := range []string{nonceCanary, hashCanary} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("rendered report retained nonce/hash payload %q", canary)
			}
		}
		assertReportBounds(t, report)
	})
}

func assertReportBounds(t *testing.T, report Report) {
	t.Helper()
	if len(report.Observations) > maxObservations {
		t.Fatalf("observation count exceeds bound: %d", len(report.Observations))
	}
	for _, set := range []PolicySet{report.Enforced, report.ReportOnly} {
		if len(set.Policies) > maxPoliciesPerDisposition {
			t.Fatalf("policy count exceeds bound: %d", len(set.Policies))
		}
		if set.Truncated && !report.Truncated {
			t.Fatal("truncated policy set did not propagate to report")
		}
		for _, policy := range set.Policies {
			if len(policy.Directives)+len(policy.discardedDirectives) > maxDirectivesPerPolicy {
				t.Fatalf("combined directive count exceeds bound: %d", len(policy.Directives)+len(policy.discardedDirectives))
			}
			if policy.Truncated {
				if !set.Truncated {
					t.Fatal("truncated policy did not propagate to its policy set")
				}
				if !report.Truncated {
					t.Fatal("truncated policy did not propagate to report")
				}
				if len(policy.EffectiveControls) != 0 {
					t.Fatalf("truncated policy retained effective controls: %+v", policy.EffectiveControls)
				}
				for _, observation := range report.Observations {
					if (observation.Directive != "" || observation.Control != "") && observation.Disposition == policy.Disposition && observation.FieldIndex == policy.FieldIndex && observation.MemberIndex == policy.MemberIndex {
						t.Fatalf("truncated policy retained policy-scoped observation: %+v", observation)
					}
				}
			}
			valueTokens := 0
			for _, directive := range policy.Directives {
				valueTokens += len(directive.Sources) + directive.OpaqueTokens
				for _, source := range directive.Sources {
					assertSourceBounds(t, source)
				}
			}
			if valueTokens > maxTokensPerPolicy {
				t.Fatalf("policy token count exceeds bound: %d", valueTokens)
			}
			for _, control := range policy.EffectiveControls {
				for _, source := range control.Sources {
					assertSourceBounds(t, source)
				}
			}
		}
	}
}

func assertSourceBounds(t *testing.T, source Source) {
	t.Helper()
	if len(source.Path) > maxSourcePathBytes || len(source.Scheme) > maxSourceComponentBytes || len(source.Host) > maxSourceComponentBytes || len(source.Port) > maxSourceComponentBytes || len(source.Algorithm) > maxSourceComponentBytes {
		t.Fatalf("source component exceeds retained bound: %+v", source)
	}
	if (source.Kind == SourceNonce || source.Kind == SourceHash) && !source.Redacted {
		t.Fatalf("nonce/hash source was not redacted: %+v", source)
	}
}
