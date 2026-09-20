package findingengine

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzStableFindingID(f *testing.F) {
	for _, seed := range [][2]string{{"headers.hsts_not_active", "https://example.test/[REDACTED]"}, {"", ""}, {"rule\x00name", "https://example.test/SECRET"}, {"x", string([]byte{0xff})}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, ruleID, origin string) {
		first := stableID(ruleID, origin)
		second := stableID(ruleID, origin)
		if first != second || len(first) != 64 {
			t.Fatal("finding ID is not stable SHA-256 hex")
		}
		if _, err := hex.DecodeString(first); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzUnsafePathNeverEntersFindings(f *testing.F) {
	for _, seed := range []string{"", "[REDACTED]", "?token=", "#fragment", "\x00", "../path"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, suffix string) {
		origin := "https://example.test/" + suffix + "SECRET"
		b := newBuilder()
		b.add("headers.hsts_not_active", origin, ConfidenceHigh, EvidenceRef{
			ExchangeID: strings.Repeat("a", 32), Source: HeaderEvidence,
			Code: "hsts_absent", HopIndex: -1, ItemIndex: -1,
		})
		report := Report{EngineVersion: EngineVersion}
		b.finish(&report)
		encoded, err := json.Marshal(report)
		if err != nil || len(report.Findings) != 0 || strings.Contains(string(encoded), "SECRET") {
			t.Fatalf("unsafe path entered findings: count=%d err=%v", len(report.Findings), err)
		}
	})
}
