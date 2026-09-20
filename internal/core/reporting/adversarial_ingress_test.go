package reporting

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"sentinelhttp/internal/core/localization"
	"sentinelhttp/internal/core/network"
)

func TestParseRejectsAmbiguousObjectMembers(t *testing.T) {
	valid, err := json.Marshal(validReportDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, data string }{
		{"same known member", `{"tool":"sentinelhttp",` + string(valid[1:])},
		{"case folded known member", `{"TOOL":"sentinelhttp",` + string(valid[1:])},
		{"nested duplicate", `{"outer":{"name":1,"name":2}}`},
		{"nested case folded", `{"outer":{"name":1,"NAME":2}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := preflightJSON([]byte(tc.data)); !errors.Is(err, ErrReportMalformed) {
				t.Fatalf("preflight error = %v, want malformed", err)
			}
			if _, err := Parse([]byte(tc.data)); !errors.Is(err, ErrReportMalformed) {
				t.Fatalf("parse error = %v, want malformed", err)
			}
		})
	}
}

func FuzzParseUntrustedReport(f *testing.F) {
	target, err := network.ParseTarget("https://example.com/")
	if err != nil {
		f.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	valid, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at})
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := json.Marshal(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"schema_version":"1.0"}`))
	f.Add([]byte(`{"tool":"sentinelhttp","TOOL":"sentinelhttp"}`))
	f.Add([]byte(`{"requests":[{"id":"x"}],"unknown":{"nested":[1,2]}}`))
	f.Add([]byte(`{"target":"https://example.com/","findings":[{"observation":"<script>alert(1)</script>"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrReportMalformed) && !errors.Is(err, ErrReportInvalid) && !errors.Is(err, ErrReportUnsupported) && !errors.Is(err, ErrReportLimit) {
				t.Fatalf("unsafe parser error: %T %v", err, err)
			}
			return
		}
		for _, locale := range []localization.Locale{localization.English, localization.Spanish, localization.Russian, localization.Chinese} {
			for _, format := range []Format{FormatJSON, FormatTerminal, FormatMarkdown, FormatHTML} {
				if _, err := RenderLocalized(doc, format, locale); err != nil {
					t.Fatalf("validated report failed %s / %s: %v", format, locale, err)
				}
			}
		}
	})
}
