package headeranalysis

import (
	"reflect"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzAnalyze(f *testing.F) {
	f.Add("text/html", "max-age=31536000", "default-src 'self'", "camera=(self)", "same-origin", "DENY")
	f.Add("application/json", "max-age=0", "\x00\xff", "camera=(\"https://example.test\")", "\x00\xff", "SAMEORIGIN")

	f.Fuzz(func(t *testing.T, contentType, hsts, csp, permissions, policy, xfo string) {
		input := Input{
			Captured: true, Scheme: "https", TLSVerified: true, StatusCode: 200,
			Headers: map[string][]string{
				"Content-Type":                 {contentType},
				"Strict-Transport-Security":    {hsts},
				"Content-Security-Policy":      {csp},
				"Permissions-Policy":           {permissions},
				"X-Content-Type-Options":       {policy, xfo},
				"Referrer-Policy":              {policy, xfo},
				"X-Frame-Options":              {xfo, policy},
				"Cross-Origin-Opener-Policy":   {policy, xfo},
				"Cross-Origin-Resource-Policy": {policy, xfo},
				"Cross-Origin-Embedder-Policy": {policy, xfo},
				"Server":                       {policy, xfo},
			},
		}
		first := Analyze(input)
		second := Analyze(input)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("analysis is not deterministic")
		}
		if len(first.Results) != len(allHeaderIDs) {
			t.Fatalf("got %d results, want %d", len(first.Results), len(allHeaderIDs))
		}

		total := 0
		for _, id := range allHeaderIDs {
			values := first.Values(id)
			if len(values) > maxValuesPerHeader {
				t.Fatalf("%s retained %d values", id, len(values))
			}
			for _, value := range values {
				total += len(value)
				if len(value) > maxValueBytes || !utf8.ValidString(value) {
					t.Fatalf("%s retained invalid or oversized evidence", id)
				}
				for _, current := range value {
					if unicode.IsControl(current) || unicode.Is(unicode.Cf, current) {
						t.Fatalf("%s retained unsafe character", id)
					}
				}
			}
		}
		if total > maxEvidenceBytes {
			t.Fatalf("retained %d bytes beyond budget", total)
		}
	})
}
