package reporting

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestPreflightAcceptsBuildDocument(t *testing.T) {
	doc := validReportDocument(t)
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightJSON(encoded); err != nil {
		t.Fatalf("valid Build JSON rejected: %v", err)
	}
}

func TestPreflightRejectsOverCapArrays(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		count  int
		suffix string
	}{
		{"requests", `{"requests":[`, 33, `]}`},
		{"case-folded requests", `{"REQUESTS":[`, 33, `]}`},
		{"redirects", `{"redirects":[`, 22, `]}`},
		{"findings", `{"findings":[`, 257, `]}`},
		{"limitations", `{"limitations":[`, 65, `]}`},
		{"resolution addresses", `{"requests":[{"resolution":{"addresses":[`, 65, `]}}]}`},
		{"TLS certificates", `{"requests":[{"tls":{"certificates":[`, 17, `]}}]}`},
		{"certificate SANs", `{"requests":[{"tls":{"certificates":[{"sans":[`, 129, `]}]}}]}`},
		{"headers", `{"requests":[{"headers":[`, 11, `]}]}`},
		{"cookies", `{"requests":[{"cookies":[`, 129, `]}]}`},
		{"CSP policies", `{"requests":[{"csp":{"policies":[`, 65, `]}}]}`},
		{"CSP directives", `{"requests":[{"csp":{"policies":[{"directives":[`, 65, `]}]}}]}`},
		{"CSP sources", `{"requests":[{"csp":{"policies":[{"directives":[{"sources":[`, 257, `]}]}]}}]}`},
		{"CSP observations", `{"requests":[{"csp":{"observations":[`, 65, `]}}]}`},
		{"CORS observations", `{"requests":[{"cors":{"observations":[`, 65, `]}}]}`},
		{"probe attempts", `{"cors_probe":{"attempts":[`, 4, `]}}`},
		{"probe CORS observations", `{"cors_probe":{"attempts":[{"cors":{"observations":[`, 65, `]}}]}}`},
		{"finding evidence", `{"findings":[{"evidence":[`, 17, `]}]}`},
		{"finding references", `{"findings":[{"references":[`, 17, `]}]}`},
		{"finding limitations", `{"findings":[{"limitations":[`, 17, `]}]}`},
		{"score components", `{"score":{"components":[`, 5, `]}}`},
		{"score penalties", `{"score":{"components":[{"penalties":[`, 17, `]}]}}`},
		{"score limitations", `{"score":{"limitations":[`, 17, `]}}`},
		{"unknown array", `{"unknown":[`, 257, `]}`},
		{"nested unknown array", `{"unknown":{"items":[`, 257, `]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.prefix + strings.TrimSuffix(strings.Repeat("{},", tc.count), ",") + tc.suffix)
			if err := preflightJSON(data); !errors.Is(err, ErrReportLimit) {
				t.Fatalf("over-cap array returned %v, want ErrReportLimit", err)
			}
		})
	}
}

func TestPreflightCapsRepeatedObjectMembers(t *testing.T) {
	members := make([]string, 65)
	for i := range members {
		members[i] = `"key` + strconv.Itoa(i) + `":0`
	}
	data := []byte(`{` + strings.Join(members, ",") + `}`)
	if err := preflightJSON(data); !errors.Is(err, ErrReportLimit) {
		t.Fatalf("repeated object members returned %v, want ErrReportLimit", err)
	}
}

func TestPreflightAcceptsArrayAtCap(t *testing.T) {
	data := []byte(`{"requests":[` + strings.TrimSuffix(strings.Repeat("{},", 32), ",") + `]}`)
	if err := preflightJSON(data); err != nil {
		t.Fatalf("32 requests rejected: %v", err)
	}
}

func TestPreflightRejectsDeepOrMalformedJSON(t *testing.T) {
	deep := []byte(strings.Repeat(`{"x":`, 33) + `null` + strings.Repeat(`}`, 33))
	if err := preflightJSON(deep); !errors.Is(err, ErrReportLimit) {
		t.Fatalf("deep JSON returned %v, want ErrReportLimit", err)
	}
	for _, data := range [][]byte{
		[]byte(`{"requests":[`),
		[]byte(`{"requests":[]} {}`),
		[]byte(`[]`),
	} {
		if err := preflightJSON(data); !errors.Is(err, ErrReportMalformed) {
			t.Fatalf("malformed JSON returned %v, want ErrReportMalformed", err)
		}
	}
}

func TestPreflightRejectsInputOverEightMiB(t *testing.T) {
	data := []byte(strings.Repeat(" ", MaxDocumentBytes+1))
	if err := preflightJSON(data); !errors.Is(err, ErrReportLimit) {
		t.Fatalf("oversized JSON returned %v, want ErrReportLimit", err)
	}
}
