package corsanalysis

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unsafe"
)

func TestAnalyzeOriginAndCredentials(t *testing.T) {
	for _, test := range []struct {
		name        string
		headers     http.Header
		origin      FieldStatus
		kind        OriginKind
		value       string
		credentials FieldStatus
		enabled     bool
	}{
		{"absent", http.Header{}, FieldAbsent, OriginUnknown, "", FieldAbsent, false},
		{"wildcard", http.Header{"Access-Control-Allow-Origin": {"*"}}, FieldValid, OriginWildcard, "", FieldAbsent, false},
		{"literal null", http.Header{"Access-Control-Allow-Origin": {"null"}}, FieldValid, OriginNull, "", FieldAbsent, false},
		{"explicit origin", http.Header{"Access-Control-Allow-Origin": {"https://a.invalid"}}, FieldValid, OriginExplicit, "https://a.invalid", FieldAbsent, false},
		{"canonical IPv4 origin", http.Header{"Access-Control-Allow-Origin": {"http://127.0.0.1"}}, FieldValid, OriginExplicit, "http://127.0.0.1", FieldAbsent, false},
		{"out of range numeric host", http.Header{"Access-Control-Allow-Origin": {"http://999.999.999.999"}}, FieldInvalid, OriginUnknown, "", FieldAbsent, false},
		{"noncanonical IPv4 host", http.Header{"Access-Control-Allow-Origin": {"http://127.0.0.01"}}, FieldInvalid, OriginUnknown, "", FieldAbsent, false},
		{"hex numeric host", http.Header{"Access-Control-Allow-Origin": {"http://example.0x7f"}}, FieldInvalid, OriginUnknown, "", FieldAbsent, false},
		{"empty hex numeric host", http.Header{"Access-Control-Allow-Origin": {"http://example.0x"}}, FieldInvalid, OriginUnknown, "", FieldAbsent, false},
		{"mapped IPv6 with noncanonical dots", http.Header{"Access-Control-Allow-Origin": {"http://[::ffff:127.0.0.1]"}}, FieldInvalid, OriginUnknown, "", FieldAbsent, false},
		{"canonical mapped IPv6", http.Header{"Access-Control-Allow-Origin": {"http://[::ffff:7f00:1]"}}, FieldValid, OriginExplicit, "http://[::ffff:7f00:1]", FieldAbsent, false},
		{"path rejected", http.Header{"Access-Control-Allow-Origin": {"https://a.invalid/"}}, FieldInvalid, OriginUnknown, "", FieldAbsent, false},
		{"comma rejected", http.Header{"Access-Control-Allow-Origin": {"https://a.invalid, https://b.invalid"}}, FieldAmbiguous, OriginUnknown, "", FieldAbsent, false},
		{"duplicate ACAO", http.Header{"Access-Control-Allow-Origin": {"https://a.invalid", "https://a.invalid"}}, FieldAmbiguous, OriginUnknown, "", FieldAbsent, false},
		{"ACAC exact true", http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Credentials": {"true"}}, FieldValid, OriginWildcard, "", FieldValid, true},
		{"ACAC uppercase", http.Header{"Access-Control-Allow-Credentials": {"True"}}, FieldAbsent, OriginUnknown, "", FieldInvalid, false},
		{"ACAC duplicate", http.Header{"Access-Control-Allow-Credentials": {"true", "true"}}, FieldAbsent, OriginUnknown, "", FieldAmbiguous, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Analyze(Input{Captured: true, StatusCode: 200, Headers: test.headers})
			if got.Capture != CaptureComplete || got.StatusCode != 200 || got.Origin.Status != test.origin || got.Origin.Kind != test.kind || got.Origin.Value != test.value || got.Credentials.Status != test.credentials || got.Credentials.Enabled != test.enabled {
				t.Fatalf("unexpected CORS analysis: %+v", got)
			}
		})
	}
}

func TestUnavailableIsNotAbsence(t *testing.T) {
	got := Analyze(Input{})
	if got.Capture != CaptureUnavailable || len(got.Observations) != 0 {
		t.Fatalf("pre-header failure inferred absence: %+v", got)
	}
}

func TestCloneDoesNotAliasInput(t *testing.T) {
	headers := http.Header{"Access-Control-Allow-Origin": {"https://private-origin-canary.invalid"}}
	got := Analyze(Input{Captured: true, Headers: headers})
	headers.Set("Access-Control-Allow-Origin", "https://changed.invalid")
	if got.Origin.Value != "https://private-origin-canary.invalid" {
		t.Fatalf("report aliases header input: %+v", got.Origin)
	}
	clone := got.Clone()
	clone.Origin.Value = "https://changed.invalid"
	if got.Origin.Value != "https://private-origin-canary.invalid" {
		t.Fatal("clone aliases original")
	}
	for _, rendered := range []string{got.String(), fmt.Sprintf("%v %+v %#v", got, got, got)} {
		if strings.Contains(rendered, "private-origin-canary") {
			t.Fatalf("default formatting leaked origin: %q", rendered)
		}
	}
}

func TestMalformedValueIsInvalidWithoutRetention(t *testing.T) {
	const canary = "private-control-canary"
	got := Analyze(Input{Captured: true, Headers: http.Header{
		"Access-Control-Allow-Origin": {"https://a.invalid\x00" + canary},
	}})
	if got.Origin.Status != FieldInvalid || got.Truncated || got.Origin.Value != "" {
		t.Fatalf("unsafe field confused with omitted bytes: %+v", got)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), canary) {
		t.Fatal("invalid raw header was retained")
	}
	got = Analyze(Input{Captured: true, Headers: http.Header{
		"Access-Control-Allow-Credentials": {string([]byte{0xff, 0xfe})},
	}})
	if got.Credentials.Status != FieldInvalid || got.Truncated || got.Credentials.Enabled {
		t.Fatalf("invalid UTF-8 confused with truncation or enablement: %+v", got)
	}
}

func TestFieldAndAggregateBoundsSuppressSemantics(t *testing.T) {
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = "*"
	}
	got := Analyze(Input{Captured: true, Headers: http.Header{"Access-Control-Allow-Origin": tooMany}})
	if got.Origin.Status != FieldTruncated || got.Origin.Kind != OriginUnknown || !got.Truncated {
		t.Fatalf("field count bound did not suppress ACAO: %+v", got)
	}
	got = Analyze(Input{Captured: true, Headers: http.Header{"Access-Control-Allow-Credentials": {strings.Repeat("t", 4097)}}})
	if got.Credentials.Status != FieldTruncated || got.Credentials.Enabled || !got.Truncated {
		t.Fatalf("per-value bound did not suppress ACAC: %+v", got)
	}
	large := make([]string, 8)
	for i := range large {
		large[i] = strings.Repeat("a", 4096)
	}
	got = Analyze(Input{Captured: true, Headers: http.Header{
		"Access-Control-Allow-Origin":      large,
		"Access-Control-Allow-Credentials": {"true"},
	}})
	if got.Credentials.Status != FieldTruncated || got.Credentials.Enabled || !got.Truncated {
		t.Fatalf("aggregate bound did not suppress later field: %+v", got)
	}
}

func TestRetainedTokensOwnInputBytes(t *testing.T) {
	buf := []byte("x-sentinelhttp-probe")
	value := unsafe.String(&buf[0], len(buf))
	got := Analyze(Input{Captured: true, Headers: http.Header{"Access-Control-Allow-Headers": {value}}})
	if len(got.AllowHeaders.Tokens) != 1 || got.AllowHeaders.Tokens[0] != "x-sentinelhttp-probe" {
		t.Fatalf("valid token not retained: %+v", got.AllowHeaders)
	}
	buf[0] = 'z'
	if got.AllowHeaders.Tokens[0] != "x-sentinelhttp-probe" {
		t.Fatalf("retained token aliases mutable input: %+v", got.AllowHeaders)
	}
	clone := got.Clone()
	clone.AllowHeaders.Tokens[0] = "changed"
	if got.AllowHeaders.Tokens[0] != "x-sentinelhttp-probe" {
		t.Fatal("token slice clone aliases original")
	}
}
