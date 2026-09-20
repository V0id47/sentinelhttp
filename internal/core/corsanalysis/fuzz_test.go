package corsanalysis

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func FuzzAnalyze(f *testing.F) {
	for _, seed := range [][2]string{
		{"*", "true"},
		{"https://a.invalid", "false"},
		{"https://a.invalid, https://b.invalid", "true"},
		{"https://a.invalid\x00hostile", "True"},
		{strings.Repeat("a", 4097), "true"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, origin, credentials string) {
		input := Input{Captured: true, StatusCode: 200, Headers: http.Header{
			"Access-Control-Allow-Origin":      {origin},
			"Access-Control-Allow-Credentials": {credentials},
		}}
		first, second := Analyze(input), Analyze(input)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("CORS analysis is not deterministic")
		}
		if first.Origin.Status != FieldValid && first.Origin.Value != "" || first.Credentials.Status != FieldValid && first.Credentials.Enabled {
			t.Fatalf("incomplete CORS evidence created positive fields: %+v", first)
		}
		if len(first.Origin.Value) > maxValueBytes || len(first.AllowHeaders.Tokens) > maxInputBytes {
			t.Fatal("CORS report exceeded bounds")
		}
	})
}

func FuzzInvalidValuesAreNotRetained(f *testing.F) {
	f.Add([]byte("probe"))
	f.Add([]byte{0xff, 0xfe})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		canary := "PRIVATE_CORS_CANARY_" + hex.EncodeToString(payload)
		value := "https://a.invalid\x00" + canary
		report := Analyze(Input{Captured: true, Headers: http.Header{
			"Access-Control-Allow-Origin": {value},
		}})
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		output := string(encoded) + fmt.Sprintf("%v %+v %#v", report, report, report)
		if strings.Contains(output, canary) {
			t.Fatal("invalid CORS field payload escaped into report")
		}
	})
}
