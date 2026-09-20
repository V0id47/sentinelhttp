package redirectanalysis

import (
	"strings"
	"testing"
)

func TestIsFollowStatus(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		if !IsFollowStatus(status) {
			t.Fatalf("status %d should be followed", status)
		}
	}
	for _, status := range []int{200, 300, 304, 305, 306, 309, 399, 404} {
		if IsFollowStatus(status) {
			t.Fatalf("status %d should be terminal", status)
		}
	}
}

func TestResolveLocation(t *testing.T) {
	const base = "https://start.invalid/a/page?q=0"
	for _, tc := range []struct {
		name, value, want string
	}{
		{"relative parent and comma", "../next?token=a,b", "https://start.invalid/next?token=a,b"},
		{"root relative", "/next", "https://start.invalid/next"},
		{"scheme relative", "//other.invalid/path", "https://other.invalid/path"},
		{"query only", "?q=1", "https://start.invalid/a/page?q=1"},
		{"fragment only", "#part", "https://start.invalid/a/page?q=0#part"},
		{"absolute", "http://other.invalid/x", "http://other.invalid/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, state := ResolveLocation(base, []string{tc.value})
			if state != LocationValid || got != tc.want {
				t.Fatalf("resolved %q as %q (%s), want %q", tc.value, got, state, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		values []string
		want   LocationStatus
	}{
		{"missing", nil, LocationMissing},
		{"duplicate", []string{"/a", "/b"}, LocationAmbiguous},
		{"empty", []string{""}, LocationInvalid},
		{"bad escape", []string{"/%zz"}, LocationInvalid},
		{"backslash", []string{"/\\private"}, LocationInvalid},
		{"control", []string{"/a\x00SECRET"}, LocationInvalid},
		{"raw space", []string{"/a b"}, LocationInvalid},
		{"format rune", []string{"/a\u202eSECRET"}, LocationInvalid},
		{"invalid utf8", []string{string([]byte{0xff})}, LocationInvalid},
		{"oversized field", []string{strings.Repeat("a", 8193)}, LocationInvalid},
		{"oversized candidate", []string{strings.Repeat("a", 8190)}, LocationInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, state := ResolveLocation(base, tc.values)
			if state != tc.want || got != "" {
				t.Fatalf("unsafe Location returned candidate %q with state %s", got, state)
			}
		})
	}
}
