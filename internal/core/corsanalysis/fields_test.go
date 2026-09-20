package corsanalysis

import (
	"net/http"
	"testing"
)

func TestAnalyzeVaryAndLists(t *testing.T) {
	t.Run("repeated vary and explicit freshness", func(t *testing.T) {
		got := Analyze(Input{Captured: true, Headers: http.Header{
			"Vary":          {"Accept-Encoding", "Origin"},
			"Cache-Control": {"public, max-age=60"},
		}})
		if got.Vary.Status != FieldValid || !got.Vary.Origin || got.Vary.Star || !got.Cache.FreshShared {
			t.Fatalf("vary/cache evidence lost: %+v", got)
		}
	})
	t.Run("vary star", func(t *testing.T) {
		got := Analyze(Input{Captured: true, Headers: http.Header{"Vary": {"*"}}})
		if got.Vary.Status != FieldValid || !got.Vary.Star || got.Vary.Origin {
			t.Fatalf("vary star confused with Origin: %+v", got.Vary)
		}
	})
	t.Run("invalid vary", func(t *testing.T) {
		got := Analyze(Input{Captured: true, Headers: http.Header{"Vary": {"Origin;bad"}}})
		if got.Vary.Status != FieldInvalid || got.Vary.Origin || got.Vary.Star {
			t.Fatalf("invalid Vary created positive evidence: %+v", got.Vary)
		}
	})
	t.Run("allow headers and methods", func(t *testing.T) {
		got := Analyze(Input{Captured: true, Headers: http.Header{
			"Access-Control-Allow-Headers":  {"X-SentinelHTTP-Probe, Content-Type"},
			"Access-Control-Allow-Methods":  {"GET, OPTIONS"},
			"Access-Control-Expose-Headers": {"X-Trace"},
		}})
		if got.AllowHeaders.Status != FieldValid || len(got.AllowHeaders.Tokens) != 2 || got.AllowHeaders.Tokens[0] != "x-sentinelhttp-probe" || got.AllowMethods.Status != FieldValid || len(got.AllowMethods.Tokens) != 2 || got.ExposeHeaders.Status != FieldValid {
			t.Fatalf("token lists lost: %+v", got)
		}
	})
	t.Run("wildcard allowed list", func(t *testing.T) {
		got := Analyze(Input{Captured: true, Headers: http.Header{"Access-Control-Allow-Headers": {"*"}}})
		if got.AllowHeaders.Status != FieldValid || !got.AllowHeaders.Wildcard {
			t.Fatalf("wildcard not retained: %+v", got.AllowHeaders)
		}
	})
	t.Run("invalid list", func(t *testing.T) {
		got := Analyze(Input{Captured: true, Headers: http.Header{"Access-Control-Allow-Headers": {"X-Good, bad name"}}})
		if got.AllowHeaders.Status != FieldInvalid || len(got.AllowHeaders.Tokens) != 0 {
			t.Fatalf("invalid list retained tokens: %+v", got.AllowHeaders)
		}
	})
	for _, tc := range []struct {
		name    string
		value   string
		status  FieldStatus
		seconds uint64
	}{
		{"valid max age", "600", FieldValid, 600},
		{"negative max age", "-1", FieldInvalid, 0},
		{"overflow max age", "999999999999999999999999", FieldInvalid, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(Input{Captured: true, Headers: http.Header{"Access-Control-Max-Age": {tc.value}}})
			if got.MaxAge.Status != tc.status || got.MaxAge.Seconds != tc.seconds {
				t.Fatalf("max age mismatch: %+v", got.MaxAge)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		value string
		fresh bool
	}{
		{"public freshness", "public, max-age=60", true},
		{"shared freshness", "s-maxage=60", true},
		{"shared zero overrides max age", "public, max-age=60, s-maxage=0", false},
		{"shared positive overrides max age zero", "public, max-age=0, s-maxage=60", true},
		{"private overrides", "public, max-age=60, private", false},
		{"no-store overrides", "public, max-age=60, no-store", false},
		{"no-cache overrides", "public, max-age=60, no-cache", false},
		{"duplicate age ambiguous", "public, max-age=60, max-age=120", false},
		{"no freshness", "public", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(Input{Captured: true, Headers: http.Header{"Cache-Control": {tc.value}}})
			if got.Cache.FreshShared != tc.fresh {
				t.Fatalf("cache freshness mismatch: %+v", got.Cache)
			}
		})
	}
}
