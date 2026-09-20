package localization

import (
	"strings"
	"testing"
	"time"
)

func TestLocalesAndFallback(t *testing.T) {
	for input, want := range map[string]Locale{"en": English, "es-AR": Spanish, "ru": Russian, "zh-CN": Chinese} {
		got, err := Parse(input)
		if err != nil || got != want {
			t.Fatalf("%q: %q %v", input, got, err)
		}
	}
	if _, err := Parse("de"); err != ErrUnsupported {
		t.Fatal(err)
	}
	if CatalogSize() < 300 {
		t.Fatal("catalog incomplete")
	}
	for _, lang := range []Locale{Spanish, Russian, Chinese} {
		if Text(lang, "Observation") == "Observation" {
			t.Fatalf("missing translation for %s", lang)
		}
		if Text(lang, "X-Content-Type-Options") != "X-Content-Type-Options" {
			t.Fatal("technical token translated")
		}
	}
}

func TestLocalizedTimeKeepsOffset(t *testing.T) {
	instant := time.Date(2026, 9, 20, 7, 4, 5, 0, time.UTC)
	for lang, prefix := range map[Locale]string{Spanish: "20/09/2026", Russian: "20.09.2026", Chinese: "2026年09月20日"} {
		got := FormatTime(lang, instant)
		if !strings.HasPrefix(got, prefix) || !strings.Contains(got, "Z") {
			t.Fatalf("%s: %s", lang, got)
		}
	}
}
