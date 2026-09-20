package redirectanalysis

import (
	"fmt"
	"strings"
	"testing"
)

func FuzzResolveLocation(f *testing.F) {
	for _, seed := range []string{
		"/next", "../next?token=a,b", "//other.invalid/path", "?q=1", "#fragment",
		"https://other.invalid/path", "http://[invalid", "/%zz", "/\\private",
		"/a\x00secret", "/a\u202esecret", strings.Repeat("a", 8193),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		const base = "https://start.invalid/a/page?q=0"
		first, firstState := ResolveLocation(base, []string{raw})
		second, secondState := ResolveLocation(base, []string{raw})
		if first != second || firstState != secondState || len(first) > 8192 {
			t.Fatal("nondeterministic or unbounded Location resolution")
		}
		if firstState != LocationValid && first != "" {
			t.Fatal("invalid Location returned a candidate")
		}
		duplicate, duplicateState := ResolveLocation(base, []string{raw, raw})
		if duplicate != "" || duplicateState != LocationAmbiguous {
			t.Fatal("duplicate Location treated as navigable")
		}
	})
}

func FuzzInvalidLocationNotReturned(f *testing.F) {
	for _, seed := range []string{"", "/next", "https://other.invalid/SECRET", "a,b", strings.Repeat("x", 8192)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		candidate, state := ResolveLocation("https://start.invalid/a", []string{raw + "\x00SECRET"})
		if candidate != "" || state != LocationInvalid || strings.Contains(fmt.Sprintf("%v", state), "SECRET") {
			t.Fatal("unsafe Location escaped into classified output")
		}
	})
}
