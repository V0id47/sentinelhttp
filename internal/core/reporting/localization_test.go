package reporting

import (
	"bytes"
	"strings"
	"testing"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/localization"
)

func TestLocalizedHumanReportsKeepCanonicalJSONAndEscapeEvidence(t *testing.T) {
	doc := hostileReport(t)
	baseline, err := Render(doc, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, lang := range []localization.Locale{localization.Spanish, localization.Russian, localization.Chinese} {
		got, err := RenderLocalized(doc, FormatJSON, lang)
		if err != nil || !bytes.Equal(got, baseline) {
			t.Fatalf("JSON changed for %s: %v", lang, err)
		}
		terminal, err := RenderLocalized(doc, FormatTerminal, lang)
		if err != nil || !strings.Contains(string(terminal), localization.Text(lang, "Observation")+":") {
			t.Fatalf("terminal %s: %v", lang, err)
		}
		markdown, err := RenderLocalized(doc, FormatMarkdown, lang)
		if err != nil || strings.Contains(string(markdown), "<script>") {
			t.Fatalf("markdown %s: %v", lang, err)
		}
		html, err := RenderLocalized(doc, FormatHTML, lang)
		if err != nil || !strings.Contains(string(html), `lang="`+string(lang)+`"`) || strings.Contains(string(html), "<script>") {
			t.Fatalf("HTML %s: %v", lang, err)
		}
	}
}

func TestNarrativeTranslationRequiresExactRuleVersionAndText(t *testing.T) {
	doc := hostileReport(t)
	for i := range doc.Findings {
		f := &doc.Findings[i]
		n, ok := findingengine.CanonicalNarrative(f.RuleID, f.RuleVersion)
		if !ok {
			t.Fatal("missing fixture rule")
		}
		f.Observation, f.Inference, f.Hypothesis, f.Impact, f.Remediation = n.Observation, n.Inference, n.Hypothesis, n.Impact, n.Remediation
		f.Limitations = append([]string(nil), n.Limitations...)
	}
	first := doc.Findings[0].Observation
	translated, err := RenderLocalized(doc, FormatTerminal, localization.Spanish)
	if err != nil || !strings.Contains(string(translated), localization.Text(localization.Spanish, first)) {
		t.Fatalf("known narrative untranslated: %v", err)
	}
	doc.Findings[0].Observation = "Changed narrative: " + first
	fallback, err := RenderLocalized(doc, FormatTerminal, localization.Spanish)
	if err != nil || !strings.Contains(string(fallback), "Changed narrative: "+first) || !strings.Contains(string(fallback), "No hay traducción del hallazgo") {
		t.Fatalf("version fallback missing: %v", err)
	}
	doc.Findings[0].RuleVersion = "2"
	if got := localizedDocument(doc, localization.Spanish); !strings.Contains(strings.Join(got.Limitations, " "), "No hay traducción del hallazgo") {
		t.Fatal("unknown rule version lacks fallback")
	}
}
