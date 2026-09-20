package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/localization"
)

type Format string

const (
	FormatJSON     Format = "json"
	FormatTerminal Format = "terminal"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

const MaxRenderedBytes = 16 << 20

var ErrUnsupportedFormat = errors.New("report_format_unsupported")

const reportDisclaimer = "Findings describe performed checks. Absence of findings does not prove application security."

// Render validates the public DTO before writing any output. It performs no I/O.
func Render(doc Document, format Format) ([]byte, error) {
	return RenderLocalized(doc, format, localization.English)
}

// RenderLocalized translates only catalog-owned prose for human-readable
// formats. JSON remains canonical and language-neutral for reproducible diffing.
func RenderLocalized(doc Document, format Format, lang localization.Locale) ([]byte, error) {
	if err := Validate(doc); err != nil {
		return nil, err
	}
	if format != FormatJSON && lang != localization.English {
		doc = localizedDocument(doc, lang)
	}
	var output []byte
	var err error
	switch format {
	case FormatJSON:
		output, err = json.Marshal(doc)
	case FormatTerminal:
		output = renderTerminal(doc, lang)
	case FormatMarkdown:
		output = renderMarkdown(doc, lang)
	case FormatHTML:
		output, err = renderHTML(doc, lang)
	default:
		return nil, ErrUnsupportedFormat
	}
	if err != nil {
		return nil, err
	}
	if len(output) > MaxRenderedBytes {
		return nil, ErrReportLimit
	}
	return output, nil
}

func localizedDocument(doc Document, lang localization.Locale) Document {
	doc.Findings = append([]findingengine.Finding(nil), doc.Findings...)
	unknownNarrative := false
	for i := range doc.Findings {
		f := &doc.Findings[i]
		canonical, known := findingengine.CanonicalNarrative(f.RuleID, f.RuleVersion)
		if !known || f.Observation != canonical.Observation || f.Inference != canonical.Inference || f.Hypothesis != canonical.Hypothesis || f.Impact != canonical.Impact || f.Remediation != canonical.Remediation || !slices.Equal(f.Limitations, canonical.Limitations) {
			unknownNarrative = true
			continue
		}
		f.Observation = localization.Text(lang, f.Observation)
		f.Inference = localization.Text(lang, f.Inference)
		f.Hypothesis = localization.Text(lang, f.Hypothesis)
		f.Impact = localization.Text(lang, f.Impact)
		f.Remediation = localization.Text(lang, f.Remediation)
		f.Limitations = append([]string(nil), f.Limitations...)
		for j := range f.Limitations {
			f.Limitations[j] = localization.Text(lang, f.Limitations[j])
		}
	}
	doc.Limitations = append([]string(nil), doc.Limitations...)
	for i := range doc.Limitations {
		doc.Limitations[i] = localization.ReportLimitation(lang, doc.Limitations[i])
	}
	doc.Score.Limitations = append([]string(nil), doc.Score.Limitations...)
	for i := range doc.Score.Limitations {
		doc.Score.Limitations[i] = localization.ReportLimitation(lang, doc.Score.Limitations[i])
	}
	if unknownNarrative {
		doc.Limitations = append(doc.Limitations, localization.Text(lang, "Finding translation unavailable because rule version or text differs from the shipped catalog."))
	}
	return doc
}

// safeText removes characters that can control terminals or visually reorder
// an evidence statement. Format-specific escaping still follows this step.
func safeText(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			out.WriteByte(' ')
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func scoreDisplay(doc Document, lang localization.Locale) string {
	if doc.Score.Value == nil {
		return fmt.Sprintf("%s (%s %d%%)", safeText(localization.Text(lang, string(doc.Score.Status))), localization.Text(lang, "coverage"), doc.Score.CoveragePercent)
	}
	return fmt.Sprintf("%d/100 (%s %d%%)", *doc.Score.Value, localization.Text(lang, "coverage"), doc.Score.CoveragePercent)
}

func omittedCookieFields(doc Document) int {
	total := 0
	for _, request := range doc.Requests {
		total += request.CookieOmittedFields
	}
	return total
}
