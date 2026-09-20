package reporting

import (
	"fmt"
	"sentinelhttp/internal/core/localization"
	"strings"
)

// markdownText escapes dynamic text in the Markdown text context, including
// raw HTML. Newlines were flattened by safeText, so content cannot add blocks.
func markdownText(value string) string {
	value = safeText(value)
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		switch r {
		case '&':
			out.WriteString("&amp;")
		case '<':
			out.WriteString("&lt;")
		case '>':
			out.WriteString("&gt;")
		case '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|', '~', '=':
			out.WriteByte('\\')
			out.WriteRune(r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func renderMarkdown(doc Document, lang localization.Locale) []byte {
	tr := func(value string) string { return localization.Text(lang, value) }
	var out strings.Builder
	fmt.Fprintf(&out, "# SentinelHTTP %s %s\n\n", tr("report"), markdownText(doc.SchemaVersion))
	fmt.Fprintf(&out, "%s: %s  \n", tr("Target"), markdownText(doc.Target))
	fmt.Fprintf(&out, "%s: %s  \n%s: %s  \n", tr("Started"), localization.FormatTime(lang, doc.StartedAt), tr("Completed"), localization.FormatTime(lang, doc.CompletedAt))
	fmt.Fprintf(&out, "%s: %d; %s: %d; %s: %d; %s: %d.  \n", tr("Requests"), len(doc.Requests), tr("redirects"), len(doc.Redirects), tr("probe attempts"), probeCount(doc), tr("findings"), len(doc.Findings))
	fmt.Fprintf(&out, "%s: %s.\n\n", tr("Configuration Score"), markdownText(scoreDisplay(doc, lang)))
	for _, limitation := range doc.Score.Limitations {
		fmt.Fprintf(&out, "%s: %s\n\n", tr("Score limitation"), markdownText(limitation))
	}
	if doc.Truncated || doc.OmittedInputs != 0 || doc.OmittedFindings != 0 || doc.OmittedEvidence != 0 {
		fmt.Fprintf(&out, "%s: %s %d, %s %d, %s %d, %s %d; %s.\n\n", tr("Partial evidence"), tr("omitted inputs"), doc.OmittedInputs, tr("findings"), doc.OmittedFindings, tr("evidence"), doc.OmittedEvidence, tr("cookie fields"), omittedCookieFields(doc), tr("analyzer truncation details are in JSON request sections"))
	}
	for i, f := range doc.Findings {
		fmt.Fprintf(&out, "## %d. %s\n\n", i+1, markdownText(f.RuleID))
		fmt.Fprintf(&out, "%s: %s; %s: %s; %s: %s.\n\n", tr("Severity"), markdownText(string(f.Severity)), tr("confidence"), markdownText(string(f.Confidence)), tr("target"), markdownText(f.Target))
		fmt.Fprintf(&out, "%s: %s\n\n%s: %s\n\n%s: %s\n\n%s: %s\n\n%s: %s\n\n", tr("Observation"), markdownText(f.Observation), tr("Inference"), markdownText(f.Inference), tr("Hypothesis"), markdownText(f.Hypothesis), tr("Impact"), markdownText(f.Impact), tr("Remediation"), markdownText(f.Remediation))
		for _, evidence := range f.Evidence {
			fmt.Fprintf(&out, "%s: %s %s, %s %s, %s %s, %s %d, %s %d.\n\n", tr("Evidence"), tr("exchange"), markdownText(evidence.ExchangeID), tr("source"), markdownText(string(evidence.Source)), tr("code"), markdownText(evidence.Code), tr("hop"), evidence.HopIndex, tr("item"), evidence.ItemIndex)
		}
		for _, reference := range f.References {
			fmt.Fprintf(&out, "%s: %s\n\n", tr("Reference"), markdownText(reference))
		}
		for _, limitation := range f.Limitations {
			fmt.Fprintf(&out, "%s: %s\n\n", tr("Limitation"), markdownText(limitation))
		}
	}
	for _, limitation := range doc.Limitations {
		fmt.Fprintf(&out, "%s: %s\n\n", tr("Limitation"), markdownText(limitation))
	}
	fmt.Fprintf(&out, "%s\n", tr(reportDisclaimer))
	return []byte(out.String())
}
