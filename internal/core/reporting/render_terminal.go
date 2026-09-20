package reporting

import (
	"fmt"
	"sentinelhttp/internal/core/localization"
	"strings"
)

func renderTerminal(doc Document, lang localization.Locale) []byte {
	tr := func(value string) string { return localization.Text(lang, value) }
	var out strings.Builder
	fmt.Fprintf(&out, "SentinelHTTP %s %s\n", tr("report"), safeText(doc.SchemaVersion))
	fmt.Fprintf(&out, "%s: %s\n", tr("Target"), safeText(doc.Target))
	fmt.Fprintf(&out, "%s: %s\n%s: %s\n", tr("Started"), localization.FormatTime(lang, doc.StartedAt), tr("Completed"), localization.FormatTime(lang, doc.CompletedAt))
	fmt.Fprintf(&out, "%s: %d  %s: %d  %s: %d  %s: %d\n", tr("Requests"), len(doc.Requests), tr("Redirects"), len(doc.Redirects), tr("Probe attempts"), probeCount(doc), tr("Findings"), len(doc.Findings))
	fmt.Fprintf(&out, "%s: %s\n", tr("Configuration Score"), scoreDisplay(doc, lang))
	for _, limitation := range doc.Score.Limitations {
		fmt.Fprintf(&out, "%s: %s\n", tr("Score limitation"), safeText(limitation))
	}
	if doc.Truncated || doc.OmittedInputs != 0 || doc.OmittedFindings != 0 || doc.OmittedEvidence != 0 {
		fmt.Fprintf(&out, "%s: %s=%d %s=%d %s=%d %s=%d; %s\n", tr("Partial evidence"), tr("omitted inputs"), doc.OmittedInputs, tr("findings"), doc.OmittedFindings, tr("evidence"), doc.OmittedEvidence, tr("cookie fields"), omittedCookieFields(doc), tr("analyzer truncation details are in JSON request sections"))
	}
	for i, f := range doc.Findings {
		fmt.Fprintf(&out, "\n%d. %s [%s; %s %s]\n", i+1, safeText(f.RuleID), safeText(string(f.Severity)), tr("confidence"), safeText(string(f.Confidence)))
		fmt.Fprintf(&out, "   %s: %s\n", tr("Target"), safeText(f.Target))
		fmt.Fprintf(&out, "   %s: %s\n", tr("Observation"), safeText(f.Observation))
		fmt.Fprintf(&out, "   %s: %s\n", tr("Inference"), safeText(f.Inference))
		fmt.Fprintf(&out, "   %s: %s\n", tr("Hypothesis"), safeText(f.Hypothesis))
		fmt.Fprintf(&out, "   %s: %s\n", tr("Impact"), safeText(f.Impact))
		fmt.Fprintf(&out, "   %s: %s\n", tr("Remediation"), safeText(f.Remediation))
		for _, evidence := range f.Evidence {
			fmt.Fprintf(&out, "   %s: %s=%s %s=%s %s=%s %s=%d %s=%d\n", tr("Evidence"), tr("exchange"), safeText(evidence.ExchangeID), tr("source"), safeText(string(evidence.Source)), tr("code"), safeText(evidence.Code), tr("hop"), evidence.HopIndex, tr("item"), evidence.ItemIndex)
		}
		for _, reference := range f.References {
			fmt.Fprintf(&out, "   %s: %s\n", tr("Reference"), safeText(reference))
		}
		for _, limitation := range f.Limitations {
			fmt.Fprintf(&out, "   %s: %s\n", tr("Limitation"), safeText(limitation))
		}
	}
	for _, limitation := range doc.Limitations {
		fmt.Fprintf(&out, "%s: %s\n", tr("Limitation"), safeText(limitation))
	}
	fmt.Fprintf(&out, "%s\n", tr(reportDisclaimer))
	return []byte(out.String())
}

func probeCount(doc Document) int {
	if doc.CORSProbe == nil {
		return 0
	}
	return len(doc.CORSProbe.Attempts)
}
