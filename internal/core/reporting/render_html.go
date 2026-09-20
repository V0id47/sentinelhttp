package reporting

import (
	"bytes"
	"fmt"
	"html/template"
	"sentinelhttp/internal/core/localization"
)

type htmlFinding struct {
	RuleID, Severity, Confidence, Target, Observation, Inference, Hypothesis, Impact, Remediation string
	Evidence, References, Limitations                                                             []string
}

type htmlReport struct {
	Lang                                             string
	Version, Target, Started, Completed, Score       string
	Requests, Redirects, ProbeAttempts, FindingCount int
	Partial                                          bool
	OmittedInputs, OmittedFindings, OmittedEvidence  int
	OmittedCookieFields                              int
	Findings                                         []htmlFinding
	ScoreLimitations                                 []string
	Limitations                                      []string
	Disclaimer                                       string
}

const reportHTMLTemplateText = `<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SentinelHTTP {{tr "report"}}</title></head><body>
<main><h1>SentinelHTTP {{tr "report"}} {{.Version}}</h1><p>{{tr "Target"}}: {{.Target}}</p><p>{{tr "Started"}}: {{.Started}}<br>{{tr "Completed"}}: {{.Completed}}</p>
<p>{{tr "Requests"}}: {{.Requests}}; {{tr "redirects"}}: {{.Redirects}}; {{tr "probe attempts"}}: {{.ProbeAttempts}}; {{tr "findings"}}: {{.FindingCount}}.</p>
<p>{{tr "Configuration Score"}}: {{.Score}}</p>{{range .ScoreLimitations}}<p>{{tr "Score limitation"}}: {{.}}</p>{{end}}
{{if .Partial}}<p>{{tr "Partial evidence"}}: {{tr "omitted inputs"}} {{.OmittedInputs}}, {{tr "findings"}} {{.OmittedFindings}}, {{tr "evidence"}} {{.OmittedEvidence}}, {{tr "cookie fields"}} {{.OmittedCookieFields}}; {{tr "analyzer truncation details are in JSON request sections"}}.</p>{{end}}
{{range .Findings}}<section><h2>{{.RuleID}}</h2><p>{{tr "Severity"}}: {{.Severity}}; {{tr "confidence"}}: {{.Confidence}}; {{tr "target"}}: {{.Target}}</p><p>{{tr "Observation"}}: {{.Observation}}</p><p>{{tr "Inference"}}: {{.Inference}}</p><p>{{tr "Hypothesis"}}: {{.Hypothesis}}</p><p>{{tr "Impact"}}: {{.Impact}}</p><p>{{tr "Remediation"}}: {{.Remediation}}</p>{{range .Evidence}}<p>{{tr "Evidence"}}: {{.}}</p>{{end}}{{range .References}}<p>{{tr "Reference"}}: {{.}}</p>{{end}}{{range .Limitations}}<p>{{tr "Limitation"}}: {{.}}</p>{{end}}</section>{{end}}
{{range .Limitations}}<p>{{tr "Limitation"}}: {{.}}</p>{{end}}<p>{{.Disclaimer}}</p></main></body></html>`

func renderHTML(doc Document, lang localization.Locale) ([]byte, error) {
	view := htmlReport{
		Lang:    string(lang),
		Version: safeText(doc.SchemaVersion), Target: safeText(doc.Target),
		Started: localization.FormatTime(lang, doc.StartedAt), Completed: localization.FormatTime(lang, doc.CompletedAt),
		Score: scoreDisplay(doc, lang), Requests: len(doc.Requests), Redirects: len(doc.Redirects), ProbeAttempts: probeCount(doc), FindingCount: len(doc.Findings),
		Partial:       doc.Truncated || doc.OmittedInputs != 0 || doc.OmittedFindings != 0 || doc.OmittedEvidence != 0,
		OmittedInputs: doc.OmittedInputs, OmittedFindings: doc.OmittedFindings, OmittedEvidence: doc.OmittedEvidence,
		OmittedCookieFields: omittedCookieFields(doc),
		Findings:            make([]htmlFinding, 0, len(doc.Findings)), ScoreLimitations: make([]string, 0, len(doc.Score.Limitations)), Limitations: make([]string, 0, len(doc.Limitations)), Disclaimer: localization.Text(lang, reportDisclaimer),
	}
	for _, limitation := range doc.Score.Limitations {
		view.ScoreLimitations = append(view.ScoreLimitations, safeText(limitation))
	}
	for _, f := range doc.Findings {
		item := htmlFinding{RuleID: safeText(f.RuleID), Severity: safeText(string(f.Severity)), Confidence: safeText(string(f.Confidence)), Target: safeText(f.Target), Observation: safeText(f.Observation), Inference: safeText(f.Inference), Hypothesis: safeText(f.Hypothesis), Impact: safeText(f.Impact), Remediation: safeText(f.Remediation), Evidence: make([]string, 0, len(f.Evidence)), References: make([]string, 0, len(f.References)), Limitations: make([]string, 0, len(f.Limitations))}
		for _, evidence := range f.Evidence {
			item.Evidence = append(item.Evidence, safeText(fmt.Sprintf("exchange %s, source %s, code %s, hop %d, item %d", evidence.ExchangeID, evidence.Source, evidence.Code, evidence.HopIndex, evidence.ItemIndex)))
		}
		for _, reference := range f.References {
			item.References = append(item.References, safeText(reference))
		}
		for _, limitation := range f.Limitations {
			item.Limitations = append(item.Limitations, safeText(limitation))
		}
		view.Findings = append(view.Findings, item)
	}
	for _, limitation := range doc.Limitations {
		view.Limitations = append(view.Limitations, safeText(limitation))
	}
	tmpl, err := template.New("report").Funcs(template.FuncMap{"tr": func(value string) string { return localization.Text(lang, value) }}).Parse(reportHTMLTemplateText)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, view); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
