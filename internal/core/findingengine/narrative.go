package findingengine

// Narrative is the versioned, catalog-owned explanatory prose for one rule.
// It is used only to verify localization eligibility, never as scan evidence.
type Narrative struct {
	RuleID      string   `json:"rule_id"`
	RuleVersion string   `json:"rule_version"`
	Observation string   `json:"observation"`
	Inference   string   `json:"inference"`
	Hypothesis  string   `json:"hypothesis"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	Limitations []string `json:"limitations"`
}

func CatalogNarratives() []Narrative {
	rules := allRules()
	result := make([]Narrative, 0, len(rules))
	for _, entry := range rules {
		result = append(result, Narrative{RuleID: entry.ID, RuleVersion: entry.Version,
			Observation: entry.Observation, Inference: entry.Inference,
			Hypothesis: entry.Hypothesis, Impact: entry.Impact,
			Remediation: entry.Remediation, Limitations: append([]string(nil), entry.Limitations...)})
	}
	return result
}

func CanonicalNarrative(ruleID, version string) (Narrative, bool) {
	for _, entry := range CatalogNarratives() {
		if entry.RuleID == ruleID && entry.RuleVersion == version {
			return entry, true
		}
	}
	return Narrative{}, false
}
