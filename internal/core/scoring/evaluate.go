package scoring

import (
	"sort"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/httpclient"
)

// Evaluate scores only the supplied primary response. It does not perform I/O
// or mutate the response.
func Evaluate(primary *httpclient.Response) Report {
	components := eligibility(primary)
	if primary == nil {
		return calculate(components)
	}
	findings := findingengine.Evaluate(findingengine.Input{Exchanges: []*httpclient.Response{primary}})
	if findings.SkippedInputs != 0 || findings.Truncated || findings.OmittedInputs != 0 || findings.OmittedFindings != 0 || findings.OmittedEvidence != 0 || findings.EngineVersion != findingengine.EngineVersion {
		report := calculate(components)
		report.Target = primary.Metadata().Target
		report.Status, report.Value = ScoreInsufficientEvidence, nil
		return report
	}
	meta := primary.Metadata()
	for _, finding := range findings.Findings {
		if finding.Target != meta.Target || finding.RuleVersion != "1" {
			continue
		}
		fixed, ok := penaltyFor(finding.RuleID)
		if !ok {
			continue
		}
		for i := range components {
			if components[i].Domain == fixed.Domain && components[i].Status == ComponentAssessed {
				components[i].Penalties = append(components[i].Penalties, Penalty{RuleID: fixed.RuleID, Points: fixed.Points})
			}
		}
	}
	report := calculate(components)
	report.Target = meta.Target
	return report
}

func calculate(input [4]Component) Report {
	report := Report{ModelVersion: ModelVersion, Status: ScoreInsufficientEvidence, Label: Label,
		Components: make([]Component, 0, len(input)), Limitations: append([]string(nil), fixedLimitations[:]...)}
	assessedDomains := 0
	totalPenalty := 0
	for _, source := range input {
		component := Component{Domain: source.Domain, Weight: source.Weight, Status: source.Status}
		if component.Status != ComponentNotApplicable {
			report.PossibleWeight += component.Weight
		}
		if component.Status == ComponentAssessed {
			assessedDomains++
			report.AssessedWeight += component.Weight
			seen := make(map[string]bool)
			for _, penalty := range source.Penalties {
				if penalty.Points <= 0 || seen[penalty.RuleID] {
					continue
				}
				seen[penalty.RuleID] = true
				component.Penalties = append(component.Penalties, penalty)
			}
			sort.Slice(component.Penalties, func(i, j int) bool { return component.Penalties[i].RuleID < component.Penalties[j].RuleID })
			points := 0
			for _, penalty := range component.Penalties {
				points += penalty.Points
			}
			if points > component.Weight {
				points = component.Weight
			}
			totalPenalty += points
		}
		report.Components = append(report.Components, component)
	}
	if report.PossibleWeight > 0 {
		report.CoveragePercent = roundHalfUp(100*report.AssessedWeight, report.PossibleWeight)
	}
	if assessedDomains < 2 || report.AssessedWeight < 50 {
		return report
	}
	value := roundHalfUp(100*(report.AssessedWeight-totalPenalty), report.AssessedWeight)
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	report.Status, report.Value = ScoreAvailable, &value
	return report
}

func roundHalfUp(numerator, denominator int) int {
	if denominator <= 0 {
		return 0
	}
	return (numerator + denominator/2) / denominator
}
