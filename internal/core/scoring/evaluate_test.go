package scoring

import "testing"

func TestCalculateCoverageAndHalfUpRounding(t *testing.T) {
	components := [4]Component{
		{Domain: DomainTLS, Weight: 20, Status: ComponentAssessed},
		{Domain: DomainHeaders, Weight: 30, Status: ComponentAssessed, Penalties: []Penalty{{RuleID: "headers.hsts_not_active", Points: 12}}},
		{Domain: DomainCookies, Weight: 20, Status: ComponentNotApplicable},
		{Domain: DomainCSP, Weight: 30, Status: ComponentAssessed},
	}
	report := calculate(components)
	if report.ModelVersion != "1" || report.Label != "Configuration Score" || report.Status != ScoreAvailable || report.Value == nil || *report.Value != 85 {
		t.Fatalf("score contract or arithmetic changed: %+v", report)
	}
	if report.AssessedWeight != 80 || report.PossibleWeight != 80 || report.CoveragePercent != 100 {
		t.Fatalf("coverage arithmetic changed: %+v", report)
	}
}

func TestCalculateNeverRewardsUnavailableEvidence(t *testing.T) {
	components := [4]Component{
		{Domain: DomainTLS, Weight: 20, Status: ComponentUnavailable},
		{Domain: DomainHeaders, Weight: 30, Status: ComponentAssessed},
		{Domain: DomainCookies, Weight: 20, Status: ComponentNotApplicable},
		{Domain: DomainCSP, Weight: 30, Status: ComponentUnavailable},
	}
	report := calculate(components)
	if report.Status != ScoreInsufficientEvidence || report.Value != nil || report.CoveragePercent != 38 || report.AssessedWeight != 30 || report.PossibleWeight != 80 {
		t.Fatalf("insufficient evidence produced a numeric score: %+v", report)
	}
}

func TestCalculateDeduplicatesAndCapsDomainPenalty(t *testing.T) {
	components := [4]Component{
		{Domain: DomainTLS, Weight: 20, Status: ComponentAssessed},
		{Domain: DomainHeaders, Weight: 30, Status: ComponentAssessed, Penalties: []Penalty{
			{RuleID: "headers.nosniff_absent", Points: 20},
			{RuleID: "headers.hsts_not_active", Points: 20},
			{RuleID: "headers.nosniff_absent", Points: 20},
		}},
		{Domain: DomainCookies, Weight: 20, Status: ComponentNotApplicable},
		{Domain: DomainCSP, Weight: 30, Status: ComponentNotApplicable},
	}
	report := calculate(components)
	if report.Value == nil || *report.Value != 40 || len(report.Components[1].Penalties) != 2 || report.Components[1].Penalties[0].RuleID != "headers.hsts_not_active" {
		t.Fatalf("duplicate/capped penalty changed score or order: components=%+v score=%+v", report.Components, report)
	}
}
