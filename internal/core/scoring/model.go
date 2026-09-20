// Package scoring calculates a conservative configuration score from one
// already-captured response. It performs no network or filesystem I/O.
package scoring

import "fmt"

const ModelVersion = "1"
const Label = "Configuration Score"

type Status string

const (
	ScoreAvailable            Status = "available"
	ScoreInsufficientEvidence Status = "insufficient_evidence"
)

type Domain string

const (
	DomainTLS     Domain = "tls"
	DomainHeaders Domain = "headers"
	DomainCookies Domain = "cookies"
	DomainCSP     Domain = "csp"
)

type ComponentStatus string

const (
	ComponentAssessed      ComponentStatus = "assessed"
	ComponentNotApplicable ComponentStatus = "not_applicable"
	ComponentUnavailable   ComponentStatus = "unavailable"
)

type Penalty struct {
	RuleID string `json:"rule_id"`
	Points int    `json:"points"`
}

type Component struct {
	Domain    Domain          `json:"domain"`
	Weight    int             `json:"weight"`
	Status    ComponentStatus `json:"status"`
	Penalties []Penalty       `json:"penalties"`
}

type Report struct {
	ModelVersion    string      `json:"model_version"`
	Status          Status      `json:"status"`
	Value           *int        `json:"value"`
	Label           string      `json:"label"`
	Target          string      `json:"target"`
	AssessedWeight  int         `json:"assessed_weight"`
	PossibleWeight  int         `json:"possible_weight"`
	CoveragePercent int         `json:"coverage_percent"`
	Components      []Component `json:"components"`
	Limitations     []string    `json:"limitations"`
}

func (r Report) String() string {
	if r.Value == nil {
		return fmt.Sprintf("configuration score: %s, coverage=%d%%", r.Status, r.CoveragePercent)
	}
	return fmt.Sprintf("configuration score: %d/100, coverage=%d%%", *r.Value, r.CoveragePercent)
}

func (r Report) GoString() string { return r.String() }
