package scoring

type rulePenalty struct {
	RuleID string
	Domain Domain
	Points int
}

var fixedRules = [...]rulePenalty{
	{"tls.leaf_expiring_soon", DomainTLS, 6},
	{"headers.hsts_not_active", DomainHeaders, 12},
	{"headers.nosniff_absent", DomainHeaders, 4},
	{"cookies.session_like_no_secure", DomainCookies, 6},
	{"cookies.session_like_no_httponly", DomainCookies, 4},
	{"csp.no_complete_enforcement", DomainCSP, 16},
	{"csp.unsafe_inline_observed", DomainCSP, 5},
	{"csp.unsafe_eval_observed", DomainCSP, 4},
}

var fixedLimitations = [...]string{
	"This score reflects only the checks performed on one captured response.",
	"It is not a security level, vulnerability count, exploitability estimate or site-wide guarantee.",
	"Missing or inapplicable controls do not earn points.",
}

func newComponents() [4]Component {
	return [4]Component{
		{Domain: DomainTLS, Weight: 20, Status: ComponentUnavailable},
		{Domain: DomainHeaders, Weight: 30, Status: ComponentUnavailable},
		{Domain: DomainCookies, Weight: 20, Status: ComponentUnavailable},
		{Domain: DomainCSP, Weight: 30, Status: ComponentUnavailable},
	}
}

func penaltyFor(ruleID string) (rulePenalty, bool) {
	for _, rule := range fixedRules {
		if rule.RuleID == ruleID {
			return rule, true
		}
	}
	return rulePenalty{}, false
}

// CatalogPenalty exposes the versioned penalty assignment for consumers that
// validate a persisted score. It returns values, never mutable catalog data.
func CatalogPenalty(ruleID string) (Domain, int, bool) {
	entry, ok := penaltyFor(ruleID)
	return entry.Domain, entry.Points, ok
}
