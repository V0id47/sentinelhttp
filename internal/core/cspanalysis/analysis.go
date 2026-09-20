package cspanalysis

import (
	"strings"
	"unicode/utf8"
)

const (
	maxFieldsPerDisposition   = 16
	maxFieldBytes             = 4096
	maxAggregateBytes         = 64 << 10
	maxPoliciesPerDisposition = 32
	maxDirectivesPerPolicy    = 64
	maxTokensPerPolicy        = 256
	maxTokenBytes             = 1024
	maxObservations           = 64
)

// Analyze turns captured CSP header fields into owned, bounded structural
// evidence and conservative configuration observations. It performs no I/O.
func Analyze(input Input) Report {
	report := Report{
		Capture:               CaptureUnavailable,
		DocumentApplicability: normalizeApplicability(input.DocumentApplicability),
		Enforced:              PolicySet{Disposition: Enforce},
		ReportOnly:            PolicySet{Disposition: ReportOnly},
		Framing:               FramingAssessment{Relation: FramingIndeterminate},
	}
	if !input.Captured {
		return report
	}

	remaining := maxAggregateBytes
	report.Capture = CaptureComplete
	report.Enforced = parseSet(input.EnforcedFields, Enforce, &remaining)
	report.ReportOnly = parseSet(input.ReportOnlyFields, ReportOnly, &remaining)
	deriveSetEffectiveControls(&report.Enforced)
	deriveSetEffectiveControls(&report.ReportOnly)
	report.Truncated = report.Enforced.Truncated || report.ReportOnly.Truncated
	assess(&report, input)
	return report
}

func deriveSetEffectiveControls(set *PolicySet) {
	if set == nil {
		return
	}
	for index := range set.Policies {
		deriveEffectiveControls(&set.Policies[index])
	}
}

func normalizeApplicability(value Applicability) Applicability {
	switch value {
	case Applicable, NotApplicable, ApplicabilityUnknown:
		return value
	default:
		return ApplicabilityUnknown
	}
}

func parseSet(fields []string, disposition Disposition, remaining *int) PolicySet {
	set := PolicySet{Disposition: disposition, FieldCount: len(fields)}
	for fieldIndex := range fields {
		if fieldIndex >= maxFieldsPerDisposition {
			set.Truncated = true
			set.OmittedPolicies += len(fields) - fieldIndex
			break
		}
		if len(set.Policies) >= maxPoliciesPerDisposition || remaining == nil || *remaining <= 0 {
			set.Truncated = true
			set.OmittedPolicies += len(fields) - fieldIndex
			break
		}

		field := fields[fieldIndex]
		if len(field) > maxFieldBytes || remaining == nil || *remaining < len(field) {
			set.Truncated = true
			// The field was not split, so it is known to contain at least one
			// omitted policy without traversing attacker-controlled delimiters.
			set.OmittedPolicies++
			continue
		}
		*remaining -= len(field)
		members := strings.Split(field, ",")

		for memberIndex, member := range members {
			if len(set.Policies) >= maxPoliciesPerDisposition {
				set.Truncated = true
				set.OmittedPolicies += len(members) - memberIndex
				set.OmittedPolicies += len(fields) - fieldIndex - 1
				return set
			}
			policy := parsePolicy(member, disposition, fieldIndex, memberIndex)
			set.Policies = append(set.Policies, policy)
			set.AnalyzedPolicies++
			if policy.Truncated {
				set.Truncated = true
			}
		}
	}
	return set
}

func parsePolicy(value string, disposition Disposition, fieldIndex, memberIndex int) Policy {
	policy := Policy{
		Disposition: disposition,
		FieldIndex:  fieldIndex,
		MemberIndex: memberIndex,
	}
	seen := make(map[string]int)
	valueTokens := 0

	for _, rawDirective := range strings.Split(value, ";") {
		tokens := splitASCIIWhitespace(rawDirective)
		if containsHTTPInvalidControl(rawDirective) {
			valueBoundExceeded := accountRejectedValueTokens(tokens, &valueTokens)
			recordDiscardedDirective(&policy, seen, rawDirective)
			if (len(tokens) > 0 && len(tokens[0]) > maxTokenBytes) || valueBoundExceeded {
				policy.Truncated = true
				break
			}
			policy.SyntaxIssues++
			continue
		}
		rawDirective = trimASCIIWhitespace(rawDirective)
		if rawDirective == "" {
			continue
		}
		tokens = splitASCIIWhitespace(rawDirective)
		if len(tokens) == 0 {
			continue
		}
		if len(tokens[0]) > maxTokenBytes {
			policy.Truncated = true
			break
		}
		if unsafeToken(tokens[0]) || !validDirectiveName(tokens[0]) {
			if accountRejectedValueTokens(tokens, &valueTokens) {
				policy.Truncated = true
				break
			}
			policy.SyntaxIssues++
			continue
		}

		name := lowerASCII(tokens[0])
		if index, exists := seen[name]; exists {
			valueBoundExceeded := accountRejectedValueTokens(tokens, &valueTokens)
			policy.Directives[index].IgnoredDuplicates++
			if valueBoundExceeded {
				policy.Truncated = true
				break
			}
			continue
		}
		if len(policy.Directives)+len(policy.discardedDirectives) >= maxDirectivesPerPolicy {
			policy.Truncated = true
			break
		}

		directive := Directive{
			Name:   name,
			Kind:   directiveKind(name),
			Status: DirectiveValid,
		}
		for _, token := range tokens[1:] {
			if len(token) > maxTokenBytes {
				policy.Truncated = true
				directive.Status = DirectiveTruncated
				break
			}
			if valueTokens >= maxTokensPerPolicy {
				policy.Truncated = true
				directive.Status = DirectiveTruncated
				break
			}
			valueTokens++
			if unsafeToken(token) {
				policy.SyntaxIssues++
				directive.Status = DirectivePartial
				if directive.Kind == DirectiveSourceList {
					directive.Sources = append(directive.Sources, Source{Kind: SourceInvalid})
					directive.Nonconforming = true
				}
				continue
			}
			if directive.Kind == DirectiveSourceList {
				if sourceRetentionLimitExceeded(token) {
					policy.Truncated = true
					directive.Status = DirectiveTruncated
					break
				}
				source := parseDirectiveSource(name, token)
				directive.Sources = append(directive.Sources, source)
				if !source.Valid {
					policy.SyntaxIssues++
					directive.Status = DirectivePartial
					directive.Nonconforming = true
				}
			} else {
				directive.OpaqueTokens++
			}
		}
		if directive.Kind == DirectiveSourceList && hasNoneWithOtherSource(directive.Sources) {
			directive.Nonconforming = true
			if name == "frame-ancestors" && directive.Status == DirectiveValid {
				directive.Status = DirectivePartial
				policy.SyntaxIssues++
			}
		}
		seen[name] = len(policy.Directives)
		policy.Directives = append(policy.Directives, directive)
		if policy.Truncated {
			break
		}
	}

	switch {
	case policy.Truncated:
		policy.Parse = ParseTruncated
	case len(policy.Directives) == 0:
		policy.Parse = ParseInvalid
	case policy.SyntaxIssues > 0:
		policy.Parse = ParsePartial
	default:
		policy.Parse = ParseValid
	}
	return policy
}

func splitASCIIWhitespace(value string) []string {
	return strings.FieldsFunc(value, isASCIIWhitespace)
}

func trimASCIIWhitespace(value string) string {
	return strings.TrimFunc(value, isASCIIWhitespace)
}

func isASCIIWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f'
}

func validDirectiveName(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}
	return true
}

func unsafeToken(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char >= 0x80 || char == 0x7f || (char < 0x20 && char != '\t') {
			return true
		}
	}
	return false
}

func containsHTTPInvalidControl(value string) bool {
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char == 0x7f || (char < 0x20 && char != '\t') {
			return true
		}
	}
	return false
}

// recordDiscardedDirective retains only a safe directive-name prefix from a
// control-containing token. The malformed token itself never enters semantic
// CSP parsing, but a known candidate must suppress conclusions for its chain.
func recordDiscardedDirective(policy *Policy, seen map[string]int, raw string) {
	if policy == nil {
		return
	}
	name := discardedDirectiveName(raw)
	if name == "" || !isControlFallbackDirective(name) {
		return
	}
	if _, exists := seen[name]; exists {
		return
	}
	for _, existing := range policy.discardedDirectives {
		if existing == name {
			return
		}
	}
	if len(policy.Directives)+len(policy.discardedDirectives) >= maxDirectivesPerPolicy {
		policy.Truncated = true
		return
	}
	policy.discardedDirectives = append(policy.discardedDirectives, name)
}

func discardedDirectiveName(raw string) string {
	start := 0
	for start < len(raw) && isASCIIWhitespaceByte(raw[start]) {
		start++
	}
	end := start
	for end < len(raw) {
		char := raw[end]
		if isASCIIWhitespaceByte(char) || char == 0x7f || (char < 0x20 && char != '\t') {
			break
		}
		end++
	}
	if end == start {
		return ""
	}
	name := raw[start:end]
	if len(name) > maxTokenBytes || unsafeToken(name) || !validDirectiveName(name) {
		return ""
	}
	return lowerASCII(name)
}

// accountRejectedValueTokens applies byte-only value-token accounting before a
// malformed, duplicate, or control-containing directive is semantically
// rejected. It stores no rejected values and preserves first-directive-wins.
func accountRejectedValueTokens(tokens []string, valueTokens *int) bool {
	if len(tokens) < 2 {
		return false
	}
	for _, token := range tokens[1:] {
		if len(token) > maxTokenBytes {
			return true
		}
		if valueTokens == nil || *valueTokens >= maxTokensPerPolicy {
			return true
		}
		*valueTokens++
	}
	return false
}

func isASCIIWhitespaceByte(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f'
}

func lowerASCII(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		builder.WriteByte(char)
	}
	return builder.String()
}

func directiveKind(name string) DirectiveKind {
	if isSourceListDirective(name) {
		return DirectiveSourceList
	}
	return DirectiveOpaque
}

func hasNoneWithOtherSource(sources []Source) bool {
	if len(sources) < 2 {
		return false
	}
	for _, source := range sources {
		if source.Kind == SourceKeyword && source.Keyword == "none" {
			return true
		}
	}
	return false
}
