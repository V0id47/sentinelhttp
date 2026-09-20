package findingengine

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"sentinelhttp/internal/core/network"
)

const maxFindings = 256
const maxEvidencePerFinding = 16

type candidate struct {
	rule       rule
	origin     string
	confidence Confidence
	refs       map[EvidenceRef]bool
}

type builder struct {
	candidates map[string]*candidate
}

func newBuilder() *builder { return &builder{candidates: make(map[string]*candidate)} }

func safeOrigin(value string) bool {
	target, err := network.ParseTarget(value)
	return err == nil && target.SafeURL() == value
}

func validExchangeID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func validEvidenceCode(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func validEvidenceSource(source EvidenceSource) bool {
	switch source {
	case TLSEvidence, HeaderEvidence, CookieEvidence, CSPEvidence, CORSProbeEvidence, RedirectEvidence:
		return true
	default:
		return false
	}
}

func stableID(ruleID, origin string) string {
	sum := sha256.Sum256([]byte("sentinelhttp-finding-v1\x00" + ruleID + "\x00" + origin))
	return hex.EncodeToString(sum[:])
}

// StableFindingID returns the version-1 identity derived from rule and safe
// origin. Consumers of persisted reports use the same derivation for validation.
func StableFindingID(ruleID, origin string) string { return stableID(ruleID, origin) }

func (b *builder) add(ruleID, origin string, confidence Confidence, ref EvidenceRef) {
	if b == nil || !safeOrigin(origin) || !validExchangeID(ref.ExchangeID) || !validEvidenceSource(ref.Source) || !validEvidenceCode(ref.Code) || ref.HopIndex < -1 || ref.ItemIndex < -1 {
		return
	}
	r, ok := lookupRule(ruleID)
	if !ok {
		return
	}
	if confidence != ConfidenceLow && confidence != ConfidenceMedium && confidence != ConfidenceHigh {
		confidence = r.Confidence
	}
	key := ruleID + "\x00" + origin
	c := b.candidates[key]
	if c == nil {
		c = &candidate{rule: r, origin: origin, confidence: confidence, refs: make(map[EvidenceRef]bool)}
		b.candidates[key] = c
	}
	if confidenceRank(confidence) < confidenceRank(c.confidence) {
		c.confidence = confidence
	}
	c.refs[ref] = true
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

func (b *builder) finish(report *Report) {
	if b == nil || report == nil {
		return
	}
	items := make([]*candidate, 0, len(b.candidates))
	for _, item := range b.candidates {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].rule.ID != items[j].rule.ID {
			return items[i].rule.ID < items[j].rule.ID
		}
		return items[i].origin < items[j].origin
	})
	for i, item := range items {
		if i >= maxFindings {
			report.OmittedFindings++
			report.Truncated = true
			continue
		}
		refs := make([]EvidenceRef, 0, len(item.refs))
		for ref := range item.refs {
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool {
			a, b := refs[i], refs[j]
			if a.Source != b.Source {
				return a.Source < b.Source
			}
			if a.ExchangeID != b.ExchangeID {
				return a.ExchangeID < b.ExchangeID
			}
			if a.HopIndex != b.HopIndex {
				return a.HopIndex < b.HopIndex
			}
			if a.ItemIndex != b.ItemIndex {
				return a.ItemIndex < b.ItemIndex
			}
			return a.Code < b.Code
		})
		if len(refs) > maxEvidencePerFinding {
			report.OmittedEvidence += len(refs) - maxEvidencePerFinding
			report.Truncated = true
			refs = refs[:maxEvidencePerFinding]
		}
		r := item.rule
		report.Findings = append(report.Findings, Finding{
			FindingID: stableID(r.ID, item.origin), RuleID: r.ID, RuleVersion: r.Version,
			Category: r.Category, Severity: r.Severity, Confidence: item.confidence, Target: item.origin,
			Evidence: refs, Observation: r.Observation, Inference: r.Inference,
			Hypothesis: r.Hypothesis, Impact: r.Impact, Remediation: r.Remediation,
			References: append([]string(nil), r.References...), Limitations: append([]string(nil), r.Limitations...),
		})
	}
}
