package findingengine

import "sentinelhttp/internal/core/httpclient"

const maxDistinctExchanges = 32
const maxInspectedExchanges = 256
const maxTraceHops = 21

// Evaluate assembles findings only from supplied evidence. It does not perform
// network I/O or mutate caller-owned responses, traces or probes.
func Evaluate(input Input) Report {
	report := Report{EngineVersion: EngineVersion}
	b := newBuilder()
	seen := make(map[string]*httpclient.Response)
	processed := 0
	visit := func(response *httpclient.Response, hopIndex int) bool {
		if response == nil {
			report.SkippedInputs++
			return false
		}
		meta := response.Metadata()
		if !validExchangeID(meta.ID) || !safeOrigin(meta.Target) {
			report.SkippedInputs++
			return false
		}
		if previous, found := seen[meta.ID]; found {
			if previous != response {
				report.SkippedInputs++
				return false
			}
			return true
		}
		if processed >= maxDistinctExchanges {
			report.OmittedInputs++
			report.Truncated = true
			return false
		}
		seen[meta.ID] = response
		processed++
		evaluateExchange(b, response, meta, hopIndex)
		return true
	}
	for index, response := range input.Exchanges {
		if index == maxInspectedExchanges {
			report.OmittedInputs += len(input.Exchanges) - index
			report.Truncated = true
			break
		}
		visit(response, -1)
	}
	lastTraceHopAdmitted := false
	if input.Trace != nil {
		for i, hop := range input.Trace.Hops {
			if i == maxTraceHops {
				report.OmittedInputs += len(input.Trace.Hops) - i
				report.Truncated = true
				break
			}
			lastTraceHopAdmitted = visit(hop.Response, i)
		}
	}
	evaluateCORS(b, input.CORSProbe, &report)
	if lastTraceHopAdmitted {
		evaluateTrace(b, input.Trace, &report)
	}
	b.finish(&report)
	return report
}
