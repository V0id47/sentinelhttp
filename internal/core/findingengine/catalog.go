package findingengine

type rule struct {
	ID, Version                                string
	Category                                   Category
	Severity                                   Severity
	Confidence                                 Confidence
	Observation, Inference, Hypothesis, Impact string
	Remediation                                string
	References, Limitations                    []string
}

var catalog = []rule{
	{
		ID: "headers.hsts_not_active", Version: "1", Category: CategoryHeaders, Severity: SeverityLow, Confidence: ConfidenceHigh,
		Observation: "At least one captured, applicable HTTPS response did not establish an active HSTS policy.",
		Inference:   "The observed response does not itself instruct compatible browsers to require HTTPS for this host.",
		Hypothesis:  "A browser without an existing HSTS policy could make a later HTTP request to this host.",
		Impact:      "Such a request could lose transport protection if the surrounding deployment permits HTTP.",
		Remediation: "Review the host's HTTPS policy and serve a valid positive Strict-Transport-Security max-age where appropriate.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc6797"},
		Limitations: []string{"This is one response, not a survey of every route or browser state.", "Preload enrollment is not assessed."},
	},
	{
		ID: "headers.nosniff_absent", Version: "1", Category: CategoryHeaders, Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Observation: "At least one captured HTML or JSON response did not include X-Content-Type-Options.",
		Inference:   "The observed response lacks this browser MIME-type hardening signal.",
		Hypothesis:  "Some clients may apply their own content-type interpretation in contexts where this header matters.",
		Impact:      "The absence may reduce defense in depth, depending on content and browser behavior.",
		Remediation: "Consider X-Content-Type-Options: nosniff alongside correct Content-Type values.",
		References:  []string{"https://fetch.spec.whatwg.org/#x-content-type-options-header"},
		Limitations: []string{"No MIME confusion or executable-content path was demonstrated."},
	},
	{
		ID: "cookies.session_like_no_secure", Version: "1", Category: CategoryCookies, Severity: SeverityLow, Confidence: ConfidenceLow,
		Observation: "An accepted cookie that appears session-like was observed without the Secure attribute on HTTPS.",
		Inference:   "The cookie may be sent on an HTTP request if the browser later makes one within its scope.",
		Hypothesis:  "If the cookie carries sensitive state, an unprotected request could expose that state.",
		Impact:      "Potential transport exposure depends on cookie purpose, browser behavior and whether HTTP is reachable.",
		Remediation: "Set Secure on cookies that carry session or other sensitive state.",
		References:  []string{"https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html"},
		Limitations: []string{"Session-like classification is a name/lifetime heuristic, not proof of authentication.", "Cookie values are not retained or inspected."},
	},
	{
		ID: "cookies.session_like_no_httponly", Version: "1", Category: CategoryCookies, Severity: SeverityLow, Confidence: ConfidenceLow,
		Observation: "An accepted cookie that appears session-like was observed without the HttpOnly attribute on HTTPS.",
		Inference:   "The observed cookie is not marked to restrict script access through HttpOnly.",
		Hypothesis:  "If the cookie carries sensitive state and script execution is possible, that state could be exposed.",
		Impact:      "Potential impact depends on cookie purpose and an independent script-execution condition.",
		Remediation: "Set HttpOnly on session or other sensitive cookies that do not require script access.",
		References:  []string{"https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html"},
		Limitations: []string{"This does not establish XSS or prove that the cookie authenticates a user."},
	},
	{
		ID: "csp.no_complete_enforcement", Version: "1", Category: CategoryCSP, Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Observation: "No complete enforced CSP policy was observed for an applicable HTML response.",
		Inference:   "The captured CSP fields do not establish an analyzable enforced policy for this response.",
		Hypothesis:  "A suitable enforced policy could add defense in depth for this document.",
		Impact:      "The effect depends on the document, scripts and other controls.",
		Remediation: "Review whether an enforced Content-Security-Policy is appropriate and deploy a tested policy.",
		References:  []string{"https://www.w3.org/TR/CSP3/"},
		Limitations: []string{"This is not proof of XSS and does not account for document content or meta policies."},
	},
	{
		ID: "csp.unsafe_inline_observed", Version: "1", Category: CategoryCSP, Severity: SeverityInfo, Confidence: ConfidenceMedium,
		Observation: "One enforced CSP policy has an effective unsafe-inline source within a parsed control.",
		Inference:   "That policy's selected control permits the observed inline script or style behavior under the parser's narrow conditions.",
		Hypothesis:  "A stricter policy could narrow the allowed inline behavior.",
		Impact:      "Actual behavior depends on all enforced policies and document content.",
		Remediation: "Review inline script/style needs and prefer a tested restrictive policy where practical.",
		References:  []string{"https://www.w3.org/TR/CSP3/"},
		Limitations: []string{"Other enforced policies may further restrict the combined result.", "No XSS or browser execution was demonstrated."},
	},
	{
		ID: "csp.unsafe_eval_observed", Version: "1", Category: CategoryCSP, Severity: SeverityInfo, Confidence: ConfidenceMedium,
		Observation: "One enforced CSP policy includes unsafe-eval in a parsed script control.",
		Inference:   "That policy does not restrict the affected evaluation behavior by itself.",
		Hypothesis:  "Removing unsafe-eval could strengthen defense in depth after compatibility testing.",
		Impact:      "The effect depends on all enforced policies and application code.",
		Remediation: "Review dynamic code-evaluation needs and remove unsafe-eval if compatible.",
		References:  []string{"https://www.w3.org/TR/CSP3/"},
		Limitations: []string{"Other enforced policies may narrow the combined result.", "No XSS was demonstrated."},
	},
	{
		ID: "cors.sampled_reflection_with_credentials", Version: "1", Category: CategoryCORS, Severity: SeverityLow, Confidence: ConfidenceLow,
		Observation: "Two synthetic origins were echoed with credential allowance in captured CORS samples.",
		Inference:   "The sampled responses are consistent with permissive credentialed CORS behavior.",
		Hypothesis:  "An authorized manual review could determine whether a sensitive authenticated resource is affected.",
		Impact:      "Exposure would depend on real credentials, resource sensitivity and browser behavior.",
		Remediation: "Review the origin allowlist and credential policy for resources carrying sensitive data.",
		References:  []string{"https://fetch.spec.whatwg.org/#http-cors-protocol"},
		Limitations: []string{"Only two fixed, unauthenticated origins were sampled.", "No confirmed data exposure is claimed."},
	},
	{
		ID: "cors.vary_origin_shared_cache", Version: "1", Category: CategoryCORS, Severity: SeverityLow, Confidence: ConfidenceLow,
		Observation: "A sampled origin-varying CORS response lacked Vary: Origin and advertised shared-cache freshness.",
		Inference:   "A shared cache could reuse a response across Origin request values under some deployments.",
		Hypothesis:  "Manual cache testing could determine whether this creates an observable mismatch.",
		Impact:      "Impact depends on the actual cache path, resource sensitivity and response handling.",
		Remediation: "Review Vary: Origin and shared-cache policy for origin-dependent responses.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc9110.html#name-vary", "https://www.rfc-editor.org/rfc/rfc9111"},
		Limitations: []string{"No shared cache was exercised and no data leak was demonstrated."},
	},
	{
		ID: "redirects.https_to_http_proposed", Version: "1", Category: CategoryRedirects, Severity: SeverityLow, Confidence: ConfidenceHigh,
		Observation: "A captured HTTPS redirect proposed an HTTP destination; SentinelHTTP blocked the next request.",
		Inference:   "A client that follows that Location could transition to an unencrypted URL.",
		Hypothesis:  "The redirect may weaken transport protection for clients that do not block the downgrade.",
		Impact:      "Potential impact depends on client behavior and the destination's actual service.",
		Remediation: "Review the redirect target and prefer an HTTPS destination where available.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc9110.html#name-redirection-3xx"},
		Limitations: []string{"The proposed HTTP destination was not requested by SentinelHTTP."},
	},
	{
		ID: "redirects.loop_or_limit", Version: "1", Category: CategoryRedirects, Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Observation: "The captured redirect journey stopped at an exact loop or configured redirect limit.",
		Inference:   "The observed chain did not reach a terminal non-redirect response within this operation.",
		Hypothesis:  "Some clients may experience failed or excessive navigation for this path.",
		Impact:      "This may affect availability or usability for the observed request journey.",
		Remediation: "Review the redirect chain and remove loops or unnecessary hops.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc9110.html#name-redirection-3xx"},
		Limitations: []string{"A configured limit is not proof that every client loops or fails."},
	},
	{
		ID: "tls.leaf_expiring_soon", Version: "1", Category: CategoryTLS, Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Observation: "The verified TLS connection presented a leaf certificate expiring within 30 days of observation.",
		Inference:   "Certificate renewal may be needed soon to maintain successful validation.",
		Hypothesis:  "If it is not renewed, future clients could reject the service after expiry.",
		Impact:      "Availability and trust effects depend on renewal and client trust configuration.",
		Remediation: "Check the renewal schedule and deploy a replacement certificate before expiry.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc5280"},
		Limitations: []string{"This is one verified connection at a captured instant; revocation was not checked."},
	},
}

func allRules() []rule {
	out := append([]rule(nil), catalog...)
	for i := range out {
		out[i].References = append([]string(nil), out[i].References...)
		out[i].Limitations = append([]string(nil), out[i].Limitations...)
	}
	return out
}

func lookupRule(id string) (rule, bool) {
	for _, entry := range catalog {
		if entry.ID == id {
			return entry, true
		}
	}
	return rule{}, false
}
