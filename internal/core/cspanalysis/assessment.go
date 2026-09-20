package cspanalysis

var controlFallbacks = []struct {
	control string
	chain   []string
}{
	{"script-element", []string{"script-src-elem", "script-src", "default-src"}},
	{"script-attribute", []string{"script-src-attr", "script-src", "default-src"}},
	{"style-element", []string{"style-src-elem", "style-src", "default-src"}},
	{"style-attribute", []string{"style-src-attr", "style-src", "default-src"}},
	{"worker", []string{"worker-src", "child-src", "script-src", "default-src"}},
	{"frame", []string{"frame-src", "child-src", "default-src"}},
	{"object", []string{"object-src", "default-src"}},
	{"connect", []string{"connect-src", "default-src"}},
	{"image", []string{"img-src", "default-src"}},
	{"font", []string{"font-src", "default-src"}},
	{"media", []string{"media-src", "default-src"}},
	{"manifest", []string{"manifest-src", "default-src"}},
	{"base-uri", []string{"base-uri"}},
	{"frame-ancestors", []string{"frame-ancestors"}},
	{"form-action", []string{"form-action"}},
}

func isControlFallbackDirective(name string) bool {
	for _, fallback := range controlFallbacks {
		for _, candidate := range fallback.chain {
			if candidate == name {
				return true
			}
		}
	}
	return false
}

// deriveEffectiveControls resolves each supported CSP control within one policy.
// It does not combine policies, because enforced policies apply cumulatively.
func deriveEffectiveControls(policy *Policy) {
	if policy == nil {
		return
	}
	if policy.Truncated || policy.Parse == ParseInvalid {
		policy.EffectiveControls = nil
		return
	}

	policy.EffectiveControls = make([]EffectiveControl, 0, len(controlFallbacks))
	for _, fallback := range controlFallbacks {
		policy.EffectiveControls = append(policy.EffectiveControls, deriveEffectiveControl(policy, fallback.control, fallback.chain))
	}
}

func deriveEffectiveControl(policy *Policy, control string, chain []string) EffectiveControl {
	if policy.Truncated || policy.Parse == ParseInvalid {
		return EffectiveControl{Control: control, Status: EffectiveIndeterminate}
	}

	for index, name := range chain {
		if hasDiscardedDirective(policy, name) {
			return EffectiveControl{Control: control, Status: EffectiveIndeterminate}
		}
		directive, found := directiveByName(policy, name)
		if !found {
			continue
		}
		if directive.Kind != DirectiveSourceList || directive.Status != DirectiveValid {
			return EffectiveControl{Control: control, Status: EffectiveIndeterminate}
		}

		status := EffectiveFallback
		if index == 0 {
			status = EffectiveExplicit
		}
		return EffectiveControl{
			Control:   control,
			Directive: name,
			Status:    status,
			Sources:   append([]Source(nil), directive.Sources...),
		}
	}

	return EffectiveControl{Control: control, Status: EffectiveUnrestricted}
}

// assess records bounded configuration evidence without turning it into a
// finding, severity, or combined-policy conclusion.
func assess(report *Report, input Input) {
	if report == nil || report.Capture != CaptureComplete {
		return
	}

	completeEnforcement := hasCompleteEnforcedPolicy(report)
	fullyAnalyzedEnforcement := !report.Enforced.Truncated
	if fullyAnalyzedEnforcement && !completeEnforcement {
		addObservation(report, Observation{Code: EnforcementAbsent})
	}
	if fullyAnalyzedEnforcement && len(report.ReportOnly.Policies) > 0 && !completeEnforcement {
		addObservation(report, Observation{Code: ReportOnlyWithoutEnforcement, Disposition: ReportOnly})
	}

	for _, policy := range report.Enforced.Policies {
		assessPolicy(report, policy)
	}
	for _, policy := range report.ReportOnly.Policies {
		assessPolicy(report, policy)
	}
	assessGlobalAbsence(report)
	assessFraming(report, input.XFrameOptions)
}

func assessPolicy(report *Report, policy Policy) {
	if report == nil || policy.Truncated {
		return
	}
	for _, directive := range policy.Directives {
		context := Observation{
			Disposition: policy.Disposition,
			FieldIndex:  policy.FieldIndex,
			MemberIndex: policy.MemberIndex,
			Directive:   directive.Name,
		}
		if directive.IgnoredDuplicates > 0 {
			context.Code = DuplicateDirectiveIgnored
			addObservation(report, context)
		}
		if directive.Nonconforming {
			context.Code = SourceListNonconforming
			addObservation(report, context)
		}
	}
	for _, control := range policy.EffectiveControls {
		if control.Status != EffectiveExplicit && control.Status != EffectiveFallback {
			continue
		}
		context := Observation{
			Disposition: policy.Disposition,
			FieldIndex:  policy.FieldIndex,
			MemberIndex: policy.MemberIndex,
			Directive:   control.Directive,
			Control:     control.Control,
		}
		switch {
		case isScriptControl(control.Control) && unsafeInlineEffective(control, true):
			context.Code = UnsafeInlineEffective
			addObservation(report, context)
		case isStyleControl(control.Control) && unsafeInlineEffective(control, false):
			context.Code = UnsafeInlineEffective
			addObservation(report, context)
		}
		if isScriptControl(control.Control) && containsKeyword(control, "unsafe-eval") {
			context.Code = UnsafeEvalPresent
			addObservation(report, context)
		}
		if containsGeneralWildcard(control) {
			context.Code = GeneralWildcardPresent
			addObservation(report, context)
		}
		if control.Control == "object" && objectSourcesPermitted(control) {
			context.Code = ObjectSourcesPermitted
			addObservation(report, context)
		}
	}
}

func unsafeInlineEffective(control EffectiveControl, script bool) bool {
	if !containsKeyword(control, "unsafe-inline") {
		return false
	}
	for _, source := range control.Sources {
		if source.Kind == SourceNonce || source.Kind == SourceHash {
			return false
		}
		if script && source.Kind == SourceKeyword && source.Keyword == "strict-dynamic" {
			return false
		}
	}
	return true
}

func containsKeyword(control EffectiveControl, keyword string) bool {
	for _, source := range control.Sources {
		if source.Kind == SourceKeyword && source.Keyword == keyword {
			return true
		}
	}
	return false
}

func containsGeneralWildcard(control EffectiveControl) bool {
	for _, source := range control.Sources {
		if source.Kind == SourceWildcard {
			return true
		}
	}
	return false
}

func assessGlobalAbsence(report *Report) {
	if report == nil || !completeEnforcedEvidence(report) {
		return
	}
	allObjectUnrestricted := true
	allBaseAbsent := true
	allFrameAncestorsAbsent := true
	allFormActionAbsent := true
	for _, policy := range report.Enforced.Policies {
		if controlByName(policy, "object").Status != EffectiveUnrestricted {
			allObjectUnrestricted = false
		}
		if controlByName(policy, "base-uri").Status != EffectiveUnrestricted {
			allBaseAbsent = false
		}
		if controlByName(policy, "frame-ancestors").Status != EffectiveUnrestricted {
			allFrameAncestorsAbsent = false
		}
		if controlByName(policy, "form-action").Status != EffectiveUnrestricted {
			allFormActionAbsent = false
		}
	}
	if allObjectUnrestricted {
		addObservation(report, Observation{Code: ObjectControlAbsent})
	}
	if report.DocumentApplicability != Applicable {
		return
	}
	if allBaseAbsent {
		addObservation(report, Observation{Code: BaseURIControlAbsent})
	}
	if allFrameAncestorsAbsent {
		addObservation(report, Observation{Code: FrameAncestorsControlAbsent})
	}
	if allFormActionAbsent {
		addObservation(report, Observation{Code: FormActionControlAbsent})
	}
}

func assessFraming(report *Report, xfo XFOEvidence) {
	if report == nil {
		return
	}
	report.Framing = FramingAssessment{
		Relation:     FramingIndeterminate,
		XFOPresent:   xfo.Present,
		XFOValid:     xfo.Valid,
		XFOEffective: xfo.Effective,
	}
	if report.Capture != CaptureComplete || report.DocumentApplicability != Applicable {
		return
	}
	for _, policy := range report.Enforced.Policies {
		directive, found := directiveByName(&policy, "frame-ancestors")
		if found && directive.Kind == DirectiveSourceList && directive.Status != DirectiveTruncated {
			report.Framing.CSPFrameAncestors = true
			report.Framing.Relation = CSPOverridesXFO
			return
		}
	}
	if !completeFrameAncestorsEvidence(report) {
		return
	}
	if xfo.Present && xfo.Valid {
		report.Framing.Relation = XFOFallbackObserved
		return
	}
	report.Framing.Relation = NoObservedFramingControl
}

func addObservation(report *Report, observation Observation) {
	if report == nil {
		return
	}
	if len(report.Observations) >= maxObservations {
		report.Truncated = true
		return
	}
	report.Observations = append(report.Observations, observation)
}

func completePolicy(policy Policy) bool {
	return policy.Parse == ParseValid && !policy.Truncated
}

func hasCompleteEnforcedPolicy(report *Report) bool {
	if report == nil {
		return false
	}
	for _, policy := range report.Enforced.Policies {
		if completePolicy(policy) {
			return true
		}
	}
	return false
}

func completeEnforcedEvidence(report *Report) bool {
	if !completeEnforcedSet(report) || len(report.Enforced.Policies) == 0 {
		return false
	}
	return true
}

// completeFrameAncestorsEvidence is narrower than completeEnforcedSet: unrelated
// invalid or partial directives do not hide the absence of frame-ancestors.
func completeFrameAncestorsEvidence(report *Report) bool {
	if report == nil || report.Capture != CaptureComplete || report.Enforced.Truncated {
		return false
	}
	for index := range report.Enforced.Policies {
		policy := &report.Enforced.Policies[index]
		if policy.Truncated || hasDiscardedDirective(policy, "frame-ancestors") {
			return false
		}
	}
	return true
}

func completeEnforcedSet(report *Report) bool {
	if report == nil || report.Capture != CaptureComplete || report.Enforced.Truncated {
		return false
	}
	for _, policy := range report.Enforced.Policies {
		if !completePolicy(policy) {
			return false
		}
	}
	return true
}

func controlByName(policy Policy, name string) EffectiveControl {
	for _, control := range policy.EffectiveControls {
		if control.Control == name {
			return control
		}
	}
	return EffectiveControl{Control: name, Status: EffectiveIndeterminate}
}

func isScriptControl(name string) bool {
	return name == "script-element" || name == "script-attribute"
}

func isStyleControl(name string) bool {
	return name == "style-element" || name == "style-attribute"
}

func objectSourcesPermitted(control EffectiveControl) bool {
	for _, source := range control.Sources {
		switch source.Kind {
		case SourceScheme, SourceHost, SourceWildcard:
			return true
		case SourceKeyword:
			if source.Keyword == "self" {
				return true
			}
		}
	}
	return false
}

func hasDiscardedDirective(policy *Policy, name string) bool {
	for _, candidate := range policy.discardedDirectives {
		if candidate == name {
			return true
		}
	}
	return false
}

func directiveByName(policy *Policy, name string) (Directive, bool) {
	for _, directive := range policy.Directives {
		if directive.Name == name {
			return directive, true
		}
	}
	return Directive{}, false
}
