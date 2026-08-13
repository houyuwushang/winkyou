package solver

// CloneProbeResultSummary returns an owned summary without changing the
// nil-versus-empty boundary of Details.
func CloneProbeResultSummary(summary ProbeResultSummary) ProbeResultSummary {
	cloned := summary
	cloned.Details = cloneDomainStringMap(summary.Details)
	return cloned
}

// NormalizeProbeResultSummary canonicalizes an empty Details map to nil and
// owns every mutable value.
func NormalizeProbeResultSummary(summary ProbeResultSummary) ProbeResultSummary {
	normalized := CloneProbeResultSummary(summary)
	if len(normalized.Details) == 0 {
		normalized.Details = nil
	}
	return normalized
}

// CloneProbeStep returns an owned step without changing Params ordering,
// values, or its nil-versus-empty boundary.
func CloneProbeStep(step ProbeStep) ProbeStep {
	cloned := step
	cloned.Params = cloneDomainStringMap(step.Params)
	return cloned
}

// NormalizeProbeStep canonicalizes an empty Params map to nil. Action and
// Timeout remain unchanged because step ordering and timing are semantic.
func NormalizeProbeStep(step ProbeStep) ProbeStep {
	normalized := CloneProbeStep(step)
	if len(normalized.Params) == 0 {
		normalized.Params = nil
	}
	return normalized
}

// CloneProbeScript returns an owned script and preserves step order plus
// nil-versus-empty collection boundaries.
func CloneProbeScript(script ProbeScript) ProbeScript {
	cloned := script
	if script.Steps == nil {
		cloned.Steps = nil
		return cloned
	}
	cloned.Steps = make([]ProbeStep, len(script.Steps))
	for i := range script.Steps {
		cloned.Steps[i] = CloneProbeStep(script.Steps[i])
	}
	return cloned
}

// NormalizeProbeScript preserves semantic step order while canonicalizing
// empty steps and parameter maps to nil.
func NormalizeProbeScript(script ProbeScript) ProbeScript {
	normalized := script
	if len(script.Steps) == 0 {
		normalized.Steps = nil
		return normalized
	}
	normalized.Steps = make([]ProbeStep, len(script.Steps))
	for i := range script.Steps {
		normalized.Steps[i] = NormalizeProbeStep(script.Steps[i])
	}
	return normalized
}

// CloneProbeResult returns an owned result, including every observation map,
// without changing event order or nil-versus-empty boundaries.
func CloneProbeResult(result ProbeResult) ProbeResult {
	cloned := result
	cloned.Events = CloneObservations(result.Events)
	return cloned
}

// NormalizeProbeResult preserves event order and canonicalizes empty event and
// observation collections to nil.
func NormalizeProbeResult(result ProbeResult) ProbeResult {
	normalized := result
	normalized.Events = NormalizeObservations(result.Events)
	return normalized
}
