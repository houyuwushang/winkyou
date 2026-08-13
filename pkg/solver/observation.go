package solver

// CloneObservation returns an owned copy without changing scalar values or
// the nil-versus-empty boundary of Details.
func CloneObservation(observation Observation) Observation {
	cloned := observation
	cloned.Details = cloneDomainStringMap(observation.Details)
	return cloned
}

// NormalizeObservation returns an owned, deterministic domain value. Scalar
// observation values are already ordered; normalization therefore only
// canonicalizes an empty Details map to nil while preserving every entry.
func NormalizeObservation(observation Observation) Observation {
	normalized := CloneObservation(observation)
	if len(normalized.Details) == 0 {
		normalized.Details = nil
	}
	return normalized
}

// CloneObservations returns owned observations while preserving slice and map
// nil-versus-empty boundaries.
func CloneObservations(observations []Observation) []Observation {
	if observations == nil {
		return nil
	}
	cloned := make([]Observation, len(observations))
	for i := range observations {
		cloned[i] = CloneObservation(observations[i])
	}
	return cloned
}

// NormalizeObservations preserves semantic event ordering and canonicalizes
// an empty list to nil.
func NormalizeObservations(observations []Observation) []Observation {
	if len(observations) == 0 {
		return nil
	}
	normalized := make([]Observation, len(observations))
	for i := range observations {
		normalized[i] = NormalizeObservation(observations[i])
	}
	return normalized
}

func cloneDomainStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
