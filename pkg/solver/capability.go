package solver

import (
	"slices"
)

// NormalizeCapability returns an owned, deterministic capability value.
// Empty entries are removed, duplicates collapse, and values sort so domain
// equality does not depend on wire ordering.
func NormalizeCapability(capability Capability) Capability {
	return Capability{
		Strategies: normalizeCapabilityValues(capability.Strategies),
		Features:   normalizeCapabilityValues(capability.Features),
	}
}

// CloneCapability returns a deep copy without changing ordering or values.
func CloneCapability(capability Capability) Capability {
	return Capability{
		Strategies: append([]string(nil), capability.Strategies...),
		Features:   append([]string(nil), capability.Features...),
	}
}

func normalizeCapabilityValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	slices.Sort(normalized)
	return normalized
}
