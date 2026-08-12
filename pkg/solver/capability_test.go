package solver

import (
	"slices"
	"testing"
)

func TestNormalizeCapabilityOwnsDeterministicValues(t *testing.T) {
	input := Capability{
		Strategies: []string{"relay_only", "", "legacy_ice_udp", "relay_only"},
		Features:   []string{"probe_script_v1", "probe_lab_v1", "probe_script_v1"},
	}

	got := NormalizeCapability(input)
	if !slices.Equal(got.Strategies, []string{"legacy_ice_udp", "relay_only"}) {
		t.Fatalf("Strategies = %#v", got.Strategies)
	}
	if !slices.Equal(got.Features, []string{"probe_lab_v1", "probe_script_v1"}) {
		t.Fatalf("Features = %#v", got.Features)
	}

	input.Strategies[0] = "mutated"
	input.Features[0] = "mutated"
	if got.Strategies[1] != "relay_only" || got.Features[1] != "probe_script_v1" {
		t.Fatalf("normalized capability aliases input: %#v", got)
	}
}

func TestCloneCapabilityPreservesOrderWithoutAliasing(t *testing.T) {
	input := Capability{
		Strategies: []string{"second", "first"},
		Features:   []string{"feature-b", "feature-a"},
	}
	got := CloneCapability(input)
	input.Strategies[0] = "mutated"
	input.Features[0] = "mutated"
	if !slices.Equal(got.Strategies, []string{"second", "first"}) ||
		!slices.Equal(got.Features, []string{"feature-b", "feature-a"}) {
		t.Fatalf("cloned capability = %#v", got)
	}
}
