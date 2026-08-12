package session

import (
	"reflect"
	"slices"
	"testing"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

func TestCapabilityWireAdapterNormalizesAndOwnsSlices(t *testing.T) {
	wire := rproto.Capability{
		Strategies: []string{"relay_only", "", "legacy_ice_udp", "relay_only"},
		Features:   []string{"probe_script_v1", "probe_lab_v1", "probe_script_v1"},
	}
	domain := capabilityFromWire(wire)
	if !slices.Equal(domain.Strategies, []string{"legacy_ice_udp", "relay_only"}) {
		t.Fatalf("domain Strategies = %#v", domain.Strategies)
	}
	if !slices.Equal(domain.Features, []string{"probe_lab_v1", "probe_script_v1"}) {
		t.Fatalf("domain Features = %#v", domain.Features)
	}

	wire.Strategies[0] = "mutated"
	wire.Features[0] = "mutated"
	if domain.Strategies[1] != "relay_only" || domain.Features[1] != "probe_script_v1" {
		t.Fatalf("domain capability aliases wire input: %#v", domain)
	}

	wireRoundTrip := capabilityToWire(domain)
	domain.Strategies[0] = "mutated"
	domain.Features[0] = "mutated"
	if !slices.Equal(wireRoundTrip.Strategies, []string{"legacy_ice_udp", "relay_only"}) ||
		!slices.Equal(wireRoundTrip.Features, []string{"probe_lab_v1", "probe_script_v1"}) {
		t.Fatalf("wire capability aliases domain input: %#v", wireRoundTrip)
	}
}

func TestCapabilityWireAdapterNormalizedRoundTrip(t *testing.T) {
	domain := solver.Capability{
		Strategies: []string{"relay_only", "legacy_ice_udp", "relay_only"},
		Features:   []string{"probe_script_v1", "probe_lab_v1"},
	}
	want := solver.NormalizeCapability(domain)
	got := capabilityFromWire(capabilityToWire(domain))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}
