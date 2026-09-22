//go:build fieldc1c

package fieldc1c

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func routerV2Fixture(t *testing.T) (map[string]any, buildWitness, time.Time) {
	t.Helper()
	doc, build, now := fixtureDocument(t)
	var value map[string]any
	if json.Unmarshal(encodeFixture(t, doc), &value) != nil {
		t.Fatal("fixture decode")
	}
	value["authority_schema_revision"] = "winkyou-gate-c1c-authorization/2"
	value["router"] = map[string]any{
		"schema":                              "winkyou-c1c-router/1",
		"machine_scope_reference":             doc.InitiatorMachineScopeReference,
		"dependency_and_configuration_sha256": doc.DependencyAndConfigurationSHA256,
		"allow_global_conntrack_ceiling":      false,
		"disposable_environment_reference":    "synthetic-reviewed-disposable-scope",
		"anchors": []any{
			map[string]any{"role": "initiator", "name": "wyc-fixture-a", "inode": uint64(101)},
			map[string]any{"role": "transit", "name": "wyc-fixture-t", "inode": uint64(102)},
			map[string]any{"role": "responder", "name": "wyc-fixture-b", "inode": uint64(103)},
		},
		"domains": []any{
			map[string]any{"role": "initiator", "mode": "apdm_sequential/1", "endpoint_prefix": "192.0.2.2/30", "gateway_prefix": "192.0.2.1/30", "public_prefix": "198.51.100.1/29", "transit_prefix": "198.51.100.2/29"},
			map[string]any{"role": "responder", "mode": "apdm_sequential/1", "endpoint_prefix": "192.0.2.6/30", "gateway_prefix": "192.0.2.5/30", "public_prefix": "203.0.113.2/29", "transit_prefix": "203.0.113.1/29"},
		},
	}
	return value, build, now
}

func TestRouterV2ThreeRolesAndExplicitFalse(t *testing.T) {
	value, build, now := routerV2Fixture(t)
	for _, role := range []string{"initiator", "responder", "router"} {
		if _, err := validate(encodeFixture(t, value), role, now, build); err != nil {
			t.Fatalf("valid /2 with explicit false rejected for %s: %v", role, err)
		}
	}
}

func TestRouterV2StrictPermissionAndBinding(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(map[string]any)
	}{
		{"missing_router", func(v map[string]any) { delete(v, "router") }},
		{"v1_with_router", func(v map[string]any) { v["authority_schema_revision"] = Schema }},
		{"unknown_schema", func(v map[string]any) { v["authority_schema_revision"] = "winkyou-gate-c1c-authorization/3" }},
		{"missing_permission", func(v map[string]any) { delete(v["router"].(map[string]any), "allow_global_conntrack_ceiling") }},
		{"null_permission", func(v map[string]any) { v["router"].(map[string]any)["allow_global_conntrack_ceiling"] = nil }},
		{"string_permission", func(v map[string]any) { v["router"].(map[string]any)["allow_global_conntrack_ceiling"] = "true" }},
		{"extra_member", func(v map[string]any) { v["router"].(map[string]any)["command"] = "synthetic" }},
		{"shared_anchor", func(v map[string]any) { a := v["router"].(map[string]any)["anchors"].([]any); a[1] = a[0] }},
		{"wrong_peer", func(v map[string]any) { v["initiator_expected_peer_address"] = "203.0.113.9" }},
		{"wrong_mode", func(v map[string]any) {
			d := v["router"].(map[string]any)["domains"].([]any)
			d[0].(map[string]any)["mode"] = "eim/1"
		}},
		{"wrong_observer", func(v map[string]any) { v["observer_topology"].(map[string]any)["primary"] = "198.51.100.3:3478" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			value, build, now := routerV2Fixture(t)
			change.apply(value)
			for _, role := range []string{"initiator", "responder", "router"} {
				if _, err := validate(encodeFixture(t, value), role, now, build); !errors.Is(err, ErrInvalid) {
					t.Fatal("invalid /2 accepted")
				}
			}
		})
	}
	value, build, now := routerV2Fixture(t)
	value["router"].(map[string]any)["dependency_and_configuration_sha256"] = string(make([]byte, 64))
	if _, err := validate(encodeFixture(t, value), "router", now, build); !errors.Is(err, ErrInvalid) {
		t.Fatal("router dependency bypass")
	}
}

func TestRouterV1RemainsEndpointOnly(t *testing.T) {
	doc, build, now := fixtureDocument(t)
	for _, role := range []string{"initiator", "responder"} {
		if _, err := validate(encodeFixture(t, doc), role, now, build); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := validate(encodeFixture(t, doc), "router", now, build); !errors.Is(err, ErrInvalid) {
		t.Fatal("v1 granted router authority")
	}
}

func TestRouterV2CleanupTokenCannotGrantRun(t *testing.T) {
	doc, build, now := routerV2Fixture(t)
	v, e := validate(encodeFixture(t, doc), "router", now, build)
	if e != nil {
		t.Fatal(e)
	}
	a := RouterAuthority{value: v}
	if a.Check(now) != nil {
		t.Fatal("active token rejected")
	}
	for _, stamp := range []time.Time{{}, v.notBefore.Add(-time.Nanosecond), v.notAfter} {
		if !errors.Is(a.Check(stamp), ErrInvalid) {
			t.Fatal("router window escaped")
		}
	}
	a.cleanupOnly = true
	if !errors.Is(a.Check(now), ErrInvalid) {
		t.Fatal("cleanup token activated")
	}
	if !errors.Is((RouterAuthority{}).Check(now), ErrInvalid) {
		t.Fatal("zero router authority activated")
	}
}

func TestRouterV2NestedNullOrMissingRejected(t *testing.T) {
	for _, kind := range []string{"anchors", "domains"} {
		original, _, _ := routerV2Fixture(t)
		entries := original["router"].(map[string]any)[kind].([]any)
		for index, entry := range entries {
			for member := range entry.(map[string]any) {
				for _, null := range []bool{false, true} {
					value, build, now := routerV2Fixture(t)
					target := value["router"].(map[string]any)[kind].([]any)[index].(map[string]any)
					if null {
						target[member] = nil
					} else {
						delete(target, member)
					}
					if _, e := validate(encodeFixture(t, value), "router", now, build); !errors.Is(e, ErrInvalid) {
						t.Fatalf("nested required member accepted: %s", member)
					}
				}
			}
		}
	}
}
