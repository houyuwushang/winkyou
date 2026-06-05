package client

import (
	"testing"

	"winkyou/pkg/config"
)

func TestEngineMultipathPathPolicyFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.Multipath.Enabled = true
	cfg.Connectivity.Multipath.ProtectDirect = true
	cfg.Connectivity.Multipath.MaxPaths = 3
	cfg.Connectivity.Multipath.ShadowWrite = true
	cfg.Connectivity.Multipath.DependencyPenalty = 50
	cfg.Connectivity.Multipath.DirectProtectionBonus = 100

	policy := (&engine{cfg: cfg}).multipathPathPolicy()
	if !policy.MultipathEnabled || !policy.ProtectDirect || !policy.ShadowWrite {
		t.Fatalf("policy booleans = %+v, want enabled protect_direct shadow_write", policy)
	}
	if policy.MaxPaths != 3 || policy.DependencyPenalty != 50 || policy.DirectProtectionBonus != 100 {
		t.Fatalf("policy values = %+v, want max_paths=3 dependency_penalty=50 direct_bonus=100", policy)
	}
}

func TestEngineMultipathPathPolicyDefaultsProtectedDirect(t *testing.T) {
	policy := (&engine{cfg: config.Default()}).multipathPathPolicy()
	if !policy.MultipathEnabled {
		t.Fatal("MultipathEnabled = false, want true by default")
	}
	if !policy.ProtectDirect || policy.MaxPaths != 2 {
		t.Fatalf("default policy = %+v, want protect_direct=true max_paths=2", policy)
	}
}

func TestEngineMultipathPathPolicyDisabledForRelayOnlyMode(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.Mode = "relay_only"

	policy := (&engine{cfg: cfg}).multipathPathPolicy()
	if policy.MultipathEnabled {
		t.Fatal("MultipathEnabled = true, want false for relay_only mode")
	}
}

func TestEngineMultipathPathPolicyDisabledForForceRelay(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.ForceRelay = true

	policy := (&engine{cfg: cfg}).multipathPathPolicy()
	if policy.MultipathEnabled {
		t.Fatal("MultipathEnabled = true, want false for nat.force_relay")
	}
}
