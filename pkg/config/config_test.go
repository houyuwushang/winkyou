package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"winkyou/pkg/config"
)

func TestLoadValidFile(t *testing.T) {
	cfg, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Node.Name != "my-node" {
		t.Fatalf("expected node name my-node, got %q", cfg.Node.Name)
	}
	if cfg.Log.Level != "warn" {
		t.Fatalf("expected log level warn, got %q", cfg.Log.Level)
	}
	if cfg.WireGuard.ListenPort != 51821 {
		t.Fatalf("expected listen port 51821, got %d", cfg.WireGuard.ListenPort)
	}
	if cfg.Connectivity.Mode != "auto" {
		t.Fatalf("connectivity mode = %q, want auto", cfg.Connectivity.Mode)
	}
	if len(cfg.Connectivity.StrategyOrder) != 3 || cfg.Connectivity.StrategyOrder[0] != "legacy_ice_udp" || cfg.Connectivity.StrategyOrder[1] != "relay_only" || cfg.Connectivity.StrategyOrder[2] != "tcp_framed" {
		t.Fatalf("connectivity strategy order = %#v, want legacy_ice_udp, relay_only, tcp_framed", cfg.Connectivity.StrategyOrder)
	}
	if !cfg.Connectivity.Multipath.Enabled || !cfg.Connectivity.Multipath.ProtectDirect || cfg.Connectivity.Multipath.MaxPaths != 3 {
		t.Fatalf("multipath config = %#v, want enabled protect_direct max_paths=3", cfg.Connectivity.Multipath)
	}
	if cfg.Connectivity.Multipath.DependencyPenalty != 50 || cfg.Connectivity.Multipath.DirectProtectionBonus != 100 {
		t.Fatalf("multipath scoring config = %#v, want dependency_penalty=50 direct_protection_bonus=100", cfg.Connectivity.Multipath)
	}
	if !cfg.TCPFramed.Enabled || cfg.TCPFramed.ListenAddr != "127.0.0.1:0" || cfg.TCPFramed.AdvertiseAddr != "127.0.0.1:12345" {
		t.Fatalf("tcp_framed config = %#v, want enabled loopback config", cfg.TCPFramed)
	}
	if cfg.TCPFramed.DialTimeout.String() != "2s" {
		t.Fatalf("tcp_framed.dial_timeout = %s, want 2s", cfg.TCPFramed.DialTimeout)
	}
	if len(cfg.NAT.CandidateInterfaceInclude) != 1 || cfg.NAT.CandidateInterfaceInclude[0] != "Ethernet" {
		t.Fatalf("candidate interface include = %#v, want Ethernet", cfg.NAT.CandidateInterfaceInclude)
	}
	if len(cfg.NAT.CandidateCIDRExclude) != 1 || cfg.NAT.CandidateCIDRExclude[0] != "100.64.0.0/10" {
		t.Fatalf("candidate cidr exclude = %#v, want 100.64.0.0/10", cfg.NAT.CandidateCIDRExclude)
	}
	if cfg.NAT.CandidatePortMin != 40000 || cfg.NAT.CandidatePortMax != 40100 {
		t.Fatalf("candidate port range = %d-%d, want 40000-40100", cfg.NAT.CandidatePortMin, cfg.NAT.CandidatePortMax)
	}
	if cfg.NAT.NAT1To1CandidateType != "srflx" {
		t.Fatalf("nat1to1 candidate type = %q, want srflx", cfg.NAT.NAT1To1CandidateType)
	}
	if len(cfg.NAT.NAT1To1IPs) != 1 || cfg.NAT.NAT1To1IPs[0] != "203.0.113.10/192.168.0.10" {
		t.Fatalf("nat1to1 ips = %#v, want explicit external/local mapping", cfg.NAT.NAT1To1IPs)
	}
	if len(cfg.NAT.PublicDirectTrustedCIDRs) != 1 || cfg.NAT.PublicDirectTrustedCIDRs[0] != "100.64.0.0/10" {
		t.Fatalf("public direct trusted CIDRs = %#v, want 100.64.0.0/10", cfg.NAT.PublicDirectTrustedCIDRs)
	}
}

func TestLoadUsesDefaultsWhenFileMissing(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Log.Level != "info" {
		t.Fatalf("expected default log level info, got %q", cfg.Log.Level)
	}
	if cfg.NetIf.Backend != "auto" {
		t.Fatalf("expected default backend auto, got %q", cfg.NetIf.Backend)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("WINK_LOG_LEVEL", "debug")

	cfg, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Log.Level != "debug" {
		t.Fatalf("expected env override debug, got %q", cfg.Log.Level)
	}
}

func TestLoadExplicitMissingFileFails(t *testing.T) {
	_, err := config.Load(filepath.Join("testdata", "missing.yaml"))
	if err == nil {
		t.Fatal("expected error for explicit missing file")
	}
}

func TestValidateInvalidConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Log.Level = "loud"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestDefaultConnectivityPolicy(t *testing.T) {
	cfg := config.Default()
	if cfg.Connectivity.Mode != "auto" {
		t.Fatalf("default connectivity mode = %q, want auto", cfg.Connectivity.Mode)
	}
	if len(cfg.Connectivity.StrategyOrder) != 2 || cfg.Connectivity.StrategyOrder[0] != "legacy_ice_udp" || cfg.Connectivity.StrategyOrder[1] != "relay_only" {
		t.Fatalf("default strategy order = %#v, want legacy_ice_udp then relay_only", cfg.Connectivity.StrategyOrder)
	}
	if cfg.TCPFramed.Enabled {
		t.Fatal("default tcp_framed.enabled = true, want false")
	}
	if cfg.TCPFramed.ListenAddr != "0.0.0.0:0" {
		t.Fatalf("default tcp_framed.listen_addr = %q, want 0.0.0.0:0", cfg.TCPFramed.ListenAddr)
	}
	if !cfg.Connectivity.Multipath.Enabled {
		t.Fatal("default multipath.enabled = false, want true")
	}
	if !cfg.Connectivity.Multipath.ProtectDirect {
		t.Fatal("default multipath.protect_direct = false, want true")
	}
	if cfg.Connectivity.Multipath.MaxPaths != 2 {
		t.Fatalf("default multipath.max_paths = %d, want 2", cfg.Connectivity.Multipath.MaxPaths)
	}
	if !cfg.Connectivity.Multipath.ShadowWrite {
		t.Fatal("default multipath.shadow_write = false, want true")
	}
}

func TestValidateRejectsUnknownConnectivityStrategy(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.StrategyOrder = []string{"legacy_ice_udp", "future_quic"}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if got := err.Error(); got != `invalid connectivity.strategy_order[1]: "future_quic"` {
		t.Fatalf("Validate() error = %q, want unknown strategy error", got)
	}
}

func TestValidateCandidateFilters(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.CandidateInterfaceInclude = []string{"Ethernet"}
	cfg.NAT.CandidateInterfaceExclude = []string{"tailscale0"}
	cfg.NAT.CandidateCIDRInclude = []string{"192.168.0.0/16"}
	cfg.NAT.CandidateCIDRExclude = []string{"100.64.0.0/10"}
	cfg.NAT.PublicDirectTrustedCIDRs = []string{"100.64.0.0/10"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	cfg.NAT.CandidateCIDRExclude = []string{"not-a-cidr"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid CIDR")
	}
	if got := err.Error(); got != `invalid nat.candidate_cidr_exclude[0]: "not-a-cidr"` {
		t.Fatalf("Validate() error = %q, want invalid CIDR", got)
	}

	cfg = config.Default()
	cfg.NAT.PublicDirectTrustedCIDRs = []string{"not-a-cidr"}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid public direct trusted CIDR")
	}
	if got := err.Error(); got != `invalid nat.public_direct_trusted_cidrs[0]: "not-a-cidr"` {
		t.Fatalf("Validate() error = %q, want invalid public direct trusted CIDR", got)
	}
}

func TestValidateNATPublicCandidateHints(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.CandidatePortMin = 40000
	cfg.NAT.CandidatePortMax = 40100
	cfg.NAT.NAT1To1CandidateType = "srflx"
	cfg.NAT.NAT1To1IPs = []string{"203.0.113.10/192.168.0.10"}
	cfg.NAT.PublicEndpointHints = []string{"117.48.146.2:41000", "117.48.146.3:41001/192.168.1.20:40000"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	cfg.NAT.CandidatePortMax = 39999
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid candidate port range")
	}
	if got := err.Error(); got != "nat.candidate_port_max must be greater than or equal to nat.candidate_port_min" {
		t.Fatalf("Validate() error = %q, want invalid port range", got)
	}

	cfg = config.Default()
	cfg.NAT.CandidatePortMin = 40000
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject partial candidate port range")
	}
	if got := err.Error(); got != "nat.candidate_port_min and nat.candidate_port_max must be set together" {
		t.Fatalf("Validate() error = %q, want partial port range", got)
	}

	cfg = config.Default()
	cfg.NAT.NAT1To1CandidateType = "relay"
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid nat1to1 candidate type")
	}
	if got := err.Error(); got != `invalid nat.nat1to1_candidate_type: "relay"` {
		t.Fatalf("Validate() error = %q, want invalid candidate type", got)
	}

	cfg = config.Default()
	cfg.NAT.NAT1To1IPs = []string{"203.0.113.10/not-an-ip"}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid nat1to1 IP mapping")
	}
	if got := err.Error(); got != `invalid nat.nat1to1_ips[0]: "203.0.113.10/not-an-ip"` {
		t.Fatalf("Validate() error = %q, want invalid nat1to1 mapping", got)
	}

	cfg = config.Default()
	cfg.NAT.PublicEndpointHints = []string{"100.102.17.35:41000"}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject non-public endpoint hint")
	}
	if got := err.Error(); got != `invalid nat.public_endpoint_hints[0]: "100.102.17.35:41000"` {
		t.Fatalf("Validate() error = %q, want invalid public endpoint hint", got)
	}

	cfg = config.Default()
	cfg.NAT.PublicEndpointHints = []string{"117.48.146.2:41000/100.102.17.35:40000"}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject overlay local endpoint hint base")
	}
	if got := err.Error(); got != `invalid nat.public_endpoint_hints[0]: "117.48.146.2:41000/100.102.17.35:40000"` {
		t.Fatalf("Validate() error = %q, want invalid public endpoint hint local base", got)
	}

	cfg = config.Default()
	cfg.NAT.PublicDirectTrustedCIDRs = []string{"100.64.0.0/10"}
	cfg.NAT.PublicEndpointHints = []string{"100.102.17.35:41000/100.102.17.36:40000"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() trusted public endpoint hint error = %v", err)
	}
}

func TestValidateRejectsEnabledMultipathWithoutPaths(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.Multipath.Enabled = true
	cfg.Connectivity.Multipath.MaxPaths = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if got := err.Error(); got != "connectivity.multipath.max_paths must be greater than zero when connectivity.multipath.enabled=true" {
		t.Fatalf("Validate() error = %q, want multipath max_paths error", got)
	}
}

func TestDefaultPathWindowsFallback(t *testing.T) {
	original := os.Getenv("APPDATA")
	t.Cleanup(func() {
		if original == "" {
			_ = os.Unsetenv("APPDATA")
			return
		}
		_ = os.Setenv("APPDATA", original)
	})

	_ = os.Setenv("APPDATA", `C:\Users\tester\AppData\Roaming`)

	path := config.DefaultPath()
	if path == "" {
		t.Fatal("expected non-empty default path")
	}
}
