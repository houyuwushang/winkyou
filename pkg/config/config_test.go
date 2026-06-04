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
	if !cfg.TCPFramed.Enabled || cfg.TCPFramed.ListenAddr != "127.0.0.1:0" || cfg.TCPFramed.AdvertiseAddr != "127.0.0.1:12345" {
		t.Fatalf("tcp_framed config = %#v, want enabled loopback config", cfg.TCPFramed)
	}
	if cfg.TCPFramed.DialTimeout.String() != "2s" {
		t.Fatalf("tcp_framed.dial_timeout = %s, want 2s", cfg.TCPFramed.DialTimeout)
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
