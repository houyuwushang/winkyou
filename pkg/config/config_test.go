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
