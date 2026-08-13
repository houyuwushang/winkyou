package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winkyou/pkg/config"
)

func TestQuickstartConfigsLoad(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "deploy", "quickstart", "windows-client.yaml"),
		filepath.Join("..", "..", "deploy", "quickstart", "linux-peer.yaml"),
		filepath.Join("..", "..", "deploy", "quickstart", "config.node-a.yaml"),
		filepath.Join("..", "..", "deploy", "quickstart", "config.node-b.yaml"),
		filepath.Join("..", "..", "deploy", "quickstart", "config.node-a.relay-only.yaml"),
		filepath.Join("..", "..", "deploy", "quickstart", "config.node-b.relay-only.yaml"),
	}

	for _, src := range files {
		t.Run(filepath.Base(src), func(t *testing.T) {
			content, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("ReadFile(%q) error = %v", src, err)
			}

			rendered := strings.NewReplacer(
				"<HOST>", "127.0.0.1",
				"<COORDINATOR_AUTH_KEY>", "test-only-auth-key",
				"<COORDINATOR_CA_FILE>", filepath.Join(t.TempDir(), "coordinator.crt"),
			).Replace(string(content))
			dst := filepath.Join(t.TempDir(), filepath.Base(src))
			if err := os.WriteFile(dst, []byte(rendered), 0o600); err != nil {
				t.Fatalf("WriteFile(%q) error = %v", dst, err)
			}

			cfg, err := config.Load(dst)
			if err != nil {
				t.Fatalf("Load(%q) error = %v", dst, err)
			}

			if cfg.NetIf.Backend != "tun" {
				t.Fatalf("netif.backend = %q, want tun", cfg.NetIf.Backend)
			}
			if cfg.WireGuard.ListenPort != 0 {
				t.Fatalf("wireguard.listen_port = %d, want 0", cfg.WireGuard.ListenPort)
			}
			if got := cfg.Coordinator.URL; got != "grpcs://127.0.0.1:50051" {
				t.Fatalf("coordinator.url = %q, want grpcs://127.0.0.1:50051", got)
			}
			if cfg.Coordinator.AuthKey != "test-only-auth-key" {
				t.Fatalf("coordinator.auth_key = %q, want rendered test key", cfg.Coordinator.AuthKey)
			}
			if strings.TrimSpace(cfg.Coordinator.TLS.CAFile) == "" {
				t.Fatal("coordinator.tls.ca_file is empty")
			}
			if len(cfg.NAT.TURNServers) != 1 || cfg.NAT.TURNServers[0].URL != "turn:127.0.0.1:3478?transport=udp" {
				t.Fatalf("turn server = %+v, want turn:127.0.0.1:3478?transport=udp", cfg.NAT.TURNServers)
			}
		})
	}
}
