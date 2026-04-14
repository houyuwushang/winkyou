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
	}

	for _, src := range files {
		t.Run(filepath.Base(src), func(t *testing.T) {
			content, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("ReadFile(%q) error = %v", src, err)
			}

			rendered := strings.ReplaceAll(string(content), "<HOST>", "127.0.0.1")
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
			if got := cfg.Coordinator.URL; got != "grpc://127.0.0.1:50051" {
				t.Fatalf("coordinator.url = %q, want grpc://127.0.0.1:50051", got)
			}
			if len(cfg.NAT.TURNServers) != 1 || cfg.NAT.TURNServers[0].URL != "turn:127.0.0.1:3478?transport=udp" {
				t.Fatalf("turn server = %+v, want turn:127.0.0.1:3478?transport=udp", cfg.NAT.TURNServers)
			}
		})
	}
}
