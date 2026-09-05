//go:build linux && natlab && c1bproof

package tunnel

import (
	"testing"
	"winkyou/pkg/netif"
)

// Constructor-shape stub only. The required OS proof separately owns the real
// kernel TUN, route, UDP listener and read/write counters.
type gateC1bShapeTUN struct{ netif.MemoryTestInterface }

func (gateC1bShapeTUN) Type() string { return "tun" }

func TestGateCNATLabConstructorKeepsNativeBindDisabled(t *testing.T) {
	for _, mode := range []string{"valid", "memory", "name", "port"} {
		t.Run(mode, func(t *testing.T) {
			name := "wink-c1b-proof"
			if mode == "name" {
				name = "wrong"
			}
			base, err := netif.NewGateCMemoryInterface(name, 1280)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			cfg := Config{Interface: gateC1bShapeTUN{base}}
			if mode == "memory" {
				cfg.Interface = base
			}
			if mode == "port" {
				cfg.ListenPort = 1
			}
			instance, err := NewGateCNATLabWireGuard(cfg)
			if mode != "valid" {
				if err == nil {
					t.Fatal("unapproved isolated tunnel accepted")
				}
				return
			}
			if err != nil || !instance.(*wggoTunnel).memoryOnly {
				t.Fatal("isolated constructor enabled a native socket")
			}
			if _, err := NewMemoryWireGuard(cfg); err == nil {
				t.Fatal("ordinary memory guard was widened for the harness")
			}
		})
	}
}
