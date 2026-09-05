//go:build linux && natlab && c1bproof

package tunnel

import (
	"errors"
	"winkyou/pkg/netif"
)

// NewGateCNATLabWireGuard accepts only the interface already owned by the
// isolated C1b harness. It creates no TUN or native UDP bind. Ordinary builds
// have no such constructor and NewMemoryWireGuard retains its exact guard.
func NewGateCNATLabWireGuard(cfg Config) (Tunnel, error) {
	if cfg.Interface == nil || cfg.ListenPort != 0 || cfg.Interface.Type() != "tun" || cfg.Interface.Name() != "wink-c1b-proof" {
		return nil, errors.New("tunnel: isolated Gate C interface rejected")
	}
	if _, ok := cfg.Interface.(netif.MemoryTestInterface); !ok {
		return nil, errors.New("tunnel: isolated Gate C inner witness is absent")
	}
	instance := newWGGoTunnel(cfg)
	instance.memoryOnly = true // no-op native bind; all traffic uses the governed lease
	return instance, nil
}
