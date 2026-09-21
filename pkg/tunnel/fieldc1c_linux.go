//go:build linux && fieldc1c

package tunnel

import (
	"errors"
	"winkyou/pkg/netif"
)

func NewFieldWireGuard(cfg Config) (Tunnel, error) {
	owned, ok := cfg.Interface.(*netif.FieldInterface)
	if !ok || !owned.ValidTransport() || cfg.ListenPort != 0 {
		return nil, errors.New("gate_c_request_invalid")
	}
	instance := newWGGoTunnel(cfg)
	instance.memoryOnly = true // no native bind: the single promoted lease owns UDP
	return instance, nil
}
