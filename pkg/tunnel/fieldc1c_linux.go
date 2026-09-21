//go:build linux && fieldc1c

package tunnel

import (
	"errors"
	"sync"
	"winkyou/pkg/netif"
)

// FieldWireGuardWitness contains only operation outcomes, never keys or the
// underlying error text. The field entry stores it in its private evidence.
type FieldWireGuardWitness struct {
	StartCalled, StartSucceeded bool
	PeerCalled, PeerSucceeded   bool
}

type fieldWGGoTunnel struct {
	*wggoTunnel
	witnessMu sync.Mutex
	witness   FieldWireGuardWitness
}

func (field *fieldWGGoTunnel) Start() error {
	err := field.wggoTunnel.Start()
	field.witnessMu.Lock()
	field.witness.StartCalled, field.witness.StartSucceeded = true, err == nil
	field.witnessMu.Unlock()
	return err
}

func (field *fieldWGGoTunnel) AddPeer(peer *PeerConfig) error {
	err := field.wggoTunnel.AddPeer(peer)
	field.witnessMu.Lock()
	field.witness.PeerCalled, field.witness.PeerSucceeded = true, err == nil
	field.witnessMu.Unlock()
	return err
}

func FieldWireGuardSnapshot(value Tunnel) FieldWireGuardWitness {
	field, ok := value.(*fieldWGGoTunnel)
	if !ok {
		return FieldWireGuardWitness{}
	}
	field.witnessMu.Lock()
	defer field.witnessMu.Unlock()
	return field.witness
}

func NewFieldWireGuard(cfg Config) (Tunnel, error) {
	owned, ok := cfg.Interface.(*netif.FieldInterface)
	if !ok || !owned.ValidTransport() || cfg.ListenPort != 0 {
		return nil, errors.New("gate_c_request_invalid")
	}
	instance := newWGGoTunnel(cfg)
	instance.memoryOnly = true // no native bind: the single promoted lease owns UDP
	return &fieldWGGoTunnel{wggoTunnel: instance}, nil
}
