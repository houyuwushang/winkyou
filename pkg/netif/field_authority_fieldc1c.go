//go:build fieldc1c

package netif

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"winkyou/internal/v2/fieldc1c"
)

var ErrFieldInterface = errors.New("gate_c_request_invalid")

type fieldInterfaceState struct {
	instance    fieldc1c.Instance
	name        string
	mtu         int
	local, peer netip.Addr
	used        atomic.Bool
}

// FieldInterfaceAuthority is a concrete, non-forgeable and single-use token.
// The separate trusted arguments must match the signed instance exactly.
type FieldInterfaceAuthority struct{ state *fieldInterfaceState }

func NewFieldInterfaceAuthority(instance fieldc1c.Instance, name string, mtu int, local, peer netip.Addr, routes []netip.Prefix) (FieldInterfaceAuthority, error) {
	permit, err := instance.Interface()
	if err != nil || permit.Name != name || permit.MTU != mtu || permit.LocalAddress != local.String() ||
		permit.PeerAddress != peer.String() || !local.Is4() || !peer.Is4() || len(routes) != 1 || routes[0] != netip.PrefixFrom(peer, 32) {
		return FieldInterfaceAuthority{}, ErrFieldInterface
	}
	return FieldInterfaceAuthority{state: &fieldInterfaceState{instance: instance, name: name, mtu: mtu, local: local, peer: peer}}, nil
}

func (authority FieldInterfaceAuthority) valid() bool {
	return authority.state != nil && authority.state.instance.Check(time.Now()) == nil
}
