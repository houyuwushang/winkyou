//go:build fieldc1c

package netif

import (
	"errors"
	"net/netip"
	"runtime"
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
	// Windows only: derived from the sealed Instance, never a caller GUID.
	wintunGUID string
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
	state := &fieldInterfaceState{instance: instance, name: name, mtu: mtu, local: local, peer: peer}
	if runtime.GOOS == "windows" {
		derivedName, guid, identityErr := instance.WintunIdentity()
		binding, bindingErr := instance.Binding()
		device, deviceErr := instance.Device()
		if identityErr != nil || bindingErr != nil || deviceErr != nil || derivedName != name || binding.Role != "initiator" || device.OS != "windows" {
			return FieldInterfaceAuthority{}, ErrFieldInterface
		}
		state.wintunGUID = guid
	}
	return FieldInterfaceAuthority{state: state}, nil
}

func (authority FieldInterfaceAuthority) valid() bool {
	return authority.state != nil && authority.state.instance.Check(time.Now()) == nil
}
