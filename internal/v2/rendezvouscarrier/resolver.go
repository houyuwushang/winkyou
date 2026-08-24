package rendezvouscarrier

import (
	"context"
	"net"
	"net/netip"
)

type governedResolver struct{}

func (governedResolver) Resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return lookupGovernedRendezvousHost(ctx, network, host)
}

// lookupGovernedRendezvousHost is the sole reviewed DNS capability in N2c.
// resolveTarget calls it at most once and rejects multi-address answers rather
// than dialing, polling, or falling back across candidates (owner: governor).
func lookupGovernedRendezvousHost(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
