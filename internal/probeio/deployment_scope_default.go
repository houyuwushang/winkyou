//go:build !fieldc1c

package probeio

import (
	"context"
	"net/netip"
)

func authorizeAdditionalFactoryScope(ctx context.Context, _ Factory, _ AttemptLease) context.Context {
	return ctx
}
func validateAdditionalTargetScope(_ Datagram, _ netip.AddrPort) error { return nil }
