package rendezvouscarrier

import (
	"context"
	"net"
)

// openGovernedRendezvous is the sole reviewed TCP opener in this package.
// Dial validates the exact target, attempt reservation, one-shot count, and
// deadline before reaching this function. The returned stream never leaves
// the adapter (architecture owner: governor).
func openGovernedRendezvous(ctx context.Context, target string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target)
}
