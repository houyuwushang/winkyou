package probeio

import "winkyou/internal/governor"

// Only the real governor can supply the opt-in early permission revocation.
// Ordinary leases and existing adapters retain the identical Done channel.
// This signal denies new operations; the registered drain still proves their
// actual termination. It never substitutes a fake Done or releases a lease.
func probeRevocationForLease(lease AttemptLease) <-chan struct{} {
	if actual, ok := lease.(*governor.AttemptLease); ok {
		return actual.ProbeRevocation()
	}
	return lease.Done()
}
