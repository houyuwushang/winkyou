package rendezvouscarrier

import (
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvouswire"
)

const (
	MaxConnections        = 1
	MaxRendezvousTargets  = 1
	MaxDNSResolutions     = 1
	MaxFramesPerDirection = 8
	PresenceTimeout       = 3 * time.Second
	AttemptDuration       = 15 * time.Second
	terminalDrainMargin   = 2 * time.Second
	ActiveEnvelope        = AttemptDuration - terminalDrainMargin

	streamHeaderBytes = rendezvouswire.HeaderBytes

	// MaxApplicationBytes is charged independently per endpoint across reads
	// and writes. It is deliberately based on the transport frame ceiling, not
	// an estimate of TCP packets on the wire.
	MaxApplicationBytes = MaxFramesPerDirection * (streamHeaderBytes + directattempt.MaxFrameBytes)
)

// N2AttemptCost is the complete per-endpoint reservation. The TCP rendezvous
// connection and the one UDP socket share one governor attempt; the latter's
// packet ceiling is the larger initiator case (3 STUN + SYN + ACK). One
// additional socket/target/five-tuple is a deliberately coarse reservation
// for the optional single DNS lookup; literal endpoints still reserve it so
// runtime configuration can never raise the admitted envelope.
func N2AttemptCost() governor.AttemptCost {
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          3,
			Targets:          4,
			PacketsPerSecond: 5,
			Packets:          5,
			FiveTuples:       4,
		},
		Duration:    AttemptDuration,
		Heavyweight: true,
	}
}

func exactAttemptReservation(actual governor.AttemptCost) bool {
	return actual == N2AttemptCost()
}
