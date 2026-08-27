package oobcarrier

import (
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvouswire"
)

const (
	MaxHeavyweightAttempts = 1
	MaxStreams             = 1
	MaxChildProcesses      = 0
	MaxUDPSockets          = 1
	MaxSTUNTargets         = 2
	MaxDirectTargets       = 1
	MaxTargets             = MaxSTUNTargets + MaxDirectTargets
	MaxFiveTuples          = MaxTargets
	MaxSTUNOutbound        = 6
	MaxInitiatorDirect     = 2
	MaxResponderDirect     = 1
	MaxInitiatorUDP        = MaxSTUNOutbound + MaxInitiatorDirect
	MaxResponderUDP        = MaxSTUNOutbound + MaxResponderDirect
	MaxPPS                 = 5
	MaxFramesPerDirection  = 8
	MaxApplicationBytes    = MaxFramesPerDirection * (rendezvouswire.HeaderBytes + directattempt.MaxFrameBytes)

	PresenceTimeout = 3 * time.Second
	ActiveEnvelope  = 13 * time.Second
	DrainTimeout    = 2 * time.Second
	AttemptDuration = ActiveEnvelope + DrainTimeout
)

func AttemptCost(role directattempt.Role) (governor.AttemptCost, error) {
	packets := MaxResponderUDP
	if role == directattempt.RoleInitiator {
		packets = MaxInitiatorUDP
	} else if role != directattempt.RoleResponder {
		return governor.AttemptCost{}, ErrInvalidConfig
	}
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets: MaxUDPSockets, Targets: MaxTargets, FiveTuples: MaxFiveTuples,
			PacketsPerSecond: MaxPPS, Packets: packets,
		},
		Duration: AttemptDuration, Heavyweight: true,
	}, nil
}

func exactAttemptReservation(actual governor.AttemptCost, role directattempt.Role) bool {
	expected, err := AttemptCost(role)
	return err == nil && actual == expected
}
