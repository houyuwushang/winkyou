package birthdaypunch

import (
	"net"
	"time"

	"winkyou/pkg/nat"
)

const (
	// defaultPredictSpan is how many mappings ahead to predict for a sequential
	// peer.
	defaultPredictSpan = 16
	// defaultPredictSockets is the source-socket count when the peer's port is
	// predictable — a few suffice.
	defaultPredictSockets = 64
	// The birthday parameters are the lowest profile repeatedly validated by
	// the 2026-07-16 EDMxEDM field run: 128 sockets, 48 fresh targets per socket
	// per 300ms round, burst 1. Fresh targets accumulate coverage without the
	// 256x256 fixed-target flood used by the initial implementation.
	defaultBirthdaySockets    = 128
	defaultBirthdayPerRound   = 48
	defaultBirthdayRoundDelay = 300 * time.Millisecond
	birthdayPortLo            = 1024
	birthdayPortHi            = 65535

	// defaultStartLead is how far ahead the initiator schedules T0 so the start
	// message can propagate before both sides begin punching.
	defaultStartLead = 500 * time.Millisecond
)

// peerEndpoint is the decoded, validated view of a peer's advertised endpoint.
type peerEndpoint struct {
	IP           net.IP
	ObservedPort int
	Pattern      nat.PortAllocationPattern
	Delta        int
}

// punchPlan is the computed input to one punch attempt against a peer.
type punchPlan struct {
	Targets     []int
	SocketCount int
	BirthdayN   int
	RoundDelay  time.Duration
	Method      string
}

func (p punchPlan) usable() bool {
	return len(p.Targets) > 0 || p.BirthdayN > 0
}

// planPunch computes punch targets and socket width for reaching a peer with the
// given endpoint. Predictable peers (sequential/preserving) get a tight
// predicted target set with few sockets; unpredictable peers get birthday-style
// spraying across many sockets and target ports.
func planPunch(peer peerEndpoint) punchPlan {
	report := nat.PortAllocationReport{Pattern: peer.Pattern, Delta: peer.Delta}
	switch peer.Pattern {
	case nat.PortAllocationSequential, nat.PortAllocationPreserving:
		targets := report.PredictMappedPorts(peer.ObservedPort, defaultPredictSpan)
		if len(targets) == 0 && peer.ObservedPort > 0 {
			targets = []int{peer.ObservedPort}
		}
		return punchPlan{Targets: targets, SocketCount: defaultPredictSockets, Method: "predictive"}
	default:
		return punchPlan{
			SocketCount: defaultBirthdaySockets,
			BirthdayN:   defaultBirthdayPerRound,
			RoundDelay:  defaultBirthdayRoundDelay,
			Method:      "birthday",
		}
	}
}

// patternFromString parses the wire form of a NAT port-allocation pattern.
func patternFromString(s string) nat.PortAllocationPattern {
	switch s {
	case "preserving":
		return nat.PortAllocationPreserving
	case "sequential":
		return nat.PortAllocationSequential
	case "random":
		return nat.PortAllocationRandom
	default:
		return nat.PortAllocationUnknown
	}
}

// syncStartAt returns the shared punch start time. The initiator computes it as
// now+lead so the start message reaches the peer before punching begins.
func syncStartAt(now time.Time, lead time.Duration) time.Time {
	if lead <= 0 {
		lead = defaultStartLead
	}
	return now.Add(lead)
}

// waitUntil blocks until t, or returns early if the deadline has already passed.
// It is interruptible via the returned timer semantics at the call site.
func delayUntil(now, t time.Time) time.Duration {
	d := t.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}
