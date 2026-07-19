package mesh

import (
	"sync/atomic"
	"time"
)

const bootCounterStride = uint64(1 << 20)

var lastBootCounterBase atomic.Uint64

// nextBootCounterBase gives every new in-process control-plane instance a
// large, wall-clock-ordered counter base. Unix nanoseconds separate real
// process restarts, while the reserved stride makes rapid constructions in one
// process strictly increasing with room for ordinary per-instance increments.
// This keeps a restarted node's message sequences and topology revisions ahead
// of records cached from its previous process instead of resetting to one.
// Cross-process ordering assumes the host wall clock does not move backwards;
// a durable boot incarnation can replace that assumption in a later protocol.
func nextBootCounterBase() uint64 {
	nowNanos := time.Now().UnixNano()
	for {
		previous := lastBootCounterBase.Load()
		candidate := bootCounterCandidate(nowNanos, previous)
		if lastBootCounterBase.CompareAndSwap(previous, candidate) {
			return candidate
		}
	}
}

func bootCounterCandidate(nowNanos int64, previous uint64) uint64 {
	candidate := bootCounterStride
	if nowNanos > 0 {
		candidate = uint64(nowNanos)
	}
	maximum := ^uint64(0)
	minimum := maximum
	if previous <= maximum-bootCounterStride {
		minimum = previous + bootCounterStride
	}
	if candidate < minimum {
		return minimum
	}
	return candidate
}
