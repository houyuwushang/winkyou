// Package wireadapter owns conversion between rendezvous wire DTOs and the
// canonical solver domain. Callers must not pass rendezvous DTOs beyond this
// adapter boundary.
package wireadapter

import (
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

// ObservationFromWire converts and owns a rendezvous observation.
func ObservationFromWire(observation rproto.Observation) solver.Observation {
	return solver.NormalizeObservation(solver.Observation{
		Strategy:       observation.Strategy,
		PlanID:         observation.PlanID,
		Event:          observation.Event,
		PathID:         observation.PathID,
		ConnectionType: observation.ConnectionType,
		LocalAddr:      observation.LocalAddr,
		RemoteAddr:     observation.RemoteAddr,
		LocalKind:      observation.LocalKind,
		RemoteKind:     observation.RemoteKind,
		ErrorClass:     observation.ErrorClass,
		Reason:         observation.Reason,
		TimeoutMS:      observation.TimeoutMS,
		Details:        observation.Details,
		Timestamp:      observation.Timestamp,
	})
}

// ObservationToWire converts and owns a solver observation.
func ObservationToWire(observation solver.Observation) rproto.Observation {
	normalized := solver.NormalizeObservation(observation)
	return rproto.Observation{
		Strategy:       normalized.Strategy,
		PlanID:         normalized.PlanID,
		Event:          normalized.Event,
		PathID:         normalized.PathID,
		ConnectionType: normalized.ConnectionType,
		LocalAddr:      normalized.LocalAddr,
		RemoteAddr:     normalized.RemoteAddr,
		LocalKind:      normalized.LocalKind,
		RemoteKind:     normalized.RemoteKind,
		ErrorClass:     normalized.ErrorClass,
		Reason:         normalized.Reason,
		TimeoutMS:      normalized.TimeoutMS,
		Details:        normalized.Details,
		Timestamp:      normalized.Timestamp,
	}
}
