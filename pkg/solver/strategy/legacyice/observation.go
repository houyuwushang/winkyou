package legacyice

import (
	"winkyou/pkg/solver"
)

func relevantObservationForSession(input solver.SolveInput, obs solver.Observation) bool {
	if obs.Strategy != "" && obs.Strategy != StrategyName {
		return false
	}
	if sessionID := obs.Details["session_id"]; sessionID != "" && sessionID != input.SessionID {
		return false
	}
	if peerID := obs.Details["peer_id"]; peerID != "" && peerID != input.RemoteNodeID {
		return false
	}
	return true
}
