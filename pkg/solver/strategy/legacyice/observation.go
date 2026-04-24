package legacyice

import (
	"strings"

	"winkyou/pkg/solver"
)

type observationSource string

const (
	observationSourceLocal  observationSource = "local"
	observationSourceRemote observationSource = "remote"
)

type observationEvidence struct {
	Observation     solver.Observation
	CanDrivePruning bool
}

func relevantObservationForInput(input solver.SolveInput, obs solver.Observation, source observationSource) (observationEvidence, bool) {
	if obs.Strategy != "" && obs.Strategy != StrategyName {
		return observationEvidence{}, false
	}
	if !observationScopeCompatible(input, obs, source) {
		return observationEvidence{}, false
	}

	return observationEvidence{
		Observation:     obs,
		CanDrivePruning: observationCanDrivePruning(input, obs, source),
	}, true
}

// observationScopeCompatible keeps stale or cross-peer observations out of all
// evidence summaries. Remote peer_id is interpreted from the remote node's
// perspective, so it must identify this local node when present.
func observationScopeCompatible(input solver.SolveInput, obs solver.Observation, source observationSource) bool {
	if sessionID, ok := observationDetail(obs, "session_id"); ok && input.SessionID != "" && sessionID != input.SessionID {
		return false
	}
	if peerID, ok := observationDetail(obs, "peer_id"); ok {
		expectedPeerID := expectedObservationPeerID(input, source)
		if expectedPeerID != "" && peerID != expectedPeerID {
			return false
		}
	}
	return true
}

func observationCanDrivePruning(input solver.SolveInput, obs solver.Observation, source observationSource) bool {
	sessionID, hasSessionID := observationDetail(obs, "session_id")
	peerID, hasPeerID := observationDetail(obs, "peer_id")
	expectedPeerID := expectedObservationPeerID(input, source)

	return hasSessionID &&
		hasPeerID &&
		input.SessionID != "" &&
		expectedPeerID != "" &&
		sessionID == input.SessionID &&
		peerID == expectedPeerID
}

func expectedObservationPeerID(input solver.SolveInput, source observationSource) string {
	if source == observationSourceRemote {
		return input.LocalNodeID
	}
	return input.RemoteNodeID
}

func observationDetail(obs solver.Observation, key string) (string, bool) {
	value := strings.TrimSpace(obs.Details[key])
	return value, value != ""
}
