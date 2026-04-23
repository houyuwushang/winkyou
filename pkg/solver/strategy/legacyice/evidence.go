package legacyice

import (
	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

const (
	planIDDirectPrefer = "legacyice/direct_prefer"
	planIDRelayOnly    = "legacyice/relay_only"
)

type evidenceSummary struct {
	DirectFailures   int
	DirectSuccesses  int
	RelaySuccesses   int
	PreflightSuccess bool
	PreflightFailure bool
}

func summarizeSolveEvidence(input solver.SolveInput) evidenceSummary {
	summary := evidenceSummary{}
	for _, obs := range collectRelevantObservations(input) {
		summary.addObservation(obs)
	}
	summary.addProbeResult(input.LastProbeResult)
	return summary
}

func summarizeRankEvidence(input solver.RankInput) evidenceSummary {
	return summarizeSolveEvidence(solver.SolveInput{
		SessionID:          input.SessionID,
		LocalNodeID:        input.LocalNodeID,
		RemoteNodeID:       input.RemoteNodeID,
		Initiator:          input.Initiator,
		RemoteCapability:   input.RemoteCapability,
		LocalObservations:  input.LocalObservations,
		RemoteObservations: input.RemoteObservations,
		LastProbeResult:    input.LastProbeResult,
	})
}

func summarizeProbeEvidence(input solver.ProbeInput) evidenceSummary {
	return summarizeSolveEvidence(solver.SolveInput{
		SessionID:          input.SessionID,
		LocalNodeID:        input.LocalNodeID,
		RemoteNodeID:       input.RemoteNodeID,
		Initiator:          input.Initiator,
		LocalCapability:    input.LocalCapability,
		RemoteCapability:   input.RemoteCapability,
		LocalObservations:  input.LocalObservations,
		RemoteObservations: input.RemoteObservations,
		LastProbeResult:    input.LastProbeResult,
	})
}

func collectRelevantObservations(input solver.SolveInput) []solver.Observation {
	observations := make([]solver.Observation, 0, len(input.LocalObservations)+len(input.RemoteObservations))
	for _, obs := range input.LocalObservations {
		if relevantObservationForSession(input, obs) {
			observations = append(observations, obs)
		}
	}
	for _, obs := range input.RemoteObservations {
		if obs.Strategy == "" || obs.Strategy == StrategyName {
			observations = append(observations, obs)
		}
	}
	return observations
}

func (e *evidenceSummary) addObservation(obs solver.Observation) {
	switch {
	case obs.PlanID == planIDDirectPrefer && obs.Event == "candidate_failed":
		e.DirectFailures++
	case obs.PlanID == planIDDirectPrefer && isDirectSuccess(obs):
		e.DirectSuccesses++
	case obs.PlanID == planIDRelayOnly && isRelaySuccess(obs):
		e.RelaySuccesses++
	}
}

func (e *evidenceSummary) addProbeResult(result *solver.ProbeResultSummary) {
	if result == nil || result.ScriptType != pmodel.ScriptTypePreflight {
		return
	}
	if result.Success {
		e.PreflightSuccess = true
		return
	}
	e.PreflightFailure = true
}

func (e evidenceSummary) strongRelayOnly() bool {
	return e.DirectFailures >= 2 &&
		e.RelaySuccesses > 0 &&
		!e.PreflightSuccess &&
		e.DirectSuccesses == 0
}

func (e evidenceSummary) relayPreferred() bool {
	return e.DirectFailures > 0 && e.RelaySuccesses > 0
}

func (e evidenceSummary) directSuccessful() bool {
	return e.DirectSuccesses > 0
}

func (e evidenceSummary) hint() string {
	switch {
	case e.strongRelayOnly():
		return "strong_relay_only"
	case e.relayPreferred():
		return "relay_preferred"
	case e.directSuccessful():
		return "direct_success"
	case e.PreflightSuccess:
		return "preflight_success"
	case e.PreflightFailure:
		return "preflight_failure"
	default:
		return "insufficient_evidence"
	}
}
