package natlab

import (
	"testing"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatbudget"
)

type gateB3LossTerminalWitness struct {
	OK                                                bool
	Role, Terminal, ErrorClass, ErrorStage            string
	CredentialBurned, FinishRecorded, Bidirectional   bool
	EvidencePackets, CandidatePackets, WinnerPackets  int
	UDPPackets, DataPacketsRead, DataPacketsWritten   int
	CarrierFramesRead, CarrierFramesWrite             int
	CarrierDrained, CampaignCircuit, SafetyBlocksWork bool
}

func validGateB3LossTerminalPair(initiator, responder gateB3LossTerminalWitness) bool {
	return gateB3LossTerminalRejection(initiator, responder) == ""
}

// gateB3LossTerminalRejection returns a stable, privacy-safe rejection class
// for the required netns witness. It intentionally reports no endpoint,
// process, path, or machine data.
func gateB3LossTerminalRejection(initiator, responder gateB3LossTerminalWitness) string {
	common := func(result gateB3LossTerminalWitness, role directattempt.Role) bool {
		return result.OK && result.Role == string(role) && result.Terminal == "failed" &&
			result.ErrorStage == gateb.StageCandidates && result.CredentialBurned && result.FinishRecorded &&
			!result.Bidirectional && result.EvidencePackets == hardnatbudget.FreshEvidencePackets &&
			result.CandidatePackets == hardnatbudget.Hard16CandidatePackets && result.WinnerPackets == 0 &&
			result.UDPPackets == hardnatbudget.FreshEvidencePackets+hardnatbudget.Hard16CandidatePackets &&
			result.DataPacketsRead == 0 && result.DataPacketsWritten == 0 && result.CarrierDrained &&
			result.CampaignCircuit && !result.SafetyBlocksWork
	}
	if !common(initiator, directattempt.RoleInitiator) {
		return "initiator_common_witness"
	}
	if !common(responder, directattempt.RoleResponder) {
		return "responder_common_witness"
	}
	if responder.ErrorClass != gateb.ClassCandidateExhausted {
		return "responder_terminal_class"
	}
	if responder.CarrierFramesRead != 7 || responder.CarrierFramesWrite != 8 {
		return "responder_frame_shape"
	}
	switch initiator.ErrorClass {
	case gateb.ClassCandidateExhausted:
		if initiator.CarrierFramesRead != 8 || initiator.CarrierFramesWrite != 7 {
			return "initiator_exhausted_frame_shape"
		}
	case gateb.ClassOOBStreamClosed:
		if initiator.CarrierFramesRead != 7 || initiator.CarrierFramesWrite != 7 {
			return "initiator_eof_frame_shape"
		}
	default:
		return "initiator_terminal_class"
	}
	return ""
}

func TestGateB3LossTerminalContract(t *testing.T) {
	testGateB3LossTerminalContract(t)
}

func testGateB3LossTerminalContract(t *testing.T) {
	base := func(role directattempt.Role) gateB3LossTerminalWitness {
		return gateB3LossTerminalWitness{
			OK: true, Role: string(role), Terminal: "failed", ErrorStage: gateb.StageCandidates,
			CredentialBurned: true, FinishRecorded: true, EvidencePackets: hardnatbudget.FreshEvidencePackets,
			CandidatePackets: hardnatbudget.Hard16CandidatePackets,
			UDPPackets:       hardnatbudget.FreshEvidencePackets + hardnatbudget.Hard16CandidatePackets,
			CarrierDrained:   true, CampaignCircuit: true,
		}
	}
	initiator, responder := base(directattempt.RoleInitiator), base(directattempt.RoleResponder)
	initiator.ErrorClass, initiator.CarrierFramesRead, initiator.CarrierFramesWrite = gateb.ClassOOBStreamClosed, 7, 7
	responder.ErrorClass, responder.CarrierFramesRead, responder.CarrierFramesWrite = gateb.ClassCandidateExhausted, 7, 8
	if !validGateB3LossTerminalPair(initiator, responder) {
		t.Fatal("Gate B3 ordered EOF/exhaustion terminal contract rejected")
	}
	initiator.ErrorClass, initiator.CarrierFramesRead = gateb.ClassCandidateExhausted, 8
	if !validGateB3LossTerminalPair(initiator, responder) {
		t.Fatal("Gate B3 bilateral exhaustion terminal contract rejected")
	}

	tests := []struct {
		name   string
		mutate func(*gateB3LossTerminalWitness, *gateB3LossTerminalWitness)
	}{
		{name: "responder transport close", mutate: func(_, right *gateB3LossTerminalWitness) { right.ErrorClass = gateb.ClassOOBStreamClosed }},
		{name: "initiator expired", mutate: func(left, _ *gateB3LossTerminalWitness) { left.ErrorClass = gateb.ClassAttemptExpired }},
		{name: "incomplete schedule", mutate: func(left, _ *gateB3LossTerminalWitness) { left.CandidatePackets-- }},
		{name: "winner emitted", mutate: func(left, _ *gateB3LossTerminalWitness) { left.WinnerPackets = 1 }},
		{name: "wrong stage", mutate: func(left, _ *gateB3LossTerminalWitness) { left.ErrorStage = gateb.StageWinner }},
		{name: "missing finish", mutate: func(_, right *gateB3LossTerminalWitness) { right.FinishRecorded = false }},
		{name: "machine trip", mutate: func(left, _ *gateB3LossTerminalWitness) { left.SafetyBlocksWork = true }},
		{name: "data emission", mutate: func(_, right *gateB3LossTerminalWitness) { right.DataPacketsWritten = 1 }},
		{name: "carrier not drained", mutate: func(left, _ *gateB3LossTerminalWitness) { left.CarrierDrained = false }},
		{name: "wrong frame shape", mutate: func(left, _ *gateB3LossTerminalWitness) { left.CarrierFramesWrite = 8 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, right := initiator, responder
			test.mutate(&left, &right)
			if validGateB3LossTerminalPair(left, right) {
				t.Fatal("Gate B3 terminal contract accepted an incomplete witness")
			}
		})
	}
}
