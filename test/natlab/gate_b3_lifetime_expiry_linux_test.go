//go:build linux && natlab

package natlab

import (
	"testing"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
)

// This predicate is used ONLY by the explicitly named M-E fixtures. The
// ordinary fifty-percent loss predicate is unchanged and rejects these rows.
func validGateB3ExpiryPair(winnerLeft bool, left, right gateB3EndpointResult) bool {
	common := func(result gateB3EndpointResult, role directattempt.Role, winner int) bool {
		return result.OK && result.Role == string(role) && result.Terminal == "failed" &&
			result.CredentialBurned && result.FinishRecorded && !result.Bidirectional &&
			result.EvidencePackets == 13 && result.CandidatePackets == 16384 && result.WinnerPackets == winner &&
			result.UDPPackets == 16397+winner && result.DataPacketsRead == 0 && result.DataPacketsWritten == 0 &&
			result.CarrierDrained && result.CampaignCircuit && !result.SafetyBlocksWork
	}
	if !common(left, directattempt.RoleInitiator, boolGateB3Int(winnerLeft)) ||
		!common(right, directattempt.RoleResponder, boolGateB3Int(!winnerLeft)) || (!left.LocalDeadline && !right.LocalDeadline) {
		return false
	}
	if !(left.ErrorClass == gateb.ClassAttemptExpired && right.ErrorClass == gateb.ClassOOBStreamClosed ||
		left.ErrorClass == gateb.ClassOOBStreamClosed && right.ErrorClass == gateb.ClassAttemptExpired ||
		left.ErrorClass == gateb.ClassAttemptExpired && right.ErrorClass == gateb.ClassAttemptExpired) {
		return false
	}
	if winnerLeft {
		return left.ErrorStage == gateb.StageVerify && left.CarrierFramesRead == 7 && left.CarrierFramesWrite == 8 &&
			right.ErrorStage == gateb.StageCandidates && right.CarrierFramesRead == 8 && right.CarrierFramesWrite == 7
	}
	return left.ErrorStage == gateb.StageCandidates && left.CarrierFramesRead == 7 && left.CarrierFramesWrite == 7 &&
		right.ErrorStage == gateb.StageVerify && right.CarrierFramesRead == 7 && right.CarrierFramesWrite == 7
}

func testGateB3ExpiryContract(t *testing.T) {
	for _, winnerLeft := range []bool{false, true} {
		base := func(role directattempt.Role, winner int) gateB3EndpointResult {
			return gateB3EndpointResult{gateB2EndpointResult: gateB2EndpointResult{
				OK: true, Role: string(role), Terminal: "failed", CredentialBurned: true, FinishRecorded: true,
				EvidencePackets: 13, CandidatePackets: 16384, WinnerPackets: winner, UDPPackets: 16397 + winner,
				CarrierDrained: true, CarrierFramesRead: 7, CarrierFramesWrite: 7,
			}, CampaignCircuit: true}
		}
		left, right := base(directattempt.RoleInitiator, boolGateB3Int(winnerLeft)), base(directattempt.RoleResponder, boolGateB3Int(!winnerLeft))
		left.LocalDeadline = true
		left.ErrorClass, right.ErrorClass = gateb.ClassAttemptExpired, gateb.ClassOOBStreamClosed
		left.ErrorStage, right.ErrorStage = gateb.StageCandidates, gateb.StageVerify
		if winnerLeft {
			left.ErrorStage, right.ErrorStage = gateb.StageVerify, gateb.StageCandidates
			left.CarrierFramesWrite, right.CarrierFramesRead = 8, 8
		}
		if !validGateB3ExpiryPair(winnerLeft, left, right) || validGateB3FiftyPercentLossTerminal(left, right) {
			t.Fatal("explicit expiry row was rejected or leaked into ordinary loss acceptance")
		}
		for _, mutate := range []func(*gateB3EndpointResult, *gateB3EndpointResult){
			func(a, b *gateB3EndpointResult) { a.LocalDeadline, b.LocalDeadline = false, false },
			func(a, _ *gateB3EndpointResult) { a.CandidatePackets-- },
			func(_, b *gateB3EndpointResult) { b.UDPPackets-- },
			func(a, _ *gateB3EndpointResult) { a.WinnerPackets++ },
			func(a, _ *gateB3EndpointResult) { a.ErrorClass = gateb.ClassOOBStreamClosed },
			func(a, _ *gateB3EndpointResult) { a.ErrorClass = gateb.ClassOOBProtocolViolation },
			func(a, _ *gateB3EndpointResult) { a.ErrorStage = gateb.StageHandoff },
			func(a, _ *gateB3EndpointResult) { a.FinishRecorded = false },
			func(a, _ *gateB3EndpointResult) { a.CarrierDrained = false },
			func(a, _ *gateB3EndpointResult) { a.SafetyBlocksWork = true },
			func(a, _ *gateB3EndpointResult) { a.DataPacketsWritten = 1 },
			func(_, b *gateB3EndpointResult) { b.CarrierFramesRead-- },
		} {
			a, b := left, right
			mutate(&a, &b)
			if validGateB3ExpiryPair(winnerLeft, a, b) {
				t.Fatal("mapping expiry negative mutation was accepted")
			}
		}
	}
}
