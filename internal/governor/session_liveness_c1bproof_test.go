//go:build c1bproof

package governor_test

import (
	"os"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/v2/gatecorchestrator"
)

type gateC1bLivenessCase struct {
	rounds  int
	hold    time.Duration
	started time.Time
}

func TestSessionLivenessMemoryFreshComposition(t *testing.T) {
	for _, profile := range gateC1bMemoryProfiles {
		t.Run(profile.name, func(t *testing.T) {
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second}
			profile.candidateTime = max(profile.candidateTime, 500*time.Millisecond)
			runGateC1bMemoryProductProfile(t, "liveness-fresh-"+profile.name, profile)
		})
	}
}

func TestSessionLivenessMemoryIdle180Required(t *testing.T) {
	if os.Getenv("WINKYOU_LIVENESS_IDLE_REQUIRED") != "1" {
		t.Skip("real 180-second liveness proof requires its dedicated runner")
	}
	for _, profile := range gateC1bMemoryProfiles {
		t.Run(profile.name, func(t *testing.T) {
			t.Parallel()
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: 180 * time.Second}
			profile.candidateTime = max(profile.candidateTime, 500*time.Millisecond)
			runGateC1bMemoryProductProfile(t, "liveness-idle-"+profile.name, profile)
		})
	}
}

func validateGateC1bLivenessOutcome(t *testing.T, profile gateC1bMemoryProfile, result gatecorchestrator.Result, err error, stages []string, actual uint64) {
	t.Helper()
	if err != nil {
		t.Errorf("liveness composition terminal=%v end=%s witness=%+v", err, result.SessionEnd, result.Witness.Liveness)
		return
	}
	lv, wg, ho := result.Witness.Liveness, result.Witness.WireGuard, result.Witness.Handoff
	if !result.DataPlaneReady || !result.FinishRecorded || result.Terminal != "success" || !reflect.DeepEqual(stages, gatecorchestrator.ProductProgressSequence) {
		t.Error("liveness changed the establishment pipeline")
	}
	if lv == nil || !lv.Drained || !lv.BindingVerified || wg.ActivePolicy == nil || !wg.Closed ||
		!ho.FinishRecorded || !ho.AttemptReleased || !ho.OOBDrained || ho.Carrier.FramesRead != 8 || ho.Carrier.FramesWritten != 8 ||
		len(wg.Outbound)+wg.ReadinessWrites+wg.CompletionWrites != 3 || len(wg.Inbound)+wg.ReadinessReads+wg.CompletionReads != 3 {
		t.Errorf("liveness lost ownership or original 3/3 and 8-frame boundary: %+v", result.Witness)
		return
	}
	if profile.liveness.hold >= 180*time.Second {
		if time.Since(profile.liveness.started) < 180*time.Second || lv.PongValidated < 8 || lv.PingAdmitted < 8 || wg.ActivePolicy.ControlAdmitted < 1 {
			t.Errorf("idle/rekey not proved: liveness=%+v control=%+v", lv, wg.ActivePolicy)
		}
	}
	if actual != uint64(result.Witness.GateB.Emissions.UDPPacketsTotal+3+wg.ActiveWrites) {
		t.Errorf("actual datagrams=%d inconsistent with disjoint establishment and active writes", actual)
	}
	t.Logf("liveness profile=%s elapsed_ms=%d ping=%d pong=%d proof=%d admission_rejected=%d control=%d active_udp=%d total_udp=%d FINISH=true detached=true carrier=8/8 challenge=3/3 drained=true",
		profile.name, lv.ElapsedNS.Milliseconds(), lv.PingAdmitted, lv.PongAdmitted, lv.PongValidated, lv.LivenessAdmissionRejected, wg.ActivePolicy.ControlAdmitted, wg.ActiveWrites, actual)
}
