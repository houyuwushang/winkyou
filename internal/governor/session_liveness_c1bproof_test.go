//go:build c1bproof

package governor_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/gatecorchestrator"
)

type gateC1bLivenessCase struct {
	rounds        int
	hold          time.Duration
	started       time.Time
	identitySlot  int
	lossDirection uint32
	lossMask      atomic.Uint32
	faultAt       atomic.Int64
	drops         [2]atomic.Uint64
	lastWrite     [2]atomic.Int64
	fault         string
	controls      [2]gatecorchestrator.LivenessMemoryProofControl
	admission     gatecorchestrator.LivenessWitness
	faultError    error
}

func (p *gateC1bLivenessCase) isHardFault() bool {
	return p.fault == "automatic-control" || p.fault == "bypass-admission" || p.fault == "owner-unavailable"
}

func TestSessionLivenessBusinessCoexistsWithTap(t *testing.T) {
	for _, profile := range gateC1bMemoryProfiles {
		t.Run(profile.name, func(t *testing.T) {
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second, fault: "business"}
			profile.candidateTime = max(profile.candidateTime, 500*time.Millisecond)
			runGateC1bMemoryProductProfile(t, "liveness-business-"+profile.name, profile)
			if profile.liveness.faultError != nil {
				t.Fatal("ordinary business delivery failed", profile.liveness.faultError)
			}
			t.Log("business=3/3 exact_bytes=true tap_stole=0 extra_socket=0")
		})
	}
}

type livenessLossFactory struct {
	probeio.Factory
	proof *gateC1bLivenessCase
	side  int
}

func (f *livenessLossFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	d, err := f.Factory.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &livenessLossDatagram{Datagram: d, proof: f.proof, side: f.side}, nil
}

type livenessLossDatagram struct {
	probeio.Datagram
	proof *gateC1bLivenessCase
	side  int
}

func (d *livenessLossDatagram) ReadFrom(ctx context.Context, b []byte) (int, netip.AddrPort, error) {
	for {
		n, source, err := d.Datagram.ReadFrom(ctx, b)
		if err != nil || d.proof.lossMask.Load()&(1<<d.side) == 0 {
			return n, source, err
		}
		d.proof.drops[d.side].Add(1)
	}
}
func (d *livenessLossDatagram) WriteTo(ctx context.Context, b []byte, target netip.AddrPort) (int, error) {
	n, err := d.Datagram.WriteTo(ctx, b, target)
	if n > 0 {
		d.proof.lastWrite[d.side].Store(time.Now().UnixNano())
	}
	return n, err
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

func TestSessionLivenessOwnerTripCasesAreDistinct(t *testing.T) {
	for _, fault := range []string{"normal-admission", "automatic-control", "bypass-admission", "owner-unavailable"} {
		t.Run(fault, func(t *testing.T) {
			profile := gateC1bMemoryProfiles[0]
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second, fault: fault}
			profile.candidateTime = 500 * time.Millisecond
			runGateC1bMemoryProductProfile(t, "liveness-owner-"+fault, profile)
			if fault == "normal-admission" && (profile.liveness.faultError != nil || profile.liveness.admission.LivenessAdmissionRejected != 1 || profile.liveness.admission.PongAdmissionRejected != 1) {
				t.Fatal("normal admission did not retain clear usable session")
			}
			if profile.liveness.controls[0].ReportAfterClose() == nil {
				t.Fatal("post-close report capability remained usable")
			}
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

func TestSessionLivenessMemoryFresh100Required(t *testing.T) {
	if os.Getenv("WINKYOU_LIVENESS_REPEAT_REQUIRED") != "1" {
		t.Skip("100 fresh liveness lifecycles require the dedicated runner")
	}
	for iteration := range 100 {
		profile := gateC1bMemoryProfiles[iteration%len(gateC1bMemoryProfiles)]
		profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: 10 * time.Millisecond}
		profile.candidateTime = max(profile.candidateTime, 500*time.Millisecond)
		if !t.Run(strconv.Itoa(iteration), func(t *testing.T) {
			runGateC1bMemoryProductProfile(t, "liveness-fresh100-"+strconv.Itoa(iteration), profile)
		}) {
			t.FailNow()
		}
	}
	t.Log("liveness fresh_runs=100 profiles=3 owned_resource_residue=0")
}

func TestSessionLivenessMemoryBlackholesRequired(t *testing.T) {
	if os.Getenv("WINKYOU_LIVENESS_BLACKHOLE_REQUIRED") != "1" {
		t.Skip("real-time blackhole proof requires its dedicated runner")
	}
	for ri, rounds := range []int{2, 3} {
		for di, direction := range []uint32{1, 2, 3} {
			name := []string{"m2", "m3"}[ri] + "/" + []string{"rx-initiator", "rx-responder", "both"}[di]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				profile := gateC1bMemoryProfiles[0]
				profile.liveness = &gateC1bLivenessCase{rounds: rounds, hold: 25 * time.Second, lossDirection: direction, identitySlot: 1 + ri*3 + di}
				profile.candidateTime = 500 * time.Millisecond
				runGateC1bMemoryProductProfile(t, "liveness-blackhole-"+name, profile)
				limit := time.Duration(rounds)*20*time.Second + 5*time.Second
				var actualWrite [2]int64
				for side := range 2 {
					delta := time.Duration(profile.liveness.lastWrite[side].Load() - profile.liveness.faultAt.Load())
					actualWrite[side] = delta.Milliseconds()
					if delta > limit {
						t.Fatalf("post-fault emission=%s exceeds %s", delta, limit)
					}
				}
				if time.Since(time.Unix(0, profile.liveness.faultAt.Load())) > limit+2*time.Second {
					t.Fatal("blackhole drain exceeded frozen bound")
				}
				t.Logf("blackhole rounds=%d direction=%d last_write_after_fault_ms=%v drain_after_fault_ms=%d write_bound_ms=%d drain_bound_ms=%d dropped=%d/%d residue=0", rounds, direction, actualWrite, time.Since(time.Unix(0, profile.liveness.faultAt.Load())).Milliseconds(), limit.Milliseconds(), (limit + 2*time.Second).Milliseconds(), profile.liveness.drops[0].Load(), profile.liveness.drops[1].Load())
			})
		}
	}
}

func validateGateC1bLivenessOutcome(t *testing.T, profile gateC1bMemoryProfile, result gatecorchestrator.Result, err error, stages []string, actual uint64, side int) {
	t.Helper()
	hardFault := profile.liveness.isHardFault() && side == 0
	if hardFault {
		want := "session_liveness_budget_exceeded"
		if profile.liveness.fault == "owner-unavailable" {
			want = "session_liveness_unavailable"
		}
		var failure *gatecorchestrator.Failure
		if !errors.As(err, &failure) || failure.Class != want || failure.FinishRecorded == nil || !*failure.FinishRecorded || failure.Retryable {
			t.Errorf("post-FINISH hard fault class=%v want=%s", err, want)
			return
		}
	} else if profile.liveness.lossDirection != 0 {
		var failure *gatecorchestrator.Failure
		if !errors.As(err, &failure) || failure.Class != "session_liveness_timeout" || !failure.CredentialBurned || failure.FinishRecorded == nil || !*failure.FinishRecorded || failure.Retryable || result.SessionEnd != "liveness_timeout" {
			t.Errorf("blackhole terminal lost class/durability: error=%v end=%s", err, result.SessionEnd)
			return
		}
	} else if err != nil {
		t.Errorf("liveness composition terminal=%v end=%s witness=%+v", err, result.SessionEnd, result.Witness.Liveness)
		return
	}
	lv, wg, ho := result.Witness.Liveness, result.Witness.WireGuard, result.Witness.Handoff
	if !result.DataPlaneReady || !result.FinishRecorded || (!hardFault && profile.liveness.lossDirection == 0 && result.Terminal != "success") || !reflect.DeepEqual(stages, gatecorchestrator.ProductProgressSequence) {
		t.Error("liveness changed the establishment pipeline")
	}
	if lv == nil || !lv.Drained || !lv.BindingVerified || wg.ActivePolicy == nil || !wg.Closed ||
		!ho.FinishRecorded || !ho.AttemptReleased || !ho.OOBDrained || ho.Carrier.FramesRead != 8 || ho.Carrier.FramesWritten != 8 ||
		len(wg.Outbound)+wg.ReadinessWrites+wg.CompletionWrites != 3 || len(wg.Inbound)+wg.ReadinessReads+wg.CompletionReads != 3 {
		t.Errorf("liveness lost ownership or original 3/3 and 8-frame boundary: %+v", result.Witness)
		return
	}
	if profile.liveness.hold >= 180*time.Second {
		if time.Since(profile.liveness.started) < 180*time.Second || lv.PongValidated < 8 || lv.PingAdmitted < 8 || wg.ActivePolicy.HandshakeInitiations+wg.ActivePolicy.HandshakeResponses < 1 {
			t.Errorf("idle/rekey not proved: liveness=%+v control=%+v", lv, wg.ActivePolicy)
		}
	}
	if actual != uint64(result.Witness.GateB.Emissions.UDPPacketsTotal+3+wg.ActiveWrites) {
		t.Errorf("actual datagrams=%d inconsistent with disjoint establishment and active writes", actual)
	}
	if wg.ActivePolicy.ControlAdmitted != wg.ActivePolicy.HandshakeInitiations+wg.ActivePolicy.HandshakeResponses+wg.ActivePolicy.CookieReplies+wg.ActivePolicy.EmptyKeepalives {
		t.Fatal("automatic lane subtype accounting mismatch")
	}
	t.Logf("liveness profile=%s elapsed_ms=%d ping=%d pong=%d proof=%d admission_rejected=%d control=%d rekey_init_response=%d/%d empty=%d active_udp=%d total_udp=%d FINISH=true detached=true carrier=8/8 challenge=3/3 drained=true",
		profile.name, lv.ElapsedNS.Milliseconds(), lv.PingAdmitted, lv.PongAdmitted, lv.PongValidated, lv.LivenessAdmissionRejected, wg.ActivePolicy.ControlAdmitted, wg.ActivePolicy.HandshakeInitiations, wg.ActivePolicy.HandshakeResponses, wg.ActivePolicy.EmptyKeepalives, wg.ActiveWrites, actual)
}
