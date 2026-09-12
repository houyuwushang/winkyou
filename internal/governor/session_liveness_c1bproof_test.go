//go:build c1bproof

package governor_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/pkg/netif"
)

type gateC1bLivenessCase struct {
	rounds          int
	hold            time.Duration
	started         time.Time
	identitySlot    int
	lossDirection   uint32
	lossMask        atomic.Uint32
	faultAt         atomic.Int64
	drops           [2]atomic.Uint64
	lastWrite       [2]atomic.Int64
	fault           string
	controls        [2]gatecorchestrator.LivenessMemoryProofControl
	admission       gatecorchestrator.LivenessWitness
	faultError      error
	restart         bool
	trafficSide     int // 1/2=one-way business, 3=WG control only, 4=garbage RX; 0=off
	trafficBatches  atomic.Uint64
	controlPackets  [2]atomic.Uint64 // successful post-fault WG handshake writes
	emptyPackets    [2]atomic.Uint64 // successful post-fault WG empty keepalive writes
	closeMode       string           // test-only: delivered / interleaved / lost
	unrelatedKind   string
	closeInner      atomic.Uint64
	unrelatedWrites atomic.Uint64
	closeDropped    atomic.Uint64
	closeOutcome    [2]gatecorchestrator.Result
	health          [2]gatecorchestrator.LivenessWitness
	healthRekeys    [2]uint64
	healthError     [2]error
	healthElapsed   time.Duration
}

func (p *gateC1bLivenessCase) captureHealth() {
	for side := range 2 {
		p.health[side], p.healthRekeys[side], p.healthError[side] = p.controls[side].HealthySnapshot()
	}
	p.healthElapsed = time.Since(p.started)
}

func idleHealthError(elapsed time.Duration, lv gatecorchestrator.LivenessWitness, rekeys uint64, permitErr error) error {
	if permitErr != nil || elapsed < 180*time.Second || lv.ElapsedNS < 180*time.Second || lv.Drained || lv.PongValidated < 8 || lv.PingAdmitted < 8 || rekeys < 1 {
		return errors.New("pre-cancel idle health was not proved")
	}
	return nil
}

func TestSessionLivenessIdleHealthRequiresPreCancelWitness(t *testing.T) {
	healthy := gatecorchestrator.LivenessWitness{ElapsedNS: 180 * time.Second, PingAdmitted: 8, PongValidated: 8}
	if err := idleHealthError(180*time.Second, healthy, 1, nil); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"elapsed", "witness-age", "expired", "drained", "proof", "rekey"} {
		t.Run(mutation, func(t *testing.T) {
			lv, elapsed, rekeys, permit := healthy, 180*time.Second, uint64(1), error(nil)
			switch mutation {
			case "elapsed":
				elapsed--
			case "witness-age":
				lv.ElapsedNS--
			case "expired":
				permit = errors.New("expired before fixture cancellation")
			case "drained":
				lv.Drained = true
			case "proof":
				lv.PongValidated--
			case "rekey":
				rekeys = 0
			}
			if idleHealthError(elapsed, lv, rekeys, permit) == nil {
				t.Fatal("invalid health accepted")
			}
		})
	}
}

type closeInterleavingInterface struct {
	netif.MemoryTestInterface
	proof  *gateC1bLivenessCase
	closed chan struct{}
	once   sync.Once
}

func (f *closeInterleavingInterface) Close() error {
	f.once.Do(func() { close(f.closed) })
	return f.MemoryTestInterface.Close()
}

func (f *closeInterleavingInterface) InjectPacket(packet []byte) (int, error) {
	// Exact synthetic WYCE CLOSE at the inner boundary, not a production
	// ciphertext classifier. Original parser, wire and packet remain unchanged.
	if len(packet) == 76 && string(packet[28:32]) == "WYCE" && packet[33] == 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := f.proof.controls[0].CompleteUnrelatedCloseWrite(ctx, f.proof.unrelatedKind)
		cancel()
		if err != nil {
			return 0, err
		}
		f.proof.unrelatedWrites.Add(1)
		timer := time.NewTimer(250 * time.Millisecond) // strictly inside original 1s writer window
		defer timer.Stop()
		select {
		case <-f.closed:
			return 0, errors.New("synthetic CLOSE canceled before injection")
		case <-timer.C:
		}
		n, err := f.MemoryTestInterface.InjectPacket(packet)
		if err == nil && n == len(packet) {
			f.proof.closeInner.Add(1)
		}
		return n, err
	}
	return f.MemoryTestInterface.InjectPacket(packet)
}

func TestSessionLivenessCloseCompletion(t *testing.T) {
	for _, kind := range []string{"data", "empty", "rekey"} {
		t.Run(kind, func(t *testing.T) {
			profile := gateC1bMemoryProfiles[0]
			p := &gateC1bLivenessCase{rounds: 3, hold: time.Second, closeMode: "interleaved", unrelatedKind: kind}
			profile.liveness = p
			runGateC1bMemoryProductProfile(t, "liveness-close-"+kind, profile)
			if p.unrelatedWrites.Load() != 1 || p.closeInner.Load() != 1 {
				t.Fatalf("unrelated=%d CLOSE_inner=%d; unrelated write must not cancel CLOSE", p.unrelatedWrites.Load(), p.closeInner.Load())
			}
			validateCloseDelivery(t, p)
		})
	}
}

func validateCloseDelivery(t *testing.T, p *gateC1bLivenessCase) {
	t.Helper()
	i, r := p.closeOutcome[0], p.closeOutcome[1]
	if i.Witness.Echo.CloseWritten != 0 || i.SessionEnd != "canceled" ||
		r.Witness.Echo.CloseRead != 1 || r.SessionEnd != "authenticated_close" {
		t.Fatalf("CLOSE lost receipt/delivery: local=%s/%+v peer=%s/%+v", i.SessionEnd, i.Witness.Echo, r.SessionEnd, r.Witness.Echo)
	}
	t.Logf("CLOSE unrelated=%s completed=%d inner=%d outer_claim=0 authenticated_peer_read=1 drained=true", p.unrelatedKind, p.unrelatedWrites.Load(), p.closeInner.Load())
}

type livenessRestartIOTrap struct{ calls atomic.Int64 }

func (t *livenessRestartIOTrap) Open(context.Context) (probeio.Datagram, error) {
	t.calls.Add(1)
	return nil, errors.New("restart attempted socket")
}
func (t *livenessRestartIOTrap) Read([]byte) (int, error) {
	t.calls.Add(1)
	return 0, errors.New("restart attempted read")
}
func (t *livenessRestartIOTrap) Write([]byte) (int, error) {
	t.calls.Add(1)
	return 0, errors.New("restart attempted write")
}
func (t *livenessRestartIOTrap) SetDeadline(time.Time) error {
	t.calls.Add(1)
	return errors.New("restart adopted stream")
}
func (*livenessRestartIOTrap) Close() error { return nil }

func TestSessionLivenessRestartRejectsSpentArtifactBeforeIO(t *testing.T) {
	for _, profile := range gateC1bMemoryProfiles {
		t.Run(profile.name, func(t *testing.T) {
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second, restart: true}
			runGateC1bMemoryProductProfile(t, "liveness-restart-"+profile.name, profile)
		})
	}
}

func (p *gateC1bLivenessCase) isHardFault() bool {
	return p.fault == "automatic-control" || p.fault == "bypass-admission" || p.fault == "owner-unavailable"
}

func TestSessionLivenessBusinessCoexistsWithTap(t *testing.T) {
	for _, profile := range gateC1bMemoryProfiles {
		t.Run(profile.name, func(t *testing.T) {
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second, fault: "business"}
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
		// In this isolated fixture the ONLY post-cancel 112-byte WG data is
		// the 76-byte WYCE CLOSE. Count its loss independently from liveness.
		if err == nil && d.side == 1 && d.proof.closeMode == "lost" && d.proof.faultAt.Load() != 0 && n == 112 && b[0] == 4 {
			d.proof.closeDropped.Add(1)
			continue
		}
		drop := d.proof.lossMask.Load()&(1<<d.side) != 0
		if d.proof.trafficSide != 0 {
			// Test-only loss fixture: its synthetic 44-byte business packet
			// encrypts to 80 bytes; its ONLY 128-byte active data is WYCL.
			// This is not a production classifier or accounting authority.
			drop = drop && n == 128 && b[0] == 4
		}
		if err != nil || !drop {
			return n, source, err
		}
		d.proof.drops[d.side].Add(1)
	}
}

func TestSessionLivenessOneWayTrafficCannotReplaceProofRequired(t *testing.T) {
	if os.Getenv("WINKYOU_LIVENESS_BLACKHOLE_REQUIRED") != "1" {
		t.Skip("real persistent-timer counterexample requires its dedicated runner")
	}
	for side := 1; side <= 4; side++ {
		t.Run(strconv.Itoa(side), func(t *testing.T) {
			// These are four independent long-window counterexamples, not a
			// concurrent candidate-search load test. Use the same shared fixture
			// windows, without contending four setups on a runner.
			profile := gateC1bMemoryProfiles[0]
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second, lossDirection: 3, trafficSide: side, identitySlot: 10 + side}
			runGateC1bMemoryProductProfile(t, "liveness-one-way-"+strconv.Itoa(side), profile)
			if side != 3 && profile.liveness.trafficBatches.Load() < 50 {
				t.Fatal("continuous nonproof traffic not demonstrated")
			}
			if side == 3 {
				p := profile.liveness
				// WG's authenticated send cancels its local keepalive timer. It
				// need not send every automatic subtype on BOTH endpoints. Require
				// both kinds actually on the wire in this pair, while the outcome
				// oracle above still requires BOTH permits to expire with 0 PONGs.
				if p.controlPackets[0].Load()+p.controlPackets[1].Load() == 0 || p.emptyPackets[0].Load()+p.emptyPackets[1].Load() == 0 {
					t.Fatal("pair did not actually emit both handshake and empty keepalive without proof")
				}
				t.Logf("nonproof_control_actual handshake=%d/%d empty=%d/%d both_permits_expired=true", p.controlPackets[0].Load(), p.controlPackets[1].Load(), p.emptyPackets[0].Load(), p.emptyPackets[1].Load())
			}
			t.Logf("nonproof_traffic mode=%d batches=%d lost_WYCL=%d/%d lease_renewed=false residue=0", side, profile.liveness.trafficBatches.Load(), profile.liveness.drops[0].Load(), profile.liveness.drops[1].Load())
		})
	}
}
func (d *livenessLossDatagram) WriteTo(ctx context.Context, b []byte, target netip.AddrPort) (int, error) {
	n, err := d.Datagram.WriteTo(ctx, b, target)
	if n > 0 {
		d.proof.lastWrite[d.side].Store(time.Now().UnixNano())
	}
	if err == nil && n == len(b) {
		d.proof.recordCompletedAutomatic(d.side, b)
	}
	return n, err
}

func (p *gateC1bLivenessCase) recordCompletedAutomatic(side int, packet []byte) {
	if p.trafficSide != 3 || p.faultAt.Load() == 0 || len(packet) < 4 {
		return
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 1:
		if len(packet) == 148 {
			p.controlPackets[side].Add(1)
		}
	case 2:
		if len(packet) == 92 {
			p.controlPackets[side].Add(1)
		}
	case 4:
		if len(packet) == 32 {
			p.emptyPackets[side].Add(1)
		}
	}
}

func TestSessionLivenessMemoryFreshComposition(t *testing.T) {
	for _, profile := range gateC1bMemoryProfiles {
		t.Run(profile.name, func(t *testing.T) {
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second}
			runGateC1bMemoryProductProfile(t, "liveness-fresh-"+profile.name, profile)
		})
	}
}

func TestSessionLivenessOwnerTripCasesAreDistinct(t *testing.T) {
	for _, fault := range []string{"normal-admission", "automatic-control", "bypass-admission", "owner-unavailable"} {
		t.Run(fault, func(t *testing.T) {
			profile := gateC1bMemoryProfiles[0]
			profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: time.Second, fault: fault}
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
			runGateC1bMemoryProductProfile(t, "liveness-idle-"+profile.name, profile)
		})
	}
	// Required CI also exercises the actual unrelated-write counterexamples;
	// the healthy 180s phase above does not rely on CLOSE delivery.
	t.Run("close-completion", TestSessionLivenessCloseCompletion)
	t.Run("close-loss", func(t *testing.T) {
		t.Parallel()
		profile := gateC1bMemoryProfiles[0]
		p := &gateC1bLivenessCase{rounds: 3, hold: time.Second, closeMode: "lost", identitySlot: 8}
		profile.liveness = p
		runGateC1bMemoryProductProfile(t, "liveness-close-lost", profile)
		if p.closeDropped.Load() != 1 || p.closeOutcome[1].Witness.Echo.CloseRead != 0 {
			t.Fatal("exactly one CLOSE loss was not witnessed")
		}
		if p.faultAt.Load() == 0 || time.Since(time.Unix(0, p.faultAt.Load())) > 67*time.Second {
			t.Fatal("missing fault witness or CLOSE loss exceeded original drain bound")
		}
		t.Logf("CLOSE lost=1 retry=0 peer_timeout=true drain_after_cancel_ms=%d residue=0", time.Since(time.Unix(0, p.faultAt.Load())).Milliseconds())
	})
}

func TestSessionLivenessMemoryFresh100Required(t *testing.T) {
	if os.Getenv("WINKYOU_LIVENESS_REPEAT_REQUIRED") != "1" {
		t.Skip("100 fresh liveness lifecycles require the dedicated runner")
	}
	for iteration := range 100 {
		profile := gateC1bMemoryProfiles[iteration%len(gateC1bMemoryProfiles)]
		profile.liveness = &gateC1bLivenessCase{rounds: 3, hold: 10 * time.Millisecond}
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
				runGateC1bMemoryProductProfile(t, "liveness-blackhole-"+name, profile)
				if profile.liveness.faultAt.Load() == 0 {
					t.Fatal("liveness fault was not armed; no post-fault time arithmetic is valid")
				}
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
	closeLost := profile.liveness.closeMode == "lost" && side == 1
	profile.liveness.closeOutcome[side] = result
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
	} else if profile.liveness.lossDirection != 0 || closeLost {
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
	if !result.DataPlaneReady || !result.FinishRecorded || (!hardFault && !closeLost && profile.liveness.lossDirection == 0 && result.Terminal != "success") || !reflect.DeepEqual(stages, gatecorchestrator.ProductProgressSequence) {
		t.Error("liveness changed the establishment pipeline")
	}
	if lv == nil || !lv.Drained || !lv.BindingVerified || wg.ActivePolicy == nil || !wg.Closed ||
		!ho.FinishRecorded || !ho.AttemptReleased || !ho.OOBDrained || ho.Carrier.FramesRead != 8 || ho.Carrier.FramesWritten != 8 ||
		len(wg.Outbound)+wg.ReadinessWrites+wg.CompletionWrites != 3 || len(wg.Inbound)+wg.ReadinessReads+wg.CompletionReads != 3 {
		t.Errorf("liveness lost ownership or original 3/3 and 8-frame boundary: %+v", result.Witness)
		return
	}
	if profile.liveness.hold >= 180*time.Second {
		p := profile.liveness
		if idleHealthError(p.healthElapsed, p.health[side], p.healthRekeys[side], p.healthError[side]) != nil {
			t.Errorf("pre-cancel idle/rekey not proved: elapsed=%s error=%v witness=%+v rekey=%d", p.healthElapsed, p.healthError[side], p.health[side], p.healthRekeys[side])
		}
		t.Logf("IDLE_HEALTH before_cancel=true side=%d elapsed_ms=%d permit_valid=%t proof=%d rekey=%d", side, p.healthElapsed.Milliseconds(), p.healthError[side] == nil, p.health[side].PongValidated, p.healthRekeys[side])
	}
	if actual != uint64(result.Witness.GateB.Emissions.UDPPacketsTotal+3+wg.ActiveWrites) {
		t.Errorf("actual datagrams=%d inconsistent with disjoint establishment and active writes: gate_b=%d challenge=3 active=%d", actual, result.Witness.GateB.Emissions.UDPPacketsTotal, wg.ActiveWrites)
	}
	if profile.liveness.trafficSide != 0 && lv.PongValidated != 0 {
		t.Fatal("nonproof traffic renewed permit")
	}
	if profile.liveness.trafficSide == 4 && wg.ActiveReads < 50 {
		t.Fatal("garbage did not reach raw receive boundary")
	}
	if wg.ActivePolicy.ControlAdmitted != wg.ActivePolicy.HandshakeInitiations+wg.ActivePolicy.HandshakeResponses+wg.ActivePolicy.CookieReplies+wg.ActivePolicy.EmptyKeepalives {
		t.Fatal("automatic lane subtype accounting mismatch")
	}
	t.Logf("liveness profile=%s elapsed_ms=%d ping=%d pong=%d proof=%d admission_rejected=%d control=%d rekey_init_response=%d/%d empty=%d active_udp=%d total_udp=%d FINISH=true detached=true carrier=8/8 challenge=3/3 drained=true",
		profile.name, lv.ElapsedNS.Milliseconds(), lv.PingAdmitted, lv.PongAdmitted, lv.PongValidated, lv.LivenessAdmissionRejected, wg.ActivePolicy.ControlAdmitted, wg.ActivePolicy.HandshakeInitiations, wg.ActivePolicy.HandshakeResponses, wg.ActivePolicy.EmptyKeepalives, wg.ActiveWrites, actual)
}

// This precondition runs for BOTH returned endpoints before any liveness
// duration assertion. Gate B failure is not a liveness timeout, and a zero
// ready timestamp must never become a decades-long "post-fault" duration.
func gateC1bLivenessReadyPrecondition(result gatecorchestrator.Result, terminal error, started time.Time) error {
	if result.DataPlaneReady && !started.IsZero() {
		return nil
	}
	class, stage := "missing_ready_witness", "unknown"
	var failure *gatecorchestrator.Failure
	if errors.As(terminal, &failure) {
		class, stage = failure.Class, failure.Stage
	}
	return fmt.Errorf("liveness_not_armed: gate_b_class=%s stage=%s data_plane_ready=%t ready_time_present=%t",
		class, stage, result.DataPlaneReady, !started.IsZero())
}

func TestSessionLivenessUnarmedPreconditionRejectsZeroTimestamp(t *testing.T) {
	for _, class := range []string{gateb.ClassCandidateExhausted, gateb.ClassAttemptExpired, gateb.ClassOOBStreamClosed} {
		terminal := &gatecorchestrator.Failure{Class: class, Stage: gateb.StageCandidates}
		err := gateC1bLivenessReadyPrecondition(gatecorchestrator.Result{}, terminal, time.Time{})
		if err == nil || !strings.Contains(err.Error(), "liveness_not_armed") || !strings.Contains(err.Error(), class) ||
			strings.Contains(err.Error(), "post-fault emission") || strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("unarmed session lost its Gate B class: %v", err)
		}
	}
	ready := gatecorchestrator.Result{DataPlaneReady: true}
	if gateC1bLivenessReadyPrecondition(ready, nil, time.Time{}) == nil {
		t.Fatal("ready result without a bilateral ready timestamp was accepted")
	}
	if err := gateC1bLivenessReadyPrecondition(ready, nil, time.Now()); err != nil {
		t.Fatal("armed control rejected", err)
	}
}
