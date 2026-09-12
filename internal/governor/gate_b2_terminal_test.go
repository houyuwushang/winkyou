package governor_test

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directconnect/gateb"
)

type gateB2DiagnosticStream struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

type gateB2SlowCloseStream struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (stream *gateB2SlowCloseStream) Close() error {
	stream.once.Do(func() {
		_ = stream.Conn.Close()
		close(stream.entered)
		<-stream.release
	})
	return nil
}

func TestGateB2FIREFreshnessTerminalWaitsForCarrierDrainWitness(t *testing.T) {
	var leftMachine *governor.Governor
	var terminal atomic.Bool
	type observation struct{ entered, terminal, released bool }
	proof := make(chan observation, 1)
	outcomes := runGateB2SafetyRegression(t, "active_envelope_at_candidates", gateB2SafetyTestHooks{
		streams: func(left, _ *governor.Governor, a, b net.Conn) (net.Conn, net.Conn) {
			leftMachine = left
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			go func() {
				defer unblock()
				timer := time.NewTimer(2*time.Second + 100*time.Millisecond)
				defer timer.Stop()
				got := observation{}
				select {
				case <-entered:
					got.entered, got.terminal = true, terminal.Load()
					select {
					case <-governor.GateB2AttemptDoneForDiagnostic(left):
						got.released = true
					default:
					}
				case <-timer.C:
				}
				proof <- got
			}()
			return &gateB2SlowCloseStream{Conn: a, entered: entered, release: release}, b
		},
		progress: func(machine *governor.Governor, stage string) {
			if machine == leftMachine && stage == gateb.StageTerminal {
				terminal.Store(true)
			}
		},
	})
	got := <-proof
	if !got.entered || got.terminal || got.released || !terminal.Load() {
		t.Fatalf("runtime terminal did not wait for actual Close/drain: %+v terminal_after=%t", got, terminal.Load())
	}
	for _, outcome := range outcomes {
		if !outcome.result.FinishRecorded || !outcome.result.CarrierWitness.Drained ||
			outcome.result.Emissions.CandidatePackets != 0 || outcome.result.SafetyTrip.BlocksActiveWork {
			t.Fatal("slow drain changed the fail-closed terminal")
		}
	}
}

func (stream *gateB2DiagnosticStream) Close() error {
	err := stream.Conn.Close()
	stream.once.Do(func() { close(stream.closed) })
	return err
}

// The real active-envelope watcher releases the post-sync barrier. The old
// implementation retained the attempt even after this bounded drain wait.
func TestGateB2FIREFreshnessBurnCrossesActiveEnvelope(t *testing.T) {
	runGateB2SafetyRegression(t, "active_envelope_at_candidates", gateB2SafetyTestHooks{
		streams: func(left, _ *governor.Governor, a, b net.Conn) (net.Conn, net.Conn) {
			stream := &gateB2DiagnosticStream{Conn: a, closed: make(chan struct{})}
			if err := governor.HoldGateB2BurnForDiagnostic(left, stream.closed); err != nil {
				t.Fatal(err)
			}
			return stream, b
		},
		beforeResidue: func(outcomes []gateB2SafetyOutcome, left, _ *governor.Governor) {
			for i, outcome := range outcomes {
				var failure *gateb.Failure
				if !errors.As(outcome.err, &failure) {
					t.Fatalf("missing stable failure on side %d", i)
				}
				t.Logf("side=%d class=%s stage=%s burned=%t finish=%t carrier_drained=%t candidates=%d safety_blocking=%t",
					i, failure.Class, failure.Stage, outcome.result.CredentialBurned, outcome.result.FinishRecorded,
					outcome.result.CarrierWitness.Drained, outcome.result.Emissions.CandidatePackets, outcome.result.SafetyTrip.BlocksActiveWork)
			}
			timer := time.NewTimer(2*time.Second + 100*time.Millisecond)
			defer timer.Stop()
			select {
			case <-governor.GateB2AttemptDoneForDiagnostic(left):
				t.Log("attempt_done=true")
			case <-timer.C:
				t.Error("attempt_done=false after drain bound plus observation margin")
			}
			count, packets, err := governor.LoopbackCarrierTestOccupancy(left)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("durable_unfinished=%d durable_packets=%d", count, packets)
			if count != 0 || packets != 0 {
				t.Error("durable FINISH did not complete before attempt release")
			}
			for _, outcome := range outcomes {
				if !outcome.result.FinishRecorded || !outcome.result.CarrierWitness.Drained ||
					outcome.result.Emissions.CandidatePackets != 0 || outcome.result.SafetyTrip.BlocksActiveWork {
					t.Error("expired burned attempt lost its durable terminal/drain witness")
				}
			}
		},
	})
}
