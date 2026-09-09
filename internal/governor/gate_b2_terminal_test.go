package governor_test

import (
	"errors"
	"net"
	"sync"
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
