//go:build c1bdiagnostic

package probeio

import (
	"context"
	"testing"
	"time"
)

// This opt-in reproducer is intentionally RED while ADR C1 §19 is undecided.
// It is not a successful-path regression gate and never opens a real socket.
// The existing default tests and required full-pipeline CI remain unchanged.
// The packet gates use fake local transports; the real ledger/OOB composition
// failure is independently preserved in the required Linux memory CI logs.
func TestC1bUnilateralFinishGapDiagnostic(t *testing.T) {
	initiator, initiatorTransport, _ := newWireGuardGate(t, WireGuardInitiator)
	responder, responderTransport, _ := newWireGuardGate(t, WireGuardResponder)
	for _, pair := range []struct {
		gate      *WireGuardSessionGate
		transport *wireGuardGateTransport
	}{{initiator, initiatorTransport}, {responder, responderTransport}} {
		if err := beginReadyChallenge(pair.gate, pair.transport); err != nil {
			t.Fatal("diagnostic setup failed")
		}
	}
	write := func(gate *WireGuardSessionGate, kind WireGuardMessageType) {
		t.Helper()
		if err := gate.WritePacket(context.Background(), wireGuardPacket(kind)); err != nil {
			t.Fatal("diagnostic write setup failed")
		}
	}
	read := func(gate *WireGuardSessionGate, stream *wireGuardGateTransport, kind WireGuardMessageType) {
		t.Helper()
		stream.queueRead(wireGuardPacket(kind))
		if _, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
			t.Fatal("diagnostic read setup failed")
		}
	}
	write(initiator, WireGuardHandshakeInitiation)
	read(responder, responderTransport, WireGuardHandshakeInitiation)
	write(responder, WireGuardHandshakeResponse)
	read(initiator, initiatorTransport, WireGuardHandshakeResponse)
	write(initiator, WireGuardTransportData)
	read(responder, responderTransport, WireGuardTransportData)
	// Both fixed byte-type traces are already complete. Only the responder's
	// orchestrator/durable transition has not yet been scheduled.
	if err := initiator.CompleteChallenge(); err != nil {
		t.Fatal("diagnostic initiator challenge setup failed")
	}
	session, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finishes := 0
	if err := initiator.FinishAndActivate(session, func() error { finishes++; return nil }); err != nil {
		t.Fatal("diagnostic local FINISH setup failed")
	}
	before := responderTransport.writeCount()
	// This is the unchanged runtime watcher rule for pre-FINISH carrier EOF:
	// cancel the active attempt. It deliberately does not relax that rule.
	responder.attemptCancel()
	responderErr := responder.CompleteChallenge()
	left, right := initiator.Witness(), responder.Witness()
	if finishes == 1 && left.FinishRecorded && left.AttemptDetached && !right.FinishRecorded &&
		responderErr != nil && responderTransport.writeCount() == before {
		t.Fatal("finish gap reproduced: local_finish=1 peer_finish=0 both_traces_complete=true peer_eof_rejected=true extra_packets=0")
	}
	t.Fatal("diagnostic premise changed; re-review the protocol and remove this reproducer only with the accepted replacement proof")
}
