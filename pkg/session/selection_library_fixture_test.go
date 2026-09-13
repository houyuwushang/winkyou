package session

import (
	"context"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

// Only the independent, single-side library lifecycle fixtures use this helper.
// Their cancellation/binding assertions are unchanged; S1 now requires an actual
// nonempty capability message instead of their old 1ms implicit timeout fallback.
// This is NOT a bilateral S3 proof or an input to the real relay test.
func deliverLibraryTestCapability(t *testing.T, s *Session) {
	t.Helper()
	if s.agreement != nil {
		t.Fatal("library fixture cannot bypass converging protocol")
	}
	envelope := rproto.SessionEnvelope{SessionID: s.ID(), FromNode: s.cfg.PeerID, ToNode: s.cfg.LocalNodeID, MsgType: rproto.MsgTypeCapability, Payload: rproto.MustPayload(s.localCapability())}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HandleMessage(context.Background(), solver.Message{Kind: solver.MessageKindEnvelope, Namespace: envelopeNamespace, Type: rproto.MsgTypeCapability, Payload: payload, ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}
