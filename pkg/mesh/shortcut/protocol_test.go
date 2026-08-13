package shortcut

import (
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/solver"
)

func TestWireMessageRoundTrip(t *testing.T) {
	original := wireMessage{
		AttemptID: "attempt-1", InitiatorID: "A", TargetID: "C", CoordinatorID: "B",
		Strategy: "birthday_punch", ProbationMillis: 30_000, SentAt: time.Unix(100, 0).UTC(),
		SolverMessage: &solver.Message{
			Kind: solver.MessageKindStrategy, Namespace: "birthdaypunch", Type: "punch_endpoint",
			Payload: []byte("endpoint"), ReceivedAt: time.Unix(101, 0).UTC(),
		},
	}
	raw, err := marshalWire(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.AttemptID != original.AttemptID || decoded.Strategy != original.Strategy ||
		decoded.SolverMessage == nil || string(decoded.SolverMessage.Payload) != "endpoint" {
		t.Fatalf("decoded wire = %+v", decoded)
	}
	if decoded.encodedSize != len(raw) {
		t.Fatalf("decoded encoded size = %d, want %d", decoded.encodedSize, len(raw))
	}
}

func TestManagerRejectsProbationShorterThanLivenessTimeout(t *testing.T) {
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	_, err = NewManager(Config{
		Node: node, StrategyName: "test", Probation: 50 * time.Millisecond,
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 20 * time.Millisecond,
			PeerTimeout:       100 * time.Millisecond,
		},
	})
	if err == nil {
		t.Fatal("manager accepted probation shorter than peer timeout")
	}
}
