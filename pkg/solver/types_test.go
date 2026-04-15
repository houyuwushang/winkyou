package solver

import "testing"

func TestMessageKindsAreGeneric(t *testing.T) {
	msg := Message{
		Kind:      MessageKindStrategy,
		Namespace: "legacyice",
		Type:      "offer",
		Payload:   []byte("payload"),
	}

	if msg.Kind != MessageKindStrategy {
		t.Fatalf("Kind = %q, want %q", msg.Kind, MessageKindStrategy)
	}
	if msg.Namespace != "legacyice" || msg.Type != "offer" {
		t.Fatalf("message namespace/type = %q/%q, want legacyice/offer", msg.Namespace, msg.Type)
	}
}
