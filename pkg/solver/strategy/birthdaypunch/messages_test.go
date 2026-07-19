package birthdaypunch

import (
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func TestEndpointPayloadRoundTrip(t *testing.T) {
	orig := endpointPayload{
		SessionID:    "session/a/b",
		PlanID:       "birthdaypunch/direct",
		PublicIP:     "210.30.106.93",
		ObservedPort: 55161,
		Pattern:      "sequential",
		Delta:        1,
		SentAt:       time.Unix(1000, 0).UTC(),
	}
	data, err := marshalEndpoint(orig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalEndpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != orig {
		t.Fatalf("round trip = %+v, want %+v", got, orig)
	}
}

func TestStartPayloadRoundTrip(t *testing.T) {
	orig := startPayload{
		SessionID:     "session/a/b",
		PlanID:        "birthdaypunch/direct",
		StartAtUnixMs: 1_700_000_000_000,
		SentAt:        time.Unix(1000, 0).UTC(),
	}
	data, err := marshalStart(orig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalStart(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != orig {
		t.Fatalf("round trip = %+v, want %+v", got, orig)
	}
}

func TestIsMessage(t *testing.T) {
	msg := NewMessage(MessageTypeEndpoint, []byte("{}"), time.Now())
	if !IsMessage(msg) {
		t.Fatal("IsMessage = false for own message")
	}
	foreign := solver.Message{Kind: solver.MessageKindStrategy, Namespace: "signalrelay"}
	if IsMessage(foreign) {
		t.Fatal("IsMessage = true for foreign namespace")
	}
}
