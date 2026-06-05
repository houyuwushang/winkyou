package bootstrap

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMemoryBrokerStoreAndForwardRendezvous(t *testing.T) {
	now := time.Now().UTC()
	broker := NewMemoryBroker(time.Minute)
	broker.now = func() time.Time { return now }

	aDescriptor := validPeerDescriptor(now)
	aDescriptor.NodeID = "node-a"
	if err := broker.PutDescriptor(aDescriptor); err != nil {
		t.Fatalf("PutDescriptor(A) error = %v", err)
	}

	if got, ok := broker.GetDescriptor("node-a"); !ok || got.NodeID != "node-a" {
		t.Fatalf("GetDescriptor(A) = %#v/%t, want node-a", got, ok)
	}

	cDescriptor := validPeerDescriptor(now)
	cDescriptor.NodeID = "node-c"
	if err := broker.PutDescriptor(cDescriptor); err != nil {
		t.Fatalf("PutDescriptor(C) error = %v", err)
	}

	payload, err := json.Marshal(cDescriptor)
	if err != nil {
		t.Fatalf("marshal C descriptor: %v", err)
	}
	env := Envelope{
		Version: EnvelopeVersion,
		From:    "node-c",
		To:      "node-a",
		Type:    "peer_descriptor",
		Seq:     1,
		Payload: payload,
		SentAt:  now,
	}
	if err := broker.QueueEnvelope("node-a", env); err != nil {
		t.Fatalf("QueueEnvelope(C->A) error = %v", err)
	}

	drained := broker.DrainEnvelopes("node-a")
	if len(drained) != 1 || drained[0].From != "node-c" || drained[0].To != "node-a" {
		t.Fatalf("DrainEnvelopes(A) = %#v, want one C->A envelope", drained)
	}
	if again := broker.DrainEnvelopes("node-a"); len(again) != 0 {
		t.Fatalf("second DrainEnvelopes(A) = %#v, want empty", again)
	}
}

func TestMemoryBrokerCleansExpiredDescriptorAndEnvelope(t *testing.T) {
	now := time.Now().UTC()
	broker := NewMemoryBroker(10 * time.Second)
	broker.now = func() time.Time { return now }

	descriptor := validPeerDescriptor(now)
	descriptor.NodeID = "node-a"
	descriptor.ExpiresAt = now.Add(5 * time.Second)
	if err := broker.PutDescriptor(descriptor); err != nil {
		t.Fatalf("PutDescriptor() error = %v", err)
	}
	env := Envelope{
		Version: EnvelopeVersion,
		From:    "node-c",
		To:      "node-a",
		Type:    "candidate_hint",
		Seq:     1,
		Payload: json.RawMessage(`{"strategy":"legacy_ice_udp"}`),
		SentAt:  now,
	}
	if err := broker.QueueEnvelope("node-a", env); err != nil {
		t.Fatalf("QueueEnvelope() error = %v", err)
	}

	now = now.Add(6 * time.Second)
	broker.CleanupExpired()
	if _, ok := broker.GetDescriptor("node-a"); ok {
		t.Fatal("GetDescriptor(node-a) = present, want descriptor expired")
	}
	if drained := broker.DrainEnvelopes("node-a"); len(drained) != 1 {
		t.Fatalf("DrainEnvelopes before envelope TTL = %#v, want one envelope", drained)
	}

	if err := broker.QueueEnvelope("node-a", env); err != nil {
		t.Fatalf("QueueEnvelope(second) error = %v", err)
	}
	now = now.Add(11 * time.Second)
	broker.CleanupExpired()
	if drained := broker.DrainEnvelopes("node-a"); len(drained) != 0 {
		t.Fatalf("DrainEnvelopes after envelope TTL = %#v, want empty", drained)
	}
}

func TestMemoryBrokerRejectsInvalidEnvelopeTarget(t *testing.T) {
	broker := NewMemoryBroker(time.Minute)
	env := Envelope{
		Version: EnvelopeVersion,
		From:    "node-c",
		To:      "node-a",
		Type:    "candidate_hint",
		Seq:     1,
		Payload: json.RawMessage(`{"strategy":"legacy_ice_udp"}`),
		SentAt:  time.Now().UTC(),
	}
	if err := broker.QueueEnvelope("node-b", env); err == nil {
		t.Fatal("QueueEnvelope mismatched target error = nil, want error")
	}
}
