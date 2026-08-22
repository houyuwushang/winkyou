package punchproto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestMachineAcceptsBothCrossedPunchSequences(t *testing.T) {
	tests := []struct {
		name     string
		received []MessageType
		replies  []MessageType
	}{
		{name: "crossed syn", received: []MessageType{MessageSYN, MessageSYNACK}, replies: []MessageType{MessageSYNACK}},
		{name: "peer syn ack first", received: []MessageType{MessageSYNACK}, replies: []MessageType{MessageACK}},
		{name: "peer ack final", received: []MessageType{MessageSYN, MessageACK}, replies: []MessageType{MessageSYNACK}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := NewMachine()
			first, err := machine.Start()
			if err != nil || first != MessageSYN {
				t.Fatalf("Start() = %q, %v", first, err)
			}
			var replies []MessageType
			for index, received := range test.received {
				transition, err := machine.Receive(received)
				if err != nil {
					t.Fatalf("Receive(%q): %v", received, err)
				}
				if transition.Reply.Valid() {
					replies = append(replies, transition.Reply)
				}
				if transition.Complete != (index == len(test.received)-1) {
					t.Fatalf("step %d complete = %t", index, transition.Complete)
				}
			}
			if !equalMessages(replies, test.replies) {
				t.Fatalf("replies = %v, want %v", replies, test.replies)
			}
			if _, err := machine.Receive(MessageACK); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("post-complete receive error = %v", err)
			}
		})
	}
}

func TestMachineRejectsInvalidOrderWithoutAdvancing(t *testing.T) {
	machine := NewMachine()
	if _, err := machine.Receive(MessageSYN); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("receive before start error = %v", err)
	}
	if _, err := machine.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.Receive(MessageACK); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ACK as first message error = %v", err)
	}
	transition, err := machine.Receive(MessageSYNACK)
	if err != nil || !transition.Complete || transition.Reply != MessageACK {
		t.Fatalf("valid transition after rejection = %+v, %v", transition, err)
	}
}

func TestPlainPacketRoundTripAndContextBinding(t *testing.T) {
	attemptID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	packet, err := EncodePlainPacket(attemptID, 1, RoleInitiator, MessageSYN)
	if err != nil {
		t.Fatal(err)
	}
	message, err := OpenPlainPacket(packet, attemptID, 1, RoleInitiator)
	if err != nil || message != MessageSYN {
		t.Fatalf("OpenPlainPacket() = %q, %v", message, err)
	}
	if _, err := OpenPlainPacket(packet, attemptID, 1, RoleResponder); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("role mismatch error = %v", err)
	}
	packet[0] ^= 1
	if _, err := OpenPlainPacket(packet, attemptID, 1, RoleInitiator); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("mutation error = %v", err)
	}
}

func equalMessages(left, right []MessageType) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
