package session

import (
	"errors"
	"testing"

	rproto "winkyou/pkg/rendezvous/proto"
)

func TestStateMachineRejectsInvalidTransitions(t *testing.T) {
	tests := []struct {
		name string
		from State
		to   State
	}{
		{name: "bound_to_new", from: StateBound, to: StateNew},
		{name: "closed_to_executing", from: StateClosed, to: StateExecuting},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(tt.from)
			err := sm.Transition(tt.to)
			if err == nil {
				t.Fatalf("Transition(%q -> %q) error = nil, want invalid transition", tt.from, tt.to)
			}
			var invalid invalidStateTransitionError
			if !errors.As(err, &invalid) {
				t.Fatalf("Transition(%q -> %q) error = %T, want invalidStateTransitionError", tt.from, tt.to, err)
			}
			if invalid.From != tt.from || invalid.To != tt.to {
				t.Fatalf("invalid transition = %#v, want from=%q to=%q", invalid, tt.from, tt.to)
			}
			if got := sm.State(); got != tt.from {
				t.Fatalf("State() = %q, want original state %q", got, tt.from)
			}
		})
	}
}

func TestSessionTransitionReportsInvalidTransition(t *testing.T) {
	var reported error
	s, err := New(Config{
		SessionID:   "session/node-a/node-b",
		LocalNodeID: "node-a",
		PeerID:      "node-b",
		Initiator:   true,
		Resolver:    &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}},
		Sender:      &fakeSender{},
		Hooks: Hooks{
			OnError: func(err error) {
				reported = err
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	s.sm = NewStateMachine(StateBinding)
	s.metaMu.Lock()
	s.meta.State = StateBinding
	s.metaMu.Unlock()
	s.transition(StateNew)

	if reported == nil {
		t.Fatal("OnError was not called for invalid transition")
	}
	var invalid invalidStateTransitionError
	if !errors.As(reported, &invalid) {
		t.Fatalf("OnError error = %T, want invalidStateTransitionError", reported)
	}
	if invalid.From != StateBinding || invalid.To != StateNew {
		t.Fatalf("invalid transition = %#v, want binding -> new", invalid)
	}
	if got := s.State(); got != StateBinding {
		t.Fatalf("State() = %q, want %q", got, StateBinding)
	}
	if got := s.Snapshot().State; got != StateBinding {
		t.Fatalf("Snapshot().State = %q, want %q", got, StateBinding)
	}
}
