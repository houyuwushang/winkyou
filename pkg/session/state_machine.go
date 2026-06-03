package session

import (
	"fmt"
	"sync"
)

type StateMachine struct {
	mu    sync.RWMutex
	state State
}

var validStateTransitions = map[State]map[State]struct{}{
	StateNew: {
		StateCapabilityExchange: {},
		StateFailed:             {},
		StateClosed:             {},
	},
	StateCapabilityExchange: {
		StateSelecting: {},
		StateFailed:    {},
		StateClosed:    {},
	},
	StateSelecting: {
		StateProbing:  {},
		StatePlanning: {},
		StateFailed:   {},
		StateClosed:   {},
	},
	StateProbing: {
		StatePlanning: {},
		StateFailed:   {},
		StateClosed:   {},
	},
	StatePlanning: {
		StateExecuting: {},
		StateFailed:    {},
		StateClosed:    {},
	},
	StateExecuting: {
		StateExecuting: {},
		StateBinding:   {},
		StateFailed:    {},
		StateClosed:    {},
	},
	StateBinding: {
		StateBound:  {},
		StateFailed: {},
		StateClosed: {},
	},
	StateBound: {
		StateFailed: {},
		StateClosed: {},
	},
	StateFailed: {
		StateCapabilityExchange: {},
		StateClosed:             {},
	},
	StateClosed: {
		StateClosed: {},
	},
}

type invalidStateTransitionError struct {
	From State
	To   State
}

func (e invalidStateTransitionError) Error() string {
	return fmt.Sprintf("session: invalid state transition %q -> %q", e.From, e.To)
}

func NewStateMachine(initial State) *StateMachine {
	return &StateMachine{state: initial}
}

func (m *StateMachine) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *StateMachine) Transition(next State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !canTransition(m.state, next) {
		return invalidStateTransitionError{From: m.state, To: next}
	}
	m.state = next
	return nil
}

func canTransition(from, to State) bool {
	nextStates, ok := validStateTransitions[from]
	if !ok {
		return false
	}
	_, ok = nextStates[to]
	return ok
}
