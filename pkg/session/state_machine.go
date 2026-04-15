package session

import "sync"

type StateMachine struct {
	mu    sync.RWMutex
	state State
}

func NewStateMachine(initial State) *StateMachine {
	return &StateMachine{state: initial}
}

func (m *StateMachine) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *StateMachine) Transition(next State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = next
}
