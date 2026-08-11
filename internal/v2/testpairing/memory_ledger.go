package testpairing

import (
	"sync"
	"time"
)

// BurnRecord is deliberately secret-free. The in-memory simulator omits the
// durable context digest and corruption semantics required by the mini-spec.
type BurnRecord struct {
	CredentialID string
	AttemptID    string
	LocalRole    Role
	LocalScope   GovernorScope
	BurnedAt     time.Time
	ExpiresAt    time.Time
	Reason       TerminalReason
}

// ReplayLedger is injected so the simulation can prove fail-closed one-use
// behavior without creating a filesystem format. It is not the production
// durable-ledger contract.
type ReplayLedger interface {
	Burn(BurnRecord) error
	Finish(credentialID string, reason TerminalReason) error
}

// MemoryLedger is a deterministic, process-local simulation ledger. It is not
// restart-safe and must not be presented as replay protection evidence.
type MemoryLedger struct {
	mu      sync.Mutex
	records map[string]BurnRecord
}

func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{records: make(map[string]BurnRecord)}
}

func (l *MemoryLedger) Burn(record BurnRecord) error {
	if l == nil {
		return ErrInvalidContext
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.records[record.CredentialID]; exists {
		return ErrCredentialUsed
	}
	l.records[record.CredentialID] = record
	return nil
}

func (l *MemoryLedger) Finish(credentialID string, reason TerminalReason) error {
	if l == nil {
		return ErrInvalidContext
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, exists := l.records[credentialID]
	if !exists {
		return ErrInvalidContext
	}
	if record.Reason == TerminalNone {
		record.Reason = reason
		l.records[credentialID] = record
	}
	return nil
}

func (l *MemoryLedger) Record(credentialID string) (BurnRecord, bool) {
	if l == nil {
		return BurnRecord{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, exists := l.records[credentialID]
	return record, exists
}
