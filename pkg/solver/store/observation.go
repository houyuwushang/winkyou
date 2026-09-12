package store

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"winkyou/pkg/solver"
)

const observationMemoryLimit = 1000

// ObservationStore provides minimal persistent storage for observations
type ObservationStore struct {
	mu           sync.Mutex
	observations []solver.Observation
	filePath     string
	writer       *observationWriter
	sealed       bool
}

// NewObservationStore creates a new observation store
// If filePath is empty, observations are kept in memory only
func NewObservationStore(filePath string) *ObservationStore {
	return &ObservationStore{
		observations: make([]solver.Observation, 0, 100),
		filePath:     filePath,
	}
}

// Record adds an observation to the store
func (s *ObservationStore) Record(obs solver.Observation) error {
	obs = solver.CloneObservation(obs)
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}

	s.mu.Lock()
	if s.sealed {
		s.mu.Unlock()
		return ErrObservationStoreClosed
	}
	s.observations = append(s.observations, obs)
	// Keep last 1000 observations in memory
	s.observations = trimObservationHistory(s.observations, observationMemoryLimit)
	if s.writer != nil {
		// Record order and admission order share this memory-only critical
		// section. No filesystem operation or worker wait runs under s.mu.
		s.writer.enqueue(obs)
		s.mu.Unlock()
		return nil // memory-visible, NOT a durable-write acknowledgement
	}
	s.mu.Unlock()

	// Persist to file if configured
	if s.filePath != "" {
		return s.appendToFile(obs)
	}
	return nil
}

// List returns all observations in memory
func (s *ObservationStore) List() []solver.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return solver.CloneObservations(s.observations)
}

// Recent returns up to the last limit observations in chronological order.
func (s *ObservationStore) Recent(limit int) []solver.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit >= len(s.observations) {
		return solver.CloneObservations(s.observations)
	}
	start := len(s.observations) - limit
	return solver.CloneObservations(s.observations[start:])
}

// appendToFile appends an observation to the JSONL file
func (s *ObservationStore) appendToFile(obs solver.Observation) error {
	data, err := json.Marshal(obs)
	if err != nil {
		return err
	}
	return s.appendJSONLine(append(data, '\n'))
}

func (s *ObservationStore) appendJSONLine(data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

// Seal rejects future records and discards pending ordinary disk copies. The
// buffered owner finishes its sole active write before removing the file.
func (s *ObservationStore) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
	if s.writer != nil {
		s.writer.seal()
	}
}

// Drain only waits for the original buffered owner. It does not interrupt an
// OS syscall, retry removal, or authorize replacing an undrained owner.
func (s *ObservationStore) Drain(ctx context.Context) error {
	if s.writer == nil {
		return nil
	}
	return s.writer.wait(ctx)
}

// PersistenceStats exposes aggregate counts only, never observation contents
// or raw filesystem errors. Synchronous stores have Buffered=false.
func (s *ObservationStore) PersistenceStats() ObservationPersistenceStats {
	if s.writer == nil {
		return ObservationPersistenceStats{}
	}
	return s.writer.stats()
}

// LoadFromFile loads observations from a JSONL file
func (s *ObservationStore) LoadFromFile() error {
	if s.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse JSONL
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var obs solver.Observation
		if err := json.Unmarshal(line, &obs); err != nil {
			continue // Skip malformed lines
		}
		s.observations = append(s.observations, obs)
	}

	// Keep last 1000
	s.observations = trimObservationHistory(s.observations, observationMemoryLimit)

	return nil
}

func trimObservationHistory(observations []solver.Observation, limit int) []solver.Observation {
	if limit <= 0 || len(observations) <= limit {
		return observations
	}
	retained := make([]solver.Observation, limit)
	copy(retained, observations[len(observations)-limit:])
	return retained
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
