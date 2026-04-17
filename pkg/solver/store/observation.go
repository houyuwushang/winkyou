package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"winkyou/pkg/solver"
)

// ObservationStore provides minimal persistent storage for observations
type ObservationStore struct {
	mu           sync.Mutex
	observations []solver.Observation
	filePath     string
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
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}

	s.mu.Lock()
	s.observations = append(s.observations, obs)
	// Keep last 1000 observations in memory
	if len(s.observations) > 1000 {
		s.observations = s.observations[len(s.observations)-1000:]
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
	out := make([]solver.Observation, len(s.observations))
	copy(out, s.observations)
	return out
}

// Recent returns up to the last limit observations in chronological order.
func (s *ObservationStore) Recent(limit int) []solver.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit >= len(s.observations) {
		out := make([]solver.Observation, len(s.observations))
		copy(out, s.observations)
		return out
	}
	start := len(s.observations) - limit
	out := make([]solver.Observation, len(s.observations[start:]))
	copy(out, s.observations[start:])
	return out
}

// appendToFile appends an observation to the JSONL file
func (s *ObservationStore) appendToFile(obs solver.Observation) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(obs)
	if err != nil {
		return err
	}

	_, err = f.Write(append(data, '\n'))
	return err
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
	if len(s.observations) > 1000 {
		s.observations = s.observations[len(s.observations)-1000:]
	}

	return nil
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
