package recoverycard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrWrongNode reports that a card belongs to a node other than the store's
// configured node. It is suitable for errors.Is.
var ErrWrongNode = errors.New("recoverycard: wrong node")

// Store serializes reads, writes, and read-modify-write updates to one recovery
// card. It is safe for concurrent use by goroutines in one process.
type Store struct {
	mu     sync.Mutex
	path   string
	nodeID string
}

// NewStore creates a store for one node. It does not access the filesystem.
func NewStore(path, nodeID string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("recoverycard: store path is required")
	}
	if err := validateNodeID("store node_id", nodeID); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Clean(path), nodeID: nodeID}, nil
}

// Load returns the current card. A missing file is not an error and returns a
// zero Card. Corrupt, unsupported, and wrong-node files are rejected.
func (s *Store) Load() (Card, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// Save validates and atomically replaces the current card.
func (s *Store) Save(card Card) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(card)
}

// Update performs a serialized load/modify/validate/save cycle. When the card
// does not exist, fn receives a card with Version and NodeID pre-populated. The
// callback must not call another method on the same Store.
func (s *Store) Update(fn func(*Card) error) error {
	if fn == nil {
		return errors.New("recoverycard: update callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	card, err := s.loadLocked()
	if err != nil {
		return err
	}
	if card.Version == 0 {
		card.Version = CurrentVersion
		card.NodeID = s.nodeID
	}
	if err := fn(&card); err != nil {
		return err
	}
	return s.saveLocked(card)
}

func (s *Store) loadLocked() (Card, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Card{}, nil
		}
		return Card{}, fmt.Errorf("recoverycard: read %q: %w", s.path, err)
	}
	card, err := decodeCard(data)
	if err != nil {
		return Card{}, fmt.Errorf("recoverycard: load %q: %w", s.path, err)
	}
	if card.NodeID != s.nodeID {
		return Card{}, fmt.Errorf("%w: file has %q, store expects %q", ErrWrongNode, card.NodeID, s.nodeID)
	}
	return card, nil
}

func (s *Store) saveLocked(card Card) error {
	if card.NodeID != s.nodeID {
		return fmt.Errorf("%w: card has %q, store expects %q", ErrWrongNode, card.NodeID, s.nodeID)
	}
	if err := card.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(card, "", "  ")
	if err != nil {
		return fmt.Errorf("recoverycard: encode: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("recoverycard: save %q: %w", s.path, err)
	}
	return nil
}

func decodeCard(data []byte) (Card, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var card Card
	if err := decoder.Decode(&card); err != nil {
		return Card{}, fmt.Errorf("decode: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Card{}, errors.New("decode: multiple JSON values")
		}
		return Card{}, fmt.Errorf("decode trailing data: %w", err)
	}
	if err := card.Validate(); err != nil {
		return Card{}, err
	}
	return card, nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if retErr != nil {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := replaceFile(tempPath, path); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}
	if err := syncParentDirectory(dir); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}
