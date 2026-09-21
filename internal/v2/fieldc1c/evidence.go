//go:build fieldc1c

package fieldc1c

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Evidence owns a durable one-shot claim and a private append-only record.
// It never removes a claim, including after a preflight or pre-BURN failure.
type Evidence struct {
	mu   sync.Mutex
	file *os.File
	hash *digestWriter
}
type digestWriter struct{ bytes []byte }

func (instance Instance) ClaimEvidence() (*Evidence, error) {
	if instance.Check(time.Now()) != nil {
		return nil, ErrInvalid
	}
	path, err := instance.EvidenceDirectory()
	if err != nil {
		return nil, ErrInvalid
	}
	parent := filepath.Dir(path)
	if err := os.Mkdir(parent, 0o700); err != nil && !os.IsExist(err) {
		return nil, ErrInvalid
	}
	if safeParents(parent) != nil {
		return nil, ErrInvalid
	}
	// Mkdir is the atomic claim. A pre-existing directory is never repaired.
	if os.Mkdir(path, 0o700) != nil {
		return nil, ErrInvalid
	}
	if syncDirectory(parent) != nil {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(filepath.Join(path, "endpoint.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, ErrInvalid
	}
	if syncDirectory(path) != nil {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return &Evidence{file: file, hash: &digestWriter{}}, nil
}

func (evidence *Evidence) Append(value any) error {
	if evidence == nil {
		return ErrInvalid
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 256*1024 {
		return ErrInvalid
	}
	defer clear(data)
	data = append(data, '\n')
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	if evidence.file == nil || len(evidence.hash.bytes)+len(data) > 1024*1024 {
		return ErrInvalid
	}
	if _, err := evidence.file.Write(data); err != nil {
		return ErrInvalid
	}
	evidence.hash.bytes = append(evidence.hash.bytes, data...)
	return nil
}

func (evidence *Evidence) Seal() (string, error) {
	if evidence == nil {
		return "", ErrInvalid
	}
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	if evidence.file == nil {
		return "", ErrInvalid
	}
	err := evidence.file.Sync()
	closeErr := evidence.file.Close()
	evidence.file = nil
	digest := sha256.Sum256(evidence.hash.bytes)
	clear(evidence.hash.bytes)
	if err != nil || closeErr != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(digest[:]), nil
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrInvalid
	}
	defer file.Close()
	if file.Sync() != nil {
		return ErrInvalid
	}
	return nil
}
