//go:build linux && fieldc1c

package c1crouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const evidenceLimit = 16 * 1024 * 1024

type evidence struct {
	mu    sync.Mutex
	file  *os.File
	hash  hash.Hash
	bytes int
}

// Every parent is root-owned and non-writable to other users; a symlink is
// never accepted. This is separate from the endpoint's one-shot claim.
func privateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return ErrOwnership
	}
	for p := path; p != "/"; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return ErrOwnership
		}
	}
	return nil
}

func claimDirectory(path string) error {
	parent := filepath.Dir(path)
	if _, e := os.Lstat(parent); os.IsNotExist(e) {
		if privateDirectory(filepath.Dir(parent)) != nil {
			return ErrOwnership
		}
		if os.Mkdir(parent, 0o700) != nil {
			return ErrOwnership
		}
	}
	if privateDirectory(parent) != nil || os.Mkdir(path, 0o700) != nil {
		return ErrOwnership
	}
	return syncDir(parent)
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return errIO
	}
	defer f.Close()
	if f.Sync() != nil {
		return errIO
	}
	return nil
}
func openEvidence(dir, name string) (*evidence, error) {
	if privateDirectory(dir) != nil {
		return nil, ErrOwnership
	}
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return nil, ErrOwnership
	}
	if syncDir(dir) != nil {
		_ = f.Close()
		return nil, errIO
	}
	return &evidence{file: f, hash: sha256.New()}, nil
}
func (e *evidence) append(v any, durable bool) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > 64*1024 {
		return ErrResource
	}
	defer clear(b)
	b = append(b, '\n')
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil || e.bytes+len(b) > evidenceLimit {
		return ErrResource
	}
	n, err := e.file.Write(b)
	if err != nil || n != len(b) {
		return errIO
	}
	_, _ = e.hash.Write(b)
	e.bytes += len(b)
	if durable && e.file.Sync() != nil {
		return errIO
	}
	return nil
}
func (e *evidence) seal() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		return "", ErrInvalid
	}
	err := e.file.Sync()
	closed := e.file.Close()
	e.file = nil
	if err != nil || closed != nil {
		return "", errIO
	}
	return hex.EncodeToString(e.hash.Sum(nil)), nil
}
