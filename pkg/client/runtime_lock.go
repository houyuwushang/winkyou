package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrRuntimeStateLocked means another wink process owns the lifecycle lock for
// this runtime-state path. The lock is held for the full wink up lifetime and
// is released automatically by the operating system if the process exits.
var ErrRuntimeStateLocked = errors.New("client runtime state is locked")

type RuntimeStateLock struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

// AcquireRuntimeStateLock obtains the stable sidecar lock associated with a
// runtime-state path. The sidecar is deliberately never removed: deleting a
// lock file can split contenders across different file identities.
func AcquireRuntimeStateLock(path string) (*RuntimeStateLock, error) {
	lockPath := RuntimeStatePath(path) + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create runtime lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runtime lock: %w", err)
	}
	if err := lockRuntimeStateFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &RuntimeStateLock{file: file}, nil
}

func (l *RuntimeStateLock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file == nil {
		return nil
	}
	unlockErr := unlockRuntimeStateFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}
