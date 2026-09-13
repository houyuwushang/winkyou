package client

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// This registry serializes ordinary runtime-state I/O only for the same file.
// It never holds the registry mutex across file I/O or while waiting on an
// entry. References count holders AND waiters, preventing premature eviction.
// It is not a security ledger or the CLI's cross-process RuntimeStateLock.
type runtimeFileLock struct {
	mu   sync.RWMutex
	refs int
}

var runtimeFileLocks = struct {
	sync.Mutex
	entries map[string]*runtimeFileLock
}{entries: make(map[string]*runtimeFileLock)}

func runtimeFileLockKey(path string) (string, error) {
	key, err := filepath.Abs(RuntimeStatePath(path))
	if err != nil {
		return "", err
	}
	key = filepath.Clean(key)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	// Lexical aliases only: resolving symlinks/junctions would require I/O.
	return key, nil
}

func lockRuntimeFile(path string, read bool) (unlock func(), err error) {
	key, err := runtimeFileLockKey(path)
	if err != nil {
		return nil, err
	}
	runtimeFileLocks.Lock()
	entry := runtimeFileLocks.entries[key]
	if entry == nil {
		entry = &runtimeFileLock{}
		runtimeFileLocks.entries[key] = entry
	}
	entry.refs++
	runtimeFileLocks.Unlock()
	if read {
		entry.mu.RLock()
	} else {
		entry.mu.Lock()
	}
	return func() {
		if read {
			entry.mu.RUnlock()
		} else {
			entry.mu.Unlock()
		}
		runtimeFileLocks.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(runtimeFileLocks.entries, key)
		}
		runtimeFileLocks.Unlock()
	}, nil
}
