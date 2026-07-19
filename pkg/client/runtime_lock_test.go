package client

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRuntimeStateLockIsExclusiveAndReusable(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	first, err := AcquireRuntimeStateLock(stateKey)
	if err != nil {
		t.Fatalf("acquire first runtime lock: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	second, err := AcquireRuntimeStateLock(stateKey)
	if !errors.Is(err, ErrRuntimeStateLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("acquire second runtime lock error = %v, want locked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first runtime lock: %v", err)
	}

	third, err := AcquireRuntimeStateLock(stateKey)
	if err != nil {
		t.Fatalf("reacquire runtime lock: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("close reacquired runtime lock: %v", err)
	}
}
