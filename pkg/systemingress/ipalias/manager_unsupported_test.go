//go:build !windows

package ipalias

import (
	"errors"
	"testing"
)

func TestNewLoopbackManagerUnsupported(t *testing.T) {
	manager, err := NewLoopbackManager()
	if manager != nil {
		t.Fatalf("NewLoopbackManager() manager = %T, want nil", manager)
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewLoopbackManager() error = %v, want ErrUnsupported", err)
	}
}
