//go:build !linux && natlab

package natlab

import (
	"errors"
	"testing"
)

func TestLinuxNATMatrix(t *testing.T) {
	if !errors.Is(RunInNamespace("unused", func() error { return nil }), ErrNamespacesUnsupported) {
		t.Fatal("non-Linux namespace adapter did not report unsupported")
	}
	t.Skip("netns NAT lab requires Linux and root")
}
