//go:build fieldc1c

package sshassembly

import (
	"testing"
	"winkyou/internal/v2/fieldc1c"
)

func TestFieldSSHRejectsZeroInstance(t *testing.T) {
	token, err := NewFieldAuthority(fieldc1c.Instance{})
	if err != ErrAuthorityInvalid || !token.IsZero() {
		t.Fatal("field scope accepted absent validation")
	}
}
