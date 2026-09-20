//go:build linux && natlab

package sshassembly

import (
	"errors"
	"testing"
)

func TestNATLabAuthorityRejectsUnprovenNamespace(t *testing.T) {
	for _, namespace := range []string{"", "..", "not/a/namespace", "authority-absent-fixture"} {
		token, err := NewNATLabAuthority(namespace, NATLabLeft)
		if !errors.Is(err, ErrAuthorityInvalid) || !token.IsZero() {
			t.Fatal("unproven namespace returned an authority")
		}
	}
	// Even a package-internal synthetic token must revalidate the namespace on
	// every extraction. The required C1b netns job covers valid issued tokens.
	token := SSHEndpointAuthority{endpoint: natlabRightEndpoint, scope: natlabScope{namespace: ".."}}
	if endpoint, err := token.validatedEndpoint(); !errors.Is(err, ErrAuthorityInvalid) || endpoint.IsValid() {
		t.Fatal("unproven namespace returned a validated endpoint")
	}
}
