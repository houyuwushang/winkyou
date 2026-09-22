//go:build fieldc1c

package sshassembly

import (
	"net/netip"
	"time"

	"winkyou/internal/v2/fieldc1c"
)

type fieldScope struct {
	instance fieldc1c.Instance
}

// NewFieldAuthority consumes only an opaque, locally validated authorization.
// No address, scope callback, clock, or raw configuration can issue this token.
func NewFieldAuthority(instance fieldc1c.Instance) (SSHEndpointAuthority, error) {
	endpoint, err := instance.SSHEndpoint()
	if err != nil || canonicalEndpoint(endpoint) != endpoint || instance.Check(time.Now()) != nil {
		return SSHEndpointAuthority{}, ErrAuthorityInvalid
	}
	return SSHEndpointAuthority{endpoint: endpoint, scope: fieldScope{instance: instance}}, nil
}

func (scope fieldScope) validateEndpoint(endpoint netip.AddrPort) error {
	expected, err := scope.instance.SSHEndpoint()
	if err != nil || expected != endpoint || scope.instance.Check(time.Now()) != nil {
		return ErrAuthorityInvalid
	}
	return nil
}

func validateAuthorityFiles(authority SSHEndpointAuthority, identity, pin string) error {
	scope, isField := authority.scope.(fieldScope)
	if !isField {
		return nil // Existing loopback and netns scopes retain their old contract.
	}
	expectedPin, expectedIdentity, err := scope.instance.SSHFiles()
	if err != nil || expectedPin != pin || expectedIdentity != identity {
		return ErrAuthorityInvalid
	}
	return nil
}
