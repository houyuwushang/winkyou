package sshassembly

import (
	"errors"
	"net/netip"
)

var (
	ErrAuthorityInvalid = errors.New("sshassembly: endpoint authority is invalid")
	ErrProfileInvalid   = errors.New("sshassembly: fixed SSH profile is invalid")
	ErrTransport        = errors.New("sshassembly: SSH transport is unavailable")
	ErrChildTerminated  = errors.New("sshassembly: SSH child terminated")
	ErrBudgetExceeded   = errors.New("sshassembly: SSH budget exceeded")
	ErrHostIdentity     = errors.New("sshassembly: SSH host identity rejected")
	ErrAssemblyClosed   = errors.New("sshassembly: stream is closed")
	ErrDeadline         = errors.New("sshassembly: deadline reached")
)

// SSHEndpointAuthority is an opaque, immutable, single-endpoint value. The zero
// value is invalid. External packages may copy issued values, but cannot supply
// a wrapper that overrides endpoint extraction or synthesize a valid scope.
type SSHEndpointAuthority struct {
	endpoint netip.AddrPort
	scope    endpointScope
}

// A scope can only validate the token's endpoint, never supply another address.
// Implementations and construction remain private to the issuing package.
type endpointScope interface {
	validateEndpoint(netip.AddrPort) error
}

type loopbackScope struct{}

// NewLoopbackAuthority is the only ordinary-build authority constructor.
func NewLoopbackAuthority(endpoint netip.AddrPort) (SSHEndpointAuthority, error) {
	endpoint = canonicalEndpoint(endpoint)
	if !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		return SSHEndpointAuthority{}, ErrAuthorityInvalid
	}
	return SSHEndpointAuthority{endpoint: endpoint, scope: loopbackScope{}}, nil
}

// Endpoint is for request equality checks only; it does not validate authority.
// Every process-boundary consumer uses validatedEndpoint on the concrete value.
func (authority SSHEndpointAuthority) Endpoint() netip.AddrPort { return authority.endpoint }

// IsZero distinguishes absent authority in the responder path. It does not
// authorize a nonzero token; bind and spawn must still revalidate its scope.
func (authority SSHEndpointAuthority) IsZero() bool {
	return authority.endpoint == (netip.AddrPort{}) && authority.scope == nil
}

func (authority SSHEndpointAuthority) validatedEndpoint() (netip.AddrPort, error) {
	endpoint := canonicalEndpoint(authority.endpoint)
	if !endpoint.IsValid() || endpoint != authority.endpoint || authority.scope == nil || authority.scope.validateEndpoint(endpoint) != nil {
		return netip.AddrPort{}, ErrAuthorityInvalid
	}
	return endpoint, nil
}

func (loopbackScope) validateEndpoint(endpoint netip.AddrPort) error {
	if !endpoint.Addr().IsLoopback() {
		return ErrAuthorityInvalid
	}
	return nil
}

func canonicalEndpoint(endpoint netip.AddrPort) netip.AddrPort {
	if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}
