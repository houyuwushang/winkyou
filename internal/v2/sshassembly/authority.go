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

// SSHEndpointAuthority is a value-sealed, single-endpoint capability. External
// packages can compare the endpoint but cannot implement or synthesize the
// authority marker.
type SSHEndpointAuthority interface {
	Endpoint() netip.AddrPort
	validate() error
	sshEndpointAuthority()
}

type loopbackAuthority struct{ endpoint netip.AddrPort }

// NewLoopbackAuthority is the only ordinary-build authority constructor.
func NewLoopbackAuthority(endpoint netip.AddrPort) (SSHEndpointAuthority, error) {
	endpoint = canonicalEndpoint(endpoint)
	if !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		return nil, ErrAuthorityInvalid
	}
	return loopbackAuthority{endpoint: endpoint}, nil
}

func (authority loopbackAuthority) Endpoint() netip.AddrPort { return authority.endpoint }
func (loopbackAuthority) sshEndpointAuthority()              {}
func (authority loopbackAuthority) validate() error {
	endpoint := canonicalEndpoint(authority.endpoint)
	if !endpoint.IsValid() || endpoint != authority.endpoint || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
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
