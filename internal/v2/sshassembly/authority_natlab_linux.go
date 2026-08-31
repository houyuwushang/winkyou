//go:build linux && natlab

package sshassembly

import (
	"errors"
	"net/netip"
	"os"
	"regexp"
)

var natlabNamespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type NATLabSide uint8

const (
	NATLabLeft NATLabSide = iota + 1
	NATLabRight
)

var (
	natlabLeftEndpoint  = netip.MustParseAddrPort("203.0.113.2:22")
	natlabRightEndpoint = netip.MustParseAddrPort("198.51.100.1:22")
)

type natlabAuthority struct {
	namespace string
	endpoint  netip.AddrPort
}

// NewNATLabAuthority is absent from ordinary builds. It accepts no endpoint:
// the target is fixed by the repository TEST-NET topology and the constructor
// proves that the caller is already inside the named network namespace.
func NewNATLabAuthority(namespace string, side NATLabSide) (SSHEndpointAuthority, error) {
	if validateNATLabNamespace(namespace) != nil {
		return nil, ErrAuthorityInvalid
	}
	endpoint := natlabRightEndpoint
	if side == NATLabRight {
		endpoint = natlabLeftEndpoint
	} else if side != NATLabLeft {
		return nil, ErrAuthorityInvalid
	}
	return natlabAuthority{namespace: namespace, endpoint: endpoint}, nil
}

func (authority natlabAuthority) Endpoint() netip.AddrPort { return authority.endpoint }
func (natlabAuthority) sshEndpointAuthority()              {}
func (authority natlabAuthority) validate() error {
	if validateNATLabNamespace(authority.namespace) != nil ||
		(authority.endpoint != natlabLeftEndpoint && authority.endpoint != natlabRightEndpoint) {
		return ErrAuthorityInvalid
	}
	return nil
}

func validateNATLabNamespace(namespace string) error {
	if !natlabNamespacePattern.MatchString(namespace) {
		return ErrAuthorityInvalid
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return errors.Join(ErrAuthorityInvalid, err)
	}
	expected, err := os.Stat("/var/run/netns/" + namespace)
	if err != nil {
		return errors.Join(ErrAuthorityInvalid, err)
	}
	if !os.SameFile(current, expected) {
		return ErrAuthorityInvalid
	}
	return nil
}
