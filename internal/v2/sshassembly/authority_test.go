package sshassembly

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestAuthorityTokenCanonicalAndZeroBoundaries(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:22", "[::1]:22", "[::ffff:127.0.0.1]:22",
	} {
		input := netip.MustParseAddrPort(address)
		authority, err := NewLoopbackAuthority(input)
		if err != nil || authority.IsZero() {
			t.Fatal("valid loopback token rejected")
		}
		copy := authority
		endpoint, err := copy.validatedEndpoint()
		if err != nil || endpoint != canonicalEndpoint(input) || endpoint != authority.Endpoint() {
			t.Fatal("copied token changed its canonical endpoint")
		}
	}
	for _, address := range []string{
		"127.0.0.1:0", "[::1%fixture]:22", "203.0.113.8:22", "0.0.0.0:22", "[::]:22",
	} {
		authority, err := NewLoopbackAuthority(netip.MustParseAddrPort(address))
		if !errors.Is(err, ErrAuthorityInvalid) || !authority.IsZero() {
			t.Fatal("invalid endpoint returned usable authority")
		}
	}
	for _, authority := range []SSHEndpointAuthority{
		{},
		{endpoint: netip.MustParseAddrPort("127.0.0.1:22")},
		{scope: loopbackScope{}},
		{endpoint: netip.MustParseAddrPort("203.0.113.8:22"), scope: loopbackScope{}},
		{endpoint: netip.MustParseAddrPort("[::ffff:127.0.0.1]:22"), scope: loopbackScope{}},
	} {
		if endpoint, err := authority.validatedEndpoint(); !errors.Is(err, ErrAuthorityInvalid) || endpoint.IsValid() {
			t.Fatal("invalid token returned a validated endpoint")
		}
		if _, err := BindClientConfig(authority, testLocalSSHConfig(t)); !errors.Is(err, ErrProfileInvalid) {
			t.Fatal("invalid token passed bind")
		}
	}
}

func TestAuthorityMismatchOrZeroRejectedBeforeClaimAndSpawn(t *testing.T) {
	for _, mutation := range []string{"zero", "endpoint_mismatch"} {
		t.Run(mutation, func(t *testing.T) {
			config, lease := testAssemblyConfig(t)
			if mutation == "zero" {
				config.Client.authority = SSHEndpointAuthority{}
			} else {
				config.Client.endpoint = netip.MustParseAddrPort("203.0.113.8:22")
			}
			runner := &fakeRunner{behavior: echoChild}
			if _, err := buildArguments(config.Client); !errors.Is(err, ErrProfileInvalid) {
				t.Fatal("invalid authority passed argv construction")
			}
			if _, err := openClient(context.Background(), config, fakeDependencies(runner)); !errors.Is(err, ErrProfileInvalid) {
				t.Fatal("invalid authority passed process preflight")
			}
			if runner.Calls() != 0 || len(lease.claims) != 0 {
				t.Fatal("invalid authority reached claim or spawn")
			}
		})
	}
}

// A test-only revocable scope models namespace identity ceasing to match after
// argv construction. Production scope implementations are not caller-injected.
type invalidatingTestScope struct{ calls int }

func (scope *invalidatingTestScope) validateEndpoint(endpoint netip.AddrPort) error {
	scope.calls++
	if scope.calls == 3 || endpoint != netip.MustParseAddrPort("127.0.0.1:22") {
		return ErrAuthorityInvalid
	}
	return nil
}

func TestAuthorityScopeRevalidatedImmediatelyBeforeSpawn(t *testing.T) {
	config, lease := testAssemblyConfig(t)
	scope := &invalidatingTestScope{}
	config.Client.authority.scope = scope
	runner := &fakeRunner{behavior: echoChild}
	stream, err := openClient(context.Background(), config, fakeDependencies(runner))
	if stream != nil {
		_ = stream.Close()
	}
	if !errors.Is(err, ErrProfileInvalid) || scope.calls != 3 || runner.Calls() != 0 {
		t.Fatal("scope revocation did not stop spawn")
	}
	if len(lease.claims) != 1 || !lease.drain.completed {
		t.Fatal("pre-spawn authority failure did not complete its owned drain")
	}
}
