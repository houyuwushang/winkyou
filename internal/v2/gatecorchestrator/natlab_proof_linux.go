//go:build linux && natlab && c1bproof

package gatecorchestrator

import (
	"context"
	"io"
	"net/netip"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

// NATLabProofOptions grants no raw factory, owner, address, or resource
// override. The existing sealed factories verify the current named namespace
// and the fixed TEST-NET topology before any product operation. Machine scope,
// durable slot/ledger and the real OpenSSH process runner remain unchanged.
// NewInterface is solely for a TUN owned by this isolated harness.
type NATLabProofOptions struct {
	Namespace    string
	Side         probeio.GateB2NATLabSide
	SSHSide      sshassembly.NATLabSide
	Observers    [4]netip.AddrPort
	NewInterface func(string, int) (netif.MemoryTestInterface, error)
	Progress     ProgressReporter
}

func RunNATLabInitiator(ctx context.Context, entry InitiatorOptions, proof NATLabProofOptions) (Result, error) {
	deps, err := natlabProofDependencies(proof)
	if err != nil {
		return Result{}, ErrPeerUnauthorized
	}
	return runInitiator(ctx, entry, deps)
}

func RunNATLabResponder(ctx context.Context, input io.Reader, output io.Writer, entry ResponderOptions, proof NATLabProofOptions) (Result, error) {
	deps, err := natlabProofDependencies(proof)
	if err != nil {
		return Result{}, ErrPeerUnauthorized
	}
	return runResponderStdio(ctx, input, output, entry, deps)
}

func natlabProofDependencies(proof NATLabProofOptions) (dependencies, error) {
	topology := hardnatobserve.Topology{Primary: proof.Observers[0], Other: proof.Observers[3]}
	endpoints, err := topology.Endpoints()
	if err != nil || endpoints != proof.Observers {
		return dependencies{}, ErrPeerUnauthorized
	}
	factory, err := probeio.NewGateB2NATLabFactory(proof.Namespace, proof.Side, endpoints)
	if err != nil {
		return dependencies{}, err
	}
	hardFactory, err := probeio.NewGateB3NATLabFactory(proof.Namespace, proof.Side, endpoints)
	if err != nil {
		return dependencies{}, err
	}
	deps := defaultDependencies()
	deps.newSSHAuthority = func(endpoint netip.AddrPort) (sshassembly.SSHEndpointAuthority, error) {
		if endpoint.Addr().IsLoopback() {
			return sshassembly.NewLoopbackAuthority(endpoint)
		}
		authority, err := sshassembly.NewNATLabAuthority(proof.Namespace, proof.SSHSide)
		if err != nil || authority.Endpoint() != endpoint {
			return nil, ErrPeerUnauthorized
		}
		return authority, nil
	}
	deps.configureGateB = func(configuration *gateb.Config) {
		// This consumes the already parsed product artifact's frozen profile;
		// the harness cannot select a different profile or modify its budget.
		if configuration.PreparedArtifact.GateBPlannerProfile() == hardnatplan.ProfileHardBirthday {
			configuration.HardNATLabFactory = hardFactory
		} else {
			configuration.NATLabFactory = factory
		}
	}
	if proof.NewInterface != nil {
		deps.newInterface = proof.NewInterface
		deps.newTunnel = tunnel.NewGateCNATLabWireGuard
	}
	return deps, nil
}
