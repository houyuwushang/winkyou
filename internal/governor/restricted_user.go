package governor

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RestrictedUserGovernor is the deliberately smaller capability exposed by
// the explicit user-acknowledged scope. It cannot be passed where a machine
// *Governor is required and does not expose generic operation selection.
type RestrictedUserGovernor struct {
	governor *Governor
}

// RestrictedUserPeerLease allows only the two reviewed Phase 1a operations.
type RestrictedUserPeerLease struct {
	peer *PeerLease
}

// RestrictedAttemptRequest omits operation and heavyweight controls so a
// caller cannot turn this capability into runtime, recovery, mapping,
// prediction, or birthday-punch authority.
type RestrictedAttemptRequest struct {
	ID        string
	Resources Resources
	Duration  time.Duration
}

// NewRestrictedUserGovernor constructs the independent, lower-ceiling user
// authority. requested may only lower the compiled limits.
func NewRestrictedUserGovernor(owner *Owner, requested *Limits) (*RestrictedUserGovernor, error) {
	governor, err := newGovernor(owner, ProfilePhase1UserAcknowledged, requested)
	if err != nil {
		return nil, err
	}
	return &RestrictedUserGovernor{governor: governor}, nil
}

// AcquireRestrictedUserGovernor prepares and owns the canonical per-user
// namespace only after the caller has received an explicit local user opt-in.
// A ready machine namespace takes precedence and cannot be bypassed this way.
func AcquireRestrictedUserGovernor(buildVersion string) (*RestrictedUserGovernor, error) {
	return acquireRestrictedUserGovernor(buildVersion, restrictedUserDependencies{
		inspectMachine: InspectMachineNamespace,
		prepareUser:    prepareUserAcknowledgedNamespace,
		acquireOwner:   AcquirePreparedNamespace,
	})
}

type restrictedUserDependencies struct {
	inspectMachine func() NamespaceStatus
	prepareUser    func() (NamespaceStatus, error)
	acquireOwner   func(string, Scope, string) (*Owner, error)
}

func acquireRestrictedUserGovernor(buildVersion string, dependencies restrictedUserDependencies) (*RestrictedUserGovernor, error) {
	machine := dependencies.inspectMachine()
	if machine.Ready {
		return nil, fmt.Errorf("%w: %s", ErrUserScopeNotNeeded, machine.Path)
	}
	status, err := dependencies.prepareUser()
	if err != nil {
		return nil, err
	}
	owner, err := dependencies.acquireOwner(status.Path, ScopeUserAcknowledged, buildVersion)
	if err != nil {
		return nil, err
	}
	restricted, err := NewRestrictedUserGovernor(owner, nil)
	if err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	if machine = dependencies.inspectMachine(); machine.Ready {
		return nil, errors.Join(fmt.Errorf("%w: %s", ErrUserScopeNotNeeded, machine.Path), restricted.Close())
	}
	return restricted, nil
}

func (g *RestrictedUserGovernor) AcquirePeer(peerID string) (*RestrictedUserPeerLease, error) {
	if g == nil || g.governor == nil {
		return nil, ErrGovernorClosed
	}
	peer, err := g.governor.AcquirePeer(peerID)
	if err != nil {
		return nil, err
	}
	return &RestrictedUserPeerLease{peer: peer}, nil
}

func (g *RestrictedUserGovernor) Snapshot() Snapshot {
	if g == nil || g.governor == nil {
		return Snapshot{Closed: true}
	}
	return g.governor.Snapshot()
}

func (g *RestrictedUserGovernor) Close() error {
	if g == nil || g.governor == nil {
		return nil
	}
	return g.governor.Close()
}

func (p *RestrictedUserPeerLease) PeerID() string {
	if p == nil || p.peer == nil {
		return ""
	}
	return p.peer.PeerID()
}

func (p *RestrictedUserPeerLease) AcquireDiagnosticAttempt(ctx context.Context, request RestrictedAttemptRequest) (*AttemptLease, error) {
	return p.acquireAttempt(ctx, OperationDiagnose, request)
}

func (p *RestrictedUserPeerLease) AcquireConnectTestAttempt(ctx context.Context, request RestrictedAttemptRequest) (*AttemptLease, error) {
	return p.acquireAttempt(ctx, OperationConnectTest, request)
}

func (p *RestrictedUserPeerLease) acquireAttempt(ctx context.Context, operation Operation, request RestrictedAttemptRequest) (*AttemptLease, error) {
	if p == nil || p.peer == nil {
		return nil, ErrLeaseClosed
	}
	return p.peer.AcquireAttempt(ctx, AttemptRequest{
		ID:        request.ID,
		Operation: operation,
		Cost: AttemptCost{
			Resources: request.Resources,
			Duration:  request.Duration,
		},
	})
}

func (p *RestrictedUserPeerLease) Close() error {
	if p == nil || p.peer == nil {
		return nil
	}
	return p.peer.Close()
}
