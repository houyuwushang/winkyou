package probeio

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/pkg/transport"
)

const (
	// GateATestConsumer and GateB2TestConsumer are separately reviewed,
	// disconnected test consumers. Neither authorizes a product data plane.
	GateATestConsumer     = "gate-a-test-consumer/1"
	GateB2TestConsumer    = "gate-b2-test-consumer/1"
	TransportAdoptTimeout = time.Second
)

// TransportLeaseBinding is immutable local authority. No field may be
// supplied by an artifact, remote frame, or strategy result.
type TransportLeaseBinding struct {
	PeerID       string
	AttemptID    string
	Generation   uint64
	PathID       string
	Target       netip.AddrPort
	ConsumerKind string
}

type transportLeaseState uint8

const (
	transportLeaseIssued transportLeaseState = iota
	transportLeaseInactive
	transportLeaseAdopted
	transportLeaseStandby
	transportLeaseChallengePassed
	transportLeaseClosed
)

// TransportLeaseWitness contains only bounded lifecycle counters and no peer,
// attempt, endpoint, process, or path metadata.
type TransportLeaseWitness struct {
	Attached        bool
	Adopted         bool
	Standby         bool
	ChallengePassed bool
	AttemptDetached bool
	PacketsRead     int
	PacketsWritten  int
	DrainRegistered bool
	Drained         bool
	Closed          bool
}

// TransportLease receives exactly one fixed-target PacketTransport and owns
// its lifecycle after handoff. The attempt remains attached until the caller
// has durably recorded FINISH and explicitly calls DetachAfterFinish.
type TransportLease struct {
	mu sync.Mutex

	attempt         AttemptLease
	binding         TransportLeaseBinding
	drain           governor.DrainHandle
	state           transportLeaseState
	transport       transport.PacketTransport
	read            int
	written         int
	attachedSeen    bool
	adoptedSeen     bool
	standbySeen     bool
	challengeSeen   bool
	detached        bool
	drainRegistered bool
	drained         bool
	closeErr        error

	attached   chan struct{}
	closed     chan struct{}
	watchStop  chan struct{}
	watchDone  chan struct{}
	attachOnce sync.Once
	closeOnce  sync.Once
	stopOnce   sync.Once
}

// IssueTransportLease reserves the one reviewed test-consumer handoff. It
// grants no socket or packet I/O and must run before ProbeSocket promotion.
func IssueTransportLease(attempt *governor.AttemptLease, binding TransportLeaseBinding) (*TransportLease, error) {
	if attempt == nil {
		return nil, ErrTransportLease
	}
	return issueTransportLease(attempt, binding)
}

func issueTransportLease(attempt AttemptLease, binding TransportLeaseBinding) (*TransportLease, error) {
	if attempt == nil || !validTransportLeaseBinding(attempt, binding) {
		return nil, ErrTransportBinding
	}
	drainName := "gate-a-transport-lease"
	if binding.ConsumerKind == GateB2TestConsumer {
		drainName = "gate-b2-transport-lease"
	}
	drain, err := attempt.RegisterDrain(drainName)
	if err != nil {
		return nil, errors.Join(ErrTransportLease, err)
	}
	lease := &TransportLease{
		attempt: attempt, binding: binding, drain: drain, state: transportLeaseIssued,
		drainRegistered: true,
		attached:        make(chan struct{}), closed: make(chan struct{}),
		watchStop: make(chan struct{}), watchDone: make(chan struct{}),
	}
	go lease.watchAttempt()
	return lease, nil
}

func validTransportLeaseBinding(attempt AttemptLease, binding TransportLeaseBinding) bool {
	if !validTransportConsumer(binding.ConsumerKind, attempt.Request().Operation) || binding.Generation == 0 ||
		binding.PeerID == "" || binding.AttemptID == "" || binding.PathID == "" ||
		binding.PeerID != attempt.PeerID() || binding.AttemptID != attempt.Request().ID {
		return false
	}
	target, err := canonicalTarget(binding.Target)
	return err == nil && target == binding.Target &&
		validateText("path id", binding.PathID, 256, false) == nil
}

func validTransportConsumer(consumer string, operation governor.Operation) bool {
	return consumer == GateATestConsumer && operation == governor.OperationConnectTest ||
		consumer == GateB2TestConsumer && (operation == governor.OperationPrediction || operation == governor.OperationBirthday)
}

func (lease *TransportLease) checkPromotionBinding(binding TransportLeaseBinding) error {
	if lease == nil {
		return ErrTransportLease
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.state != transportLeaseIssued || lease.detached || lease.binding != binding {
		return ErrTransportBinding
	}
	return nil
}

func (lease *TransportLease) attach(promotion Promotion) error {
	if lease == nil || promotion.Transport == nil {
		return ErrTransportLease
	}
	binding := TransportLeaseBinding{
		PeerID: promotion.PeerID, AttemptID: promotion.AttemptID, Generation: promotion.Generation,
		PathID: lease.binding.PathID, Target: promotion.Target, ConsumerKind: lease.binding.ConsumerKind,
	}
	lease.mu.Lock()
	if lease.state != transportLeaseIssued || lease.detached || lease.binding != binding {
		lease.mu.Unlock()
		return ErrTransportBinding
	}
	lease.transport = promotion.Transport
	lease.state = transportLeaseInactive
	lease.attachedSeen = true
	lease.attachOnce.Do(func() { close(lease.attached) })
	lease.mu.Unlock()
	return nil
}

// Adopt activates the exact fixed-target transport. It waits at most one
// second for PromoteToLease and returns only a lease-owned wrapper.
func (lease *TransportLease) Adopt(ctx context.Context, binding TransportLeaseBinding) (transport.PacketTransport, error) {
	if lease == nil || ctx == nil {
		return nil, ErrTransportLease
	}
	if err := lease.checkAdoptBinding(binding); err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, TransportAdoptTimeout)
	defer cancel()
	select {
	case <-lease.attached:
	case <-lease.closed:
		return nil, ErrTransportLease
	case <-waitCtx.Done():
		_ = lease.Close()
		return nil, errors.Join(ErrTransportLease, waitCtx.Err())
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.binding != binding || lease.state != transportLeaseInactive || lease.transport == nil {
		return nil, ErrTransportBinding
	}
	lease.state = transportLeaseAdopted
	lease.adoptedSeen = true
	return &leaseTransport{lease: lease}, nil
}

func (lease *TransportLease) checkAdoptBinding(binding TransportLeaseBinding) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.binding != binding || lease.state == transportLeaseClosed || lease.detached {
		return ErrTransportBinding
	}
	return nil
}

// MarkStandby is valid only after consumer adoption.
func (lease *TransportLease) MarkStandby() error {
	if lease == nil {
		return ErrTransportLease
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.state != transportLeaseAdopted {
		return ErrTransportInactive
	}
	lease.state = transportLeaseStandby
	lease.standbySeen = true
	return nil
}

// MarkChallengePassed records the final test-only data-plane proof.
func (lease *TransportLease) MarkChallengePassed() error {
	if lease == nil {
		return ErrTransportLease
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.state != transportLeaseStandby {
		return ErrTransportInactive
	}
	lease.state = transportLeaseChallengePassed
	lease.challengeSeen = true
	return nil
}

// DetachAfterFinish releases the attempt-owned drain only after the caller
// has durably appended FINISH. It does not close a successful transport; the
// TransportLease becomes its sole owner across attempt release.
func (lease *TransportLease) DetachAfterFinish() error {
	if lease == nil {
		return ErrTransportLease
	}
	lease.mu.Lock()
	if lease.detached || lease.state != transportLeaseChallengePassed || lease.transport == nil {
		lease.mu.Unlock()
		return ErrTransportInactive
	}
	lease.detached = true
	drain := lease.drain
	lease.drain = nil
	lease.drained = true
	lease.mu.Unlock()
	lease.stopWatcher()
	if drain != nil {
		return drain.Complete()
	}
	return nil
}

func (lease *TransportLease) watchAttempt() {
	defer close(lease.watchDone)
	select {
	case <-lease.attempt.Stopping():
		lease.mu.Lock()
		detached := lease.detached
		lease.mu.Unlock()
		if !detached {
			lease.closeOwned()
		}
	case <-lease.watchStop:
	case <-lease.closed:
	}
}

func (lease *TransportLease) stopWatcher() {
	lease.stopOnce.Do(func() { close(lease.watchStop) })
	<-lease.watchDone
}

func (lease *TransportLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.closeOwned()
	lease.stopWatcher()
	lease.mu.Lock()
	err := lease.closeErr
	lease.mu.Unlock()
	return err
}

func (lease *TransportLease) closeOwned() {
	lease.closeOnce.Do(func() {
		lease.mu.Lock()
		lease.state = transportLeaseClosed
		owned := lease.transport
		lease.transport = nil
		drain := lease.drain
		lease.drain = nil
		lease.drained = true
		lease.mu.Unlock()
		close(lease.closed)
		var closeErr error
		if owned != nil {
			closeErr = owned.Close()
		}
		if drain != nil {
			closeErr = errors.Join(closeErr, drain.Complete())
		}
		lease.mu.Lock()
		lease.closeErr = closeErr
		lease.mu.Unlock()
	})
}

func (lease *TransportLease) Witness() TransportLeaseWitness {
	if lease == nil {
		return TransportLeaseWitness{Closed: true, Drained: true}
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return TransportLeaseWitness{
		Attached: lease.attachedSeen, Adopted: lease.adoptedSeen,
		Standby: lease.standbySeen, ChallengePassed: lease.challengeSeen,
		AttemptDetached: lease.detached, PacketsRead: lease.read, PacketsWritten: lease.written,
		DrainRegistered: lease.drainRegistered, Drained: lease.drained, Closed: lease.state == transportLeaseClosed,
	}
}

type leaseTransport struct{ lease *TransportLease }

func (wrapped *leaseTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	owned, err := wrapped.activeTransport()
	if err != nil {
		return 0, transport.PacketMeta{}, err
	}
	n, meta, err := owned.ReadPacket(ctx, dst)
	if err == nil {
		wrapped.lease.mu.Lock()
		wrapped.lease.read++
		wrapped.lease.mu.Unlock()
	}
	return n, meta, err
}

func (wrapped *leaseTransport) WritePacket(ctx context.Context, packet []byte) error {
	owned, err := wrapped.activeTransport()
	if err != nil {
		return err
	}
	err = owned.WritePacket(ctx, packet)
	if err == nil {
		wrapped.lease.mu.Lock()
		wrapped.lease.written++
		wrapped.lease.mu.Unlock()
	}
	return err
}

func (wrapped *leaseTransport) LocalAddr() net.Addr {
	owned, err := wrapped.activeTransport()
	if err != nil {
		return nil
	}
	return owned.LocalAddr()
}

func (wrapped *leaseTransport) RemoteAddr() net.Addr {
	owned, err := wrapped.activeTransport()
	if err != nil {
		return nil
	}
	return owned.RemoteAddr()
}

func (wrapped *leaseTransport) Close() error {
	if wrapped == nil || wrapped.lease == nil {
		return nil
	}
	return wrapped.lease.Close()
}

func (wrapped *leaseTransport) activeTransport() (transport.PacketTransport, error) {
	if wrapped == nil || wrapped.lease == nil {
		return nil, ErrTransportLease
	}
	wrapped.lease.mu.Lock()
	defer wrapped.lease.mu.Unlock()
	if wrapped.lease.state < transportLeaseAdopted || wrapped.lease.state == transportLeaseClosed || wrapped.lease.transport == nil {
		return nil, ErrTransportInactive
	}
	return wrapped.lease.transport, nil
}
