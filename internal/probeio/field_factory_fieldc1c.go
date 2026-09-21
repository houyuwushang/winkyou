//go:build fieldc1c

package probeio

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

// AllowedTargetScopeFieldSingleAddress cannot be passed to NewUDPFactory.
// Only NewFieldUDPFactory may issue this narrower, instance-bound capability.
const AllowedTargetScopeFieldSingleAddress AllowedTargetScope = 2

type fieldTarget struct {
	slot     uint16
	endpoint netip.AddrPort
}

// FieldUDPFactory is opaque and single-use. Construction performs no I/O;
// opening still requires Controller's single-use permit and the exact lease.
type FieldUDPFactory struct {
	mu              sync.Mutex
	instance        fieldc1c.Instance
	binding         fieldc1c.Binding
	udp             *UDPFactory
	lease           *governor.AttemptLease
	peer            netip.Addr
	observers       [4]netip.AddrPort
	maximum, opened int
	planSet         bool
	targets         map[fieldTarget]struct{}
}

func NewFieldUDPFactory(instance fieldc1c.Instance) (*FieldUDPFactory, error) {
	peer, observers, err := instance.Network()
	if err != nil {
		return nil, ErrInvalidConfig
	}
	binding, err := instance.Binding()
	if err != nil {
		return nil, ErrInvalidConfig
	}
	envelope, err := hardnatbudget.For(hardnatplan.Profile(binding.Profile), hardnatplan.ResourceClass(binding.Resource))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	for _, observer := range observers {
		if observer.Addr() == peer {
			return nil, ErrInvalidTarget
		}
	}
	udp, err := NewUDPFactory(UDPFactoryConfig{LocalAddr: netip.AddrPortFrom(netip.IPv4Unspecified(), 0), AllowedTargetScope: AllowedTargetScopeUnicast})
	if err != nil {
		return nil, err
	}
	return &FieldUDPFactory{instance: instance, binding: binding, udp: udp, peer: peer,
		observers: observers, maximum: envelope.Cost.Resources.Sockets}, nil
}

func (factory *FieldUDPFactory) Check(profile, resource, attempt string, peer netip.Addr, observers [4]netip.AddrPort) error {
	if factory == nil || factory.instance.Check(time.Now()) != nil || profile != factory.binding.Profile ||
		resource != factory.binding.Resource || attempt != factory.binding.ID || peer != factory.peer || observers != factory.observers {
		return ErrInvalidConfig
	}
	return nil
}

// BindAttempt receives authority; it never obtains a governor or a new lease.
func (factory *FieldUDPFactory) BindAttempt(lease *governor.AttemptLease) error {
	if factory == nil || lease == nil || factory.instance.Check(time.Now()) != nil {
		return ErrInvalidConfig
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	request := lease.Request()
	if factory.lease != nil || factory.opened != 0 || request.ID != factory.binding.ID ||
		!hardnatbudget.Exact(hardnatplan.Profile(factory.binding.Profile), hardnatplan.ResourceClass(factory.binding.Resource), request.Operation, request.Cost) {
		return ErrInvalidConfig
	}
	select {
	case <-lease.Stopping():
		return ErrLeaseClosed
	default:
	}
	factory.lease = lease
	return nil
}

type deploymentLeaseKey struct{}

func authorizeAdditionalFactoryScope(ctx context.Context, factory Factory, lease AttemptLease) context.Context {
	if _, ok := factory.(*FieldUDPFactory); ok {
		return context.WithValue(ctx, deploymentLeaseKey{}, lease)
	}
	return ctx
}

func (factory *FieldUDPFactory) Open(ctx context.Context) (Datagram, error) {
	if factory == nil || ctx == nil || factory.instance.Check(time.Now()) != nil {
		return nil, ErrInvalidConfig
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.lease == nil || ctx.Value(deploymentLeaseKey{}) != factory.lease || factory.opened >= factory.maximum {
		return nil, ErrFactoryUnauthorized
	}
	select {
	case <-factory.lease.Stopping():
		return nil, ErrLeaseClosed
	default:
	}
	datagram, err := factory.udp.Open(ctx)
	if err != nil {
		return nil, err
	}
	slot := uint16(factory.opened)
	factory.opened++
	return &fieldDatagram{Datagram: datagram, owner: factory, slot: slot}, nil
}

// AuthorizePlan accepts only the local independently recomputed plan. It is
// called once, after authenticated bilateral commitment, before registration.
func (factory *FieldUDPFactory) AuthorizePlan(plan hardnatplan.Plan) error {
	if factory == nil || factory.instance.Check(time.Now()) != nil {
		return ErrInvalidConfig
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.lease == nil || factory.opened != factory.maximum || factory.planSet || !plan.Executable ||
		string(plan.Profile) != factory.binding.Profile || string(plan.ResourceClass) != factory.binding.Resource ||
		plan.Generation != 1 || len(plan.Candidates) == 0 {
		return ErrInvalidConfig
	}
	targets := make(map[fieldTarget]struct{}, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		if int(candidate.SocketSlot) >= factory.maximum || candidate.TargetPort == 0 ||
			(plan.Profile == hardnatplan.ProfileHardBirthday && candidate.TargetPort < 49152) {
			return ErrInvalidTarget
		}
		targets[fieldTarget{candidate.SocketSlot, netip.AddrPortFrom(factory.peer, candidate.TargetPort)}] = struct{}{}
	}
	factory.targets, factory.planSet = targets, true
	return nil
}

func (factory *FieldUDPFactory) targetAllowed(slot uint16, target netip.AddrPort) bool {
	if factory == nil || factory.instance.Check(time.Now()) != nil {
		return false
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return permitsFieldTarget(factory.observers, factory.targets, factory.opened, factory.planSet, slot, target)
}

func permitsFieldTarget(observers [4]netip.AddrPort, targets map[fieldTarget]struct{}, opened int, planSet bool, slot uint16, target netip.AddrPort) bool {
	if int(slot) >= opened {
		return false
	}
	// Only the reviewed evidence socket schedule can contact observers.
	for index, observer := range observers {
		if target == observer && (slot == 0 || (slot < 8 && int(slot)%4 == index)) {
			return true
		}
	}
	_, allowed := targets[fieldTarget{slot, target}]
	return planSet && allowed
}

type fieldDatagram struct {
	Datagram
	owner *FieldUDPFactory
	slot  uint16
}

func (datagram *fieldDatagram) allowsUnspecifiedLocalAddr() bool { return true }

func (datagram *fieldDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if !datagram.owner.targetAllowed(datagram.slot, target) {
		return 0, ErrInvalidTarget
	}
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

func validateAdditionalTargetScope(datagram Datagram, target netip.AddrPort) error {
	if field, ok := datagram.(*fieldDatagram); ok && !field.owner.targetAllowed(field.slot, target) {
		return ErrInvalidTarget
	}
	return nil
}
