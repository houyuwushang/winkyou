package natsim

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	ErrInvalidConfig   = errors.New("natsim: invalid configuration")
	ErrClosed          = errors.New("natsim: closed")
	ErrAddressInUse    = errors.New("natsim: address is already in use")
	ErrResourceLimit   = errors.New("natsim: resource limit exceeded")
	ErrNoMapping       = errors.New("natsim: mapping does not exist")
	ErrUDPBlocked      = errors.New("natsim: UDP is blocked")
	ErrMessageTooLarge = errors.New("natsim: datagram exceeds configured limit")
	ErrScenarioFailed  = errors.New("natsim: scenario failed")
	ErrResourceLeak    = errors.New("natsim: scenario left active resources")
)

// MappingBehavior controls which destination participates in a UDP mapping
// key. EIM reuses one mapping for an internal endpoint; EDM creates one mapping
// per internal endpoint and destination endpoint.
type MappingBehavior string

const (
	MappingEndpointIndependent MappingBehavior = "eim"
	MappingEndpointDependent   MappingBehavior = "edm"
)

// PortAllocation controls deterministic external-port selection.
type PortAllocation string

const (
	PortPreserving PortAllocation = "preserving"
	PortIncrement  PortAllocation = "increment"
	PortRandom     PortAllocation = "random"
)

// FilteringBehavior controls which inbound source endpoints may use an
// existing mapping.
type FilteringBehavior string

const (
	FilterEndpointIndependent  FilteringBehavior = "endpoint_independent"
	FilterAddressDependent     FilteringBehavior = "address_dependent"
	FilterAddressPortDependent FilteringBehavior = "address_port_dependent"
)

const (
	defaultPortMin = 40000
	defaultPortMax = 49999
)

// Model is the complete behavior of one virtual NAT generation.
type Model struct {
	Mapping    MappingBehavior
	Allocation PortAllocation
	Filtering  FilteringBehavior
	UDPBlocked bool
	PortMin    int
	PortMax    int
	RandomSeed uint64
}

// BehaviorChange replaces a NAT model immediately before the first outbound
// packet after AfterOutboundPackets completed attempts. Existing mappings are
// invalidated. PublicAddr may be invalid to retain the current public address.
type BehaviorChange struct {
	AfterOutboundPackets uint64
	Model                Model
	PublicAddr           netip.Addr
}

// NATConfig creates one virtual NAT. Changes must be ordered by strictly
// increasing AfterOutboundPackets values.
type NATConfig struct {
	Name       string
	PublicAddr netip.Addr
	Model      Model
	Changes    []BehaviorChange
}

func normalizeModel(model Model) (Model, error) {
	switch model.Mapping {
	case MappingEndpointIndependent, MappingEndpointDependent:
	default:
		return Model{}, fmt.Errorf("%w: unknown mapping behavior %q", ErrInvalidConfig, model.Mapping)
	}
	switch model.Allocation {
	case PortPreserving, PortIncrement, PortRandom:
	default:
		return Model{}, fmt.Errorf("%w: unknown port allocation %q", ErrInvalidConfig, model.Allocation)
	}
	switch model.Filtering {
	case FilterEndpointIndependent, FilterAddressDependent, FilterAddressPortDependent:
	default:
		return Model{}, fmt.Errorf("%w: unknown filtering behavior %q", ErrInvalidConfig, model.Filtering)
	}
	if model.PortMin == 0 && model.PortMax == 0 {
		model.PortMin = defaultPortMin
		model.PortMax = defaultPortMax
	}
	if model.PortMin < 1 || model.PortMax > 65535 || model.PortMin > model.PortMax {
		return Model{}, fmt.Errorf("%w: invalid port range %d-%d", ErrInvalidConfig, model.PortMin, model.PortMax)
	}
	if model.RandomSeed == 0 {
		model.RandomSeed = 1
	}
	return model, nil
}

func validateNATConfig(config NATConfig) (NATConfig, error) {
	if strings.TrimSpace(config.Name) == "" || strings.TrimSpace(config.Name) != config.Name {
		return NATConfig{}, fmt.Errorf("%w: NAT name is empty or not canonical", ErrInvalidConfig)
	}
	if err := validateVirtualIP(config.PublicAddr); err != nil {
		return NATConfig{}, fmt.Errorf("%w: NAT %q public address: %v", ErrInvalidConfig, config.Name, err)
	}
	model, err := normalizeModel(config.Model)
	if err != nil {
		return NATConfig{}, fmt.Errorf("NAT %q: %w", config.Name, err)
	}
	config.Model = model
	config.Changes = append([]BehaviorChange(nil), config.Changes...)
	var previous uint64
	for index := range config.Changes {
		change := &config.Changes[index]
		if change.AfterOutboundPackets == 0 || change.AfterOutboundPackets <= previous {
			return NATConfig{}, fmt.Errorf("%w: NAT %q changes are not strictly ordered", ErrInvalidConfig, config.Name)
		}
		previous = change.AfterOutboundPackets
		change.Model, err = normalizeModel(change.Model)
		if err != nil {
			return NATConfig{}, fmt.Errorf("NAT %q change %d: %w", config.Name, index, err)
		}
		if change.PublicAddr.IsValid() {
			if err := validateVirtualIP(change.PublicAddr); err != nil {
				return NATConfig{}, fmt.Errorf("%w: NAT %q change %d public address: %v", ErrInvalidConfig, config.Name, index, err)
			}
		}
	}
	return config, nil
}

func validateVirtualIP(address netip.Addr) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return errors.New("address must be a valid unicast address without a zone")
	}
	return nil
}

func validateEndpoint(endpoint netip.AddrPort) error {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return fmt.Errorf("%w: endpoint is invalid", ErrInvalidConfig)
	}
	if err := validateVirtualIP(endpoint.Addr()); err != nil {
		return fmt.Errorf("%w: endpoint address: %v", ErrInvalidConfig, err)
	}
	return nil
}
