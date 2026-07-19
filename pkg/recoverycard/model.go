// Package recoverycard persists the minimum last-known-good state needed to
// re-contact mesh peers after a process or machine restart.
package recoverycard

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// CurrentVersion is the only recovery-card schema understood by this
	// package. Readers reject other versions instead of guessing migrations.
	CurrentVersion = 1

	MaxNodeIDLength      = 1024
	MaxLocalBindPorts    = 64
	MaxPeers             = 1024
	MaxEndpointsPerPeer  = 64
	maxSequentialPortGap = 65535
)

// PortPattern is the persisted form of a NAT external-port allocation model.
type PortPattern string

const (
	PortPatternUnknown    PortPattern = "unknown"
	PortPatternPreserving PortPattern = "preserving"
	PortPatternSequential PortPattern = "sequential"
	PortPatternRandom     PortPattern = "random"
)

// Card is a versioned snapshot of successful peer endpoints and the local NAT
// information needed to try those endpoints again. UpdatedAt is the snapshot
// time; LastSuccessAt is the newest successful path represented by the card.
type Card struct {
	Version        int       `json:"version"`
	NodeID         string    `json:"node_id"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastSuccessAt  time.Time `json:"last_success_at"`
	LocalBindPorts []uint16  `json:"local_bind_ports"`
	LocalNAT       NATModel  `json:"local_nat"`
	Peers          []Peer    `json:"peers"`
}

// NATModel records the most recently observed external-port allocation model.
type NATModel struct {
	Pattern    PortPattern `json:"pattern"`
	Delta      int         `json:"delta"`
	Confidence float64     `json:"confidence"`
	ObservedAt time.Time   `json:"observed_at"`
}

// Peer holds a bounded history of endpoints that have successfully reached a
// peer. Consumers may choose their own ordering; every entry carries its own
// success timestamp.
type Peer struct {
	NodeID                      string     `json:"node_id"`
	LastSuccessfulLocalBindPort uint16     `json:"last_successful_local_bind_port"`
	LastSuccessAt               time.Time  `json:"last_success_at"`
	Endpoints                   []Endpoint `json:"endpoints"`
}

// Endpoint is one successful remote UDP endpoint observation. Source is an
// extensible producer name such as "peer_observed", "stun", or
// "successful_path"; NAT describes the remote endpoint's advertised model.
type Endpoint struct {
	AddrPort      string    `json:"addr_port"`
	ObservedAt    time.Time `json:"observed_at"`
	Source        string    `json:"source"`
	NAT           NATModel  `json:"nat"`
	LastSuccessAt time.Time `json:"last_success_at"`
}

// Validate rejects malformed, ambiguous, or unbounded recovery state. It does
// not compare timestamps with the local wall clock because recovery must remain
// usable across clock corrections.
func (c Card) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("recoverycard: unsupported version %d", c.Version)
	}
	if err := validateNodeID("node_id", c.NodeID); err != nil {
		return err
	}
	if c.UpdatedAt.IsZero() {
		return errors.New("recoverycard: updated_at is required")
	}
	if c.LastSuccessAt.IsZero() {
		return errors.New("recoverycard: last_success_at is required")
	}
	if c.LastSuccessAt.After(c.UpdatedAt) {
		return errors.New("recoverycard: last_success_at is after updated_at")
	}

	if len(c.LocalBindPorts) == 0 {
		return errors.New("recoverycard: at least one local_bind_port is required")
	}
	if len(c.LocalBindPorts) > MaxLocalBindPorts {
		return fmt.Errorf("recoverycard: local_bind_ports exceeds maximum %d", MaxLocalBindPorts)
	}
	bindPorts := make(map[uint16]struct{}, len(c.LocalBindPorts))
	for i, port := range c.LocalBindPorts {
		if port == 0 {
			return fmt.Errorf("recoverycard: local_bind_ports[%d] is zero", i)
		}
		if _, duplicate := bindPorts[port]; duplicate {
			return fmt.Errorf("recoverycard: duplicate local bind port %d", port)
		}
		bindPorts[port] = struct{}{}
	}

	if err := c.LocalNAT.validate(c.UpdatedAt); err != nil {
		return fmt.Errorf("recoverycard: local_nat: %w", err)
	}
	if len(c.Peers) == 0 {
		return errors.New("recoverycard: at least one peer is required")
	}
	if len(c.Peers) > MaxPeers {
		return fmt.Errorf("recoverycard: peers exceeds maximum %d", MaxPeers)
	}
	peerIDs := make(map[string]struct{}, len(c.Peers))
	newestSuccess := time.Time{}
	for i, peer := range c.Peers {
		if err := peer.validate(c.NodeID, c.UpdatedAt, bindPorts); err != nil {
			return fmt.Errorf("recoverycard: peers[%d]: %w", i, err)
		}
		if _, duplicate := peerIDs[peer.NodeID]; duplicate {
			return fmt.Errorf("recoverycard: duplicate peer node_id %q", peer.NodeID)
		}
		peerIDs[peer.NodeID] = struct{}{}
		if peer.LastSuccessAt.After(newestSuccess) {
			newestSuccess = peer.LastSuccessAt
		}
	}
	if !c.LastSuccessAt.Equal(newestSuccess) {
		return errors.New("recoverycard: last_success_at must equal the newest endpoint success")
	}
	return nil
}

func (m NATModel) validate(updatedAt time.Time) error {
	switch m.Pattern {
	case PortPatternUnknown, PortPatternPreserving, PortPatternSequential, PortPatternRandom:
	default:
		return fmt.Errorf("invalid pattern %q", m.Pattern)
	}
	if math.IsNaN(m.Confidence) || math.IsInf(m.Confidence, 0) || m.Confidence < 0 || m.Confidence > 1 {
		return fmt.Errorf("confidence %v is outside 0..1", m.Confidence)
	}
	if m.ObservedAt.IsZero() {
		return errors.New("observed_at is required")
	}
	if m.ObservedAt.After(updatedAt) {
		return errors.New("observed_at is after card updated_at")
	}
	switch m.Pattern {
	case PortPatternSequential:
		if m.Delta == 0 || m.Delta < -maxSequentialPortGap || m.Delta > maxSequentialPortGap {
			return fmt.Errorf("sequential delta %d is invalid", m.Delta)
		}
	default:
		if m.Delta != 0 {
			return fmt.Errorf("delta must be zero for pattern %q", m.Pattern)
		}
	}
	return nil
}

func (p Peer) validate(localNodeID string, updatedAt time.Time, bindPorts map[uint16]struct{}) error {
	if err := validateNodeID("peer node_id", p.NodeID); err != nil {
		return err
	}
	if p.NodeID == localNodeID {
		return errors.New("peer node_id must differ from local node_id")
	}
	if p.LastSuccessfulLocalBindPort == 0 {
		return errors.New("last_successful_local_bind_port is required")
	}
	if _, ok := bindPorts[p.LastSuccessfulLocalBindPort]; !ok {
		return fmt.Errorf("last_successful_local_bind_port %d is absent from local_bind_ports", p.LastSuccessfulLocalBindPort)
	}
	if p.LastSuccessAt.IsZero() {
		return errors.New("last_success_at is required")
	}
	if p.LastSuccessAt.After(updatedAt) {
		return errors.New("last_success_at is after card updated_at")
	}
	if len(p.Endpoints) == 0 {
		return errors.New("at least one endpoint is required")
	}
	if len(p.Endpoints) > MaxEndpointsPerPeer {
		return fmt.Errorf("endpoints exceeds maximum %d", MaxEndpointsPerPeer)
	}
	addresses := make(map[netip.AddrPort]struct{}, len(p.Endpoints))
	newestSuccess := time.Time{}
	for i, endpoint := range p.Endpoints {
		addrPort, err := endpoint.validate(updatedAt)
		if err != nil {
			return fmt.Errorf("endpoints[%d]: %w", i, err)
		}
		if _, duplicate := addresses[addrPort]; duplicate {
			return fmt.Errorf("duplicate endpoint addr_port %q", endpoint.AddrPort)
		}
		addresses[addrPort] = struct{}{}
		if endpoint.LastSuccessAt.After(newestSuccess) {
			newestSuccess = endpoint.LastSuccessAt
		}
	}
	if !p.LastSuccessAt.Equal(newestSuccess) {
		return errors.New("last_success_at must equal the newest endpoint success")
	}
	return nil
}

func (e Endpoint) validate(updatedAt time.Time) (netip.AddrPort, error) {
	if strings.TrimSpace(e.AddrPort) != e.AddrPort || e.AddrPort == "" {
		return netip.AddrPort{}, errors.New("addr_port must be non-empty and have no surrounding whitespace")
	}
	addrPort, err := netip.ParseAddrPort(e.AddrPort)
	if err != nil || !addrPort.IsValid() || addrPort.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid addr_port %q", e.AddrPort)
	}
	addr := addrPort.Addr()
	if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.AddrPort{}, fmt.Errorf("unusable addr_port %q", e.AddrPort)
	}
	if e.ObservedAt.IsZero() {
		return netip.AddrPort{}, errors.New("observed_at is required")
	}
	if e.ObservedAt.After(updatedAt) {
		return netip.AddrPort{}, errors.New("observed_at is after card updated_at")
	}
	if strings.TrimSpace(e.Source) != e.Source || e.Source == "" || len(e.Source) > 64 || !utf8.ValidString(e.Source) {
		return netip.AddrPort{}, errors.New("source must be 1..64 bytes with no surrounding whitespace")
	}
	for _, r := range e.Source {
		if unicode.IsControl(r) {
			return netip.AddrPort{}, errors.New("source contains a control character")
		}
	}
	if err := e.NAT.validate(updatedAt); err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: %w", err)
	}
	if e.NAT.ObservedAt.After(e.ObservedAt) {
		return netip.AddrPort{}, errors.New("nat observed_at is after endpoint observed_at")
	}
	if e.LastSuccessAt.IsZero() {
		return netip.AddrPort{}, errors.New("last_success_at is required")
	}
	if e.LastSuccessAt.After(updatedAt) {
		return netip.AddrPort{}, errors.New("last_success_at is after card updated_at")
	}
	if e.ObservedAt.After(e.LastSuccessAt) {
		return netip.AddrPort{}, errors.New("observed_at is after last_success_at")
	}
	return addrPort, nil
}

func validateNodeID(field, value string) error {
	if strings.TrimSpace(value) != value || value == "" || !utf8.ValidString(value) {
		return fmt.Errorf("recoverycard: %s must be non-empty and have no surrounding whitespace", field)
	}
	if len(value) > MaxNodeIDLength {
		return fmt.Errorf("recoverycard: %s exceeds maximum length %d", field, MaxNodeIDLength)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("recoverycard: %s contains a control character", field)
		}
	}
	return nil
}
