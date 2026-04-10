// Package nat defines the NAT traversal and ICE abstractions for the MVP.
// Concrete implementations (backed by pion/stun and pion/ice) will be
// added in later milestones; this file freezes the public contract.
package nat

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrNotImplemented is returned by stub methods that have no real
// implementation yet.
var ErrNotImplemented = errors.New("nat: not implemented")

// Config holds the parameters needed to create a NATTraversal instance.
type Config struct {
	STUNServers []string
	TURNServers []TURNServer
}

// TURNServer describes a TURN relay server.
type TURNServer struct {
	URL      string
	Username string
	Password string
}

// ICEConfig holds the parameters for creating an ICE agent.
type ICEConfig struct {
	GatherTimeout  time.Duration // default: 5s
	CheckTimeout   time.Duration // default: 10s
	ConnectTimeout time.Duration // default: 30s
	STUNServers    []string
	TURNServers    []TURNServer
}

// NATType represents the detected NAT type.
type NATType int

const (
	NATTypeUnknown  NATType = iota
	NATTypeNone             // public IP, no NAT
	NATTypeFullCone         // easiest to traverse
	NATTypeRestrictedCone
	NATTypePortRestricted
	NATTypeSymmetric // hardest to traverse
)

func (t NATType) String() string {
	switch t {
	case NATTypeNone:
		return "none"
	case NATTypeFullCone:
		return "full_cone"
	case NATTypeRestrictedCone:
		return "restricted_cone"
	case NATTypePortRestricted:
		return "port_restricted"
	case NATTypeSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// CandidateType identifies the source of a Candidate.
type CandidateType int

const (
	CandidateTypeHost  CandidateType = iota // local address
	CandidateTypeSrflx                      // STUN server-reflexive
	CandidateTypePrflx                      // peer-reflexive
	CandidateTypeRelay                      // TURN relay
)

func (ct CandidateType) String() string {
	switch ct {
	case CandidateTypeHost:
		return "host"
	case CandidateTypeSrflx:
		return "srflx"
	case CandidateTypePrflx:
		return "prflx"
	case CandidateTypeRelay:
		return "relay"
	default:
		return "unknown"
	}
}

// Candidate represents an ICE candidate address.
type Candidate struct {
	Type        CandidateType `json:"type"`
	Address     *net.UDPAddr  `json:"address"`
	Priority    uint32        `json:"priority"`
	Foundation  string        `json:"foundation"`
	RelatedAddr *net.UDPAddr  `json:"related_addr,omitempty"`
}

// CandidatePair represents a pair of candidates being checked or selected.
type CandidatePair struct {
	Local  *Candidate
	Remote *Candidate
}

// ConnectionState represents the ICE connection state.
type ConnectionState int

const (
	ConnectionStateNew ConnectionState = iota
	ConnectionStateChecking
	ConnectionStateConnected
	ConnectionStateCompleted
	ConnectionStateFailed
	ConnectionStateClosed
)

// ICEAgent negotiates a P2P connection via ICE.
type ICEAgent interface {
	GatherCandidates(ctx context.Context) ([]Candidate, error)
	SetRemoteCandidates(candidates []Candidate) error
	Connect(ctx context.Context) (net.Conn, *CandidatePair, error)
	Close() error
}

// NATTraversal is the top-level NAT traversal facility.
type NATTraversal interface {
	DetectNATType(ctx context.Context) (NATType, error)
	NewICEAgent(cfg ICEConfig) (ICEAgent, error)
}

// NewNATTraversal creates a NATTraversal instance.
func NewNATTraversal(cfg *Config) (NATTraversal, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	return &natTraversalImpl{cfg: *cfg}, nil
}
