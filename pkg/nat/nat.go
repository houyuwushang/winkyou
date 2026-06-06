// Package nat defines the NAT traversal and ICE abstractions for the MVP.
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
	GatherTimeout             time.Duration // default: 5s
	CheckTimeout              time.Duration // default: 10s
	ConnectTimeout            time.Duration // default: 30s
	CandidatePortMin          uint16
	CandidatePortMax          uint16
	STUNServers               []string
	TURNServers               []TURNServer
	Controlling               bool
	CandidateInterfaceInclude []string
	CandidateInterfaceExclude []string
	CandidateCIDRInclude      []string
	CandidateCIDRExclude      []string
	NAT1To1IPs                []string
	NAT1To1CandidateType      string
	PublicDirectTrustedCIDRs  []string

	// PublicDirectCandidate limits gathering to host/server-reflexive direct
	// candidates. It is used by stricter direct probes that must not wait on or
	// advertise TURN relay candidates.
	PublicDirectCandidate bool

	// ForceRelay forces relay-only candidate gathering (test/debug only).
	ForceRelay bool

	// relayOnly is test-only; it forces relay-only candidate gathering.
	relayOnly bool
}

// PublicDirectSTUNServerURLs returns the effective STUN binding URLs used by a
// public-direct ICE attempt. It includes configured STUN servers and UDP TURN
// servers converted to unauthenticated STUN binding URLs on the same host/port.
func PublicDirectSTUNServerURLs(cfg ICEConfig) ([]string, error) {
	urls, err := buildPionURLs(ICEConfig{
		STUNServers:           cfg.STUNServers,
		TURNServers:           cfg.TURNServers,
		PublicDirectCandidate: true,
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, uri := range urls {
		if uri == nil {
			continue
		}
		raw := uri.String()
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out, nil
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

// CandidatePairStats contains optional statistics for a selected ICE pair.
type CandidatePairStats struct {
	CurrentRoundTripTime time.Duration
	TotalRoundTripTime   time.Duration
}

// PublicDirectPunchOptions controls a best-effort UDP punch burst to remote
// public-direct candidates.
type PublicDirectPunchOptions struct {
	Limit int
	Burst int
}

// PublicDirectPunchReport summarizes a best-effort UDP punch burst.
type PublicDirectPunchReport struct {
	CandidateTotal int
	CandidateSent  int
	PacketSent     int
	LocalAddr      *net.UDPAddr
}

// PublicDirectPuncher is an optional ICEAgent capability. Implementations may
// send best-effort UDP packets from the same public-direct socket used by ICE
// to open endpoint-dependent NAT mappings before normal ICE checks select a
// pair.
type PublicDirectPuncher interface {
	PunchCandidates(ctx context.Context, candidates []Candidate, opts PublicDirectPunchOptions) (PublicDirectPunchReport, error)
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

// SelectedTransport is the long-lived transport chosen by ICE.
type SelectedTransport interface {
	net.Conn
}

// ICEAgent negotiates a P2P connection via ICE.
type ICEAgent interface {
	GatherCandidates(ctx context.Context) ([]Candidate, error)
	GetLocalCredentials() (ufrag string, pwd string, err error)
	SetRemoteCredentials(ufrag, pwd string) error
	SetRemoteCandidates(candidates []Candidate) error
	Connect(ctx context.Context) (SelectedTransport, *CandidatePair, error)
	Close() error
}

// NATTraversal is the top-level NAT traversal facility.
type NATTraversal interface {
	DetectNATType(ctx context.Context) (NATType, error)
	DetectSTUNMapping(ctx context.Context) (STUNMappingReport, error)
	NewICEAgent(cfg ICEConfig) (ICEAgent, error)
}

// NewNATTraversal creates a NATTraversal instance.
func NewNATTraversal(cfg *Config) (NATTraversal, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	return &natTraversalImpl{cfg: *cfg}, nil
}
