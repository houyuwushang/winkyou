//go:build fieldc1c

// Package c1crouter is a sealed disposable-router tool, never an endpoint
// executor. Only the separately tagged command may acquire its OS capabilities.
package c1crouter

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
)

const (
	MappingHardCap            = 40_000
	QueueCapacity             = 16_398
	RouterPacketCap           = 65_536
	ObserverPacketCap         = 64
	DrainTimeout              = 2 * time.Second
	QueryTimeout              = time.Second
	MaxConsecutiveQueryErrors = 8
)

var ErrInvalid = errors.New("gate_c_request_invalid")
var ErrResource = errors.New("c1c_router_resource_limit")
var ErrOwnership = errors.New("c1c_router_ownership_invalid")
var ErrDrain = errors.New("c1c_router_drain_failed")
var ErrCommandUnavailable = errors.New("c1c_router_command_unavailable")
var ErrQuery = errors.New("c1c_router_query_failed")
var errIO = errors.New("c1c_router_io_failed")

func errorClass(e error) string {
	for _, candidate := range []error{ErrDrain, ErrOwnership, ErrResource, ErrQuery, ErrCommandUnavailable, ErrInvalid, errIO} {
		if errors.Is(e, candidate) {
			return candidate.Error()
		}
	}
	return "c1c_router_io_failed"
}

type terminalInput struct {
	Reported    bool
	WorkerClass string
	Clean       bool
	ChildErr    bool
	Backstop    string // not_needed, success, or failed
	BackstopErr error  // non-nil only for failed
	ResidueZero bool
}

// terminalResolution is private evidence, not an extension of public Summary.
type terminalResolution struct {
	Schema         string `json:"schema"`
	WorkerReported bool   `json:"worker_reported"`
	WorkerClass    string `json:"worker_class"`
	CleanAtExit    bool   `json:"clean_at_exit"`
	ChildExitError bool   `json:"child_exit_error"`
	Backstop       string `json:"backstop_cleanup"`
	BackstopClass  string `json:"backstop_class"`
	TerminalClass  string `json:"terminal_class"`
	Rule           int    `json:"rule"`
}

func resolveTerminalClass(in terminalInput) terminalResolution {
	r := terminalResolution{
		Schema: "winkyou-router-terminal-resolution/1", WorkerReported: in.Reported,
		CleanAtExit: in.Clean, ChildExitError: in.ChildErr, Backstop: in.Backstop,
		TerminalClass: in.WorkerClass, Rule: 5,
	}
	if in.Reported {
		r.WorkerClass = in.WorkerClass
	}
	if in.Backstop == "failed" {
		r.BackstopClass = errorClass(in.BackstopErr)
	}
	if oneOf(r.TerminalClass, "cancelled", "expired", "success") {
		r.Rule = 4
	}
	// Reproduce the original guardian decision order for the RED commit.
	if !in.Reported {
		r.TerminalClass = "c1c_router_io_failed"
		r.Rule = 2
	}
	if !in.Clean {
		if in.BackstopErr != nil {
			r.TerminalClass = errorClass(in.BackstopErr)
			r.Rule = 1
		} else {
			r.TerminalClass = "c1c_router_io_failed"
			if in.Reported {
				r.Rule = 3
			}
		}
	}
	if in.ChildErr && oneOf(r.TerminalClass, "cancelled", "expired", "success") {
		r.TerminalClass = "c1c_router_io_failed"
		r.Rule = 3
	}
	if !in.ResidueZero {
		r.TerminalClass = "c1c_router_drain_failed"
		r.Rule = 6
	}
	return r
}

// No string originating in a packet, filename, namespace or raw error can be
// inserted into this public shape. Unknown external witnesses stay null.
type Summary struct {
	Profile        string `json:"profile"`
	Stage          string `json:"stage"`
	Class          string `json:"class"`
	DurationNS     int64  `json:"duration_ns"`
	Counts         Counts `json:"counts"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}
type Counts struct {
	Outbound         uint64  `json:"outbound"`
	Inbound          uint64  `json:"inbound"`
	ObserverReplies  uint64  `json:"observer_replies"`
	PeakMappings     uint64  `json:"peak_mappings"`
	Queries          uint64  `json:"queries"`
	Unknown          uint64  `json:"unknown"`
	Censored         uint64  `json:"censored"`
	SocketResidue    *uint64 `json:"socket_residue"`
	ProcessResidue   *uint64 `json:"process_residue"`
	ConntrackResidue *uint64 `json:"conntrack_residue"`
	NamespaceResidue *uint64 `json:"namespace_residue"`
	VethResidue      *uint64 `json:"veth_residue"`
	NFTResidue       *uint64 `json:"nft_residue"`
}

func (s Summary) Encode() ([]byte, error) {
	if !oneOf(s.Profile, "", "predictive_edm/1", "asymmetric_birthday/1", "hard_birthday_campaign/1") ||
		!oneOf(s.Stage, "preflight", "router_ready", "drain", "terminal") ||
		!oneOf(s.Class, "success", "cancelled", "expired", "gate_c_request_invalid", "c1c_router_resource_limit", "c1c_router_ownership_invalid", "c1c_router_drain_failed", "c1c_router_command_unavailable", "c1c_router_query_failed", "c1c_router_io_failed") || s.DurationNS < 0 {
		return nil, ErrInvalid
	}
	if s.EvidenceSHA256 != "" {
		b, e := hex.DecodeString(s.EvidenceSHA256)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != s.EvidenceSHA256 {
			return nil, ErrInvalid
		}
	}
	return json.Marshal(s)
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

type Observation struct {
	TupleRef                 string            `json:"tuple_ref"`
	Role                     string            `json:"role"`
	WitnessClockRef          string            `json:"witness_clock_ref"`
	MappingAgeAtHitNS        *int64            `json:"mapping_age_at_hit_ns"`
	MappingAgeAtWinnerNS     *int64            `json:"mapping_age_at_winner_ns"`
	MappingIdleAgeAtWinnerNS *int64            `json:"mapping_idle_age_at_winner_ns"`
	HitToStopNS              *int64            `json:"hit_to_stop_ns"`
	StopToWinnerNS           *int64            `json:"stop_to_winner_ns"`
	WinnerToVerifyNS         *int64            `json:"winner_to_verify_ns"`
	StopToVerifyNS           *int64            `json:"stop_to_verify_ns"`
	KernelFlowObservation    string            `json:"kernel_flow_observation"`
	FailureStage             *string           `json:"failure_stage"`
	TerminalClass            *string           `json:"terminal_class"`
	MissingReason            map[string]string `json:"missing_reason"`
	MeasurementSource        map[string]string `json:"measurement_source"`
}

// Unauthenticated frame headers are sampling hints, never authenticated hit,
// winner or VERIFY evidence. Correlation is a separate offline review input.
func unknownObservation(role, ref string) Observation {
	row := Observation{TupleRef: ref, Role: role, WitnessClockRef: "router-monotonic/1", KernelFlowObservation: "unknown", MissingReason: map[string]string{}, MeasurementSource: map[string]string{}}
	for _, name := range []string{"mapping_age_at_hit_ns", "mapping_age_at_winner_ns", "mapping_idle_age_at_winner_ns", "hit_to_stop_ns", "stop_to_winner_ns", "winner_to_verify_ns", "stop_to_verify_ns"} {
		row.MissingReason[name] = "authenticated_endpoint_correlation_missing"
		row.MeasurementSource[name] = "unavailable"
	}
	row.MissingReason["kernel_flow_observation"] = "not_sampled"
	row.MeasurementSource["kernel_flow_observation"] = "conntrack_exact_get"
	row.MissingReason["failure_stage"], row.MissingReason["terminal_class"] = "endpoint_result_missing", "endpoint_result_missing"
	return row
}

func (o Observation) Valid() bool {
	if !oneOf(o.Role, "initiator", "responder") || o.TupleRef == "" || o.WitnessClockRef == "" || !oneOf(o.KernelFlowObservation, "present", "absent", "unknown") {
		return false
	}
	fields := map[string]*int64{"mapping_age_at_hit_ns": o.MappingAgeAtHitNS, "mapping_age_at_winner_ns": o.MappingAgeAtWinnerNS, "mapping_idle_age_at_winner_ns": o.MappingIdleAgeAtWinnerNS, "hit_to_stop_ns": o.HitToStopNS, "stop_to_winner_ns": o.StopToWinnerNS, "winner_to_verify_ns": o.WinnerToVerifyNS, "stop_to_verify_ns": o.StopToVerifyNS}
	for name, value := range fields {
		if value == nil {
			if o.MissingReason[name] == "" {
				return false
			}
		} else if *value < 0 || o.MissingReason[name] != "" || o.MeasurementSource[name] == "" || o.MeasurementSource[name] == "unavailable" {
			return false
		}
	}
	return (o.KernelFlowObservation != "unknown" || o.MissingReason["kernel_flow_observation"] != "") && (o.FailureStage != nil || o.MissingReason["failure_stage"] != "") && (o.TerminalClass != nil || o.MissingReason["terminal_class"] != "")
}

func classifyQuery(ctx context.Context, output []byte, err error) (string, error) {
	if errors.Is(err, ErrCommandUnavailable) {
		return "unknown", ErrCommandUnavailable
	}
	if ctx.Err() != nil {
		return "unknown", ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "unknown", err
	}
	if err != nil {
		var exit interface {
			error
			ExitCode() int
		}
		text := strings.ToLower(strings.TrimSpace(string(output)))
		if errors.As(err, &exit) && exit.ExitCode() == 1 && strings.HasPrefix(text, "conntrack v") && strings.Contains(text, "such conntrack doesn't exist") && !strings.Contains(text, "\nudp ") {
			return "absent", nil
		}
		return "unknown", ErrQuery
	}
	n := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "udp ") {
			n++
		}
	}
	if n != 1 {
		return "unknown", ErrQuery
	}
	return "present", nil
}

type datagram struct {
	source, target netip.AddrPort
	payload        []byte
}

func parseUDP(packet []byte) (datagram, error) {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return datagram{}, ErrInvalid
	}
	h := int(packet[0]&15) * 4
	n := int(binary.BigEndian.Uint16(packet[2:4]))
	if h < 20 || n < h+8 || n != len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return datagram{}, ErrInvalid
	}
	u := packet[h:n]
	if int(binary.BigEndian.Uint16(u[4:6])) != len(u) {
		return datagram{}, ErrInvalid
	}
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[12:16])), binary.BigEndian.Uint16(u[:2]))
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[16:20])), binary.BigEndian.Uint16(u[2:4]))
	if src.Port() == 0 || dst.Port() == 0 {
		return datagram{}, ErrInvalid
	}
	return datagram{src, dst, append([]byte(nil), u[8:]...)}, nil
}
func encodeUDP(src, dst netip.AddrPort, payload []byte) ([]byte, error) {
	if !src.IsValid() || !dst.IsValid() || !src.Addr().Is4() || !dst.Addr().Is4() || src.Port() == 0 || dst.Port() == 0 || len(payload) > 65507 {
		return nil, ErrInvalid
	}
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	u := p[20:]
	binary.BigEndian.PutUint16(u[:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	// Zero IPv4 UDP checksum is valid; the endpoint's authenticated payload
	// remains unchanged. The router has no handshake or packet-cipher key.
	return p, nil
}
func checksum(p []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(p); i += 2 {
		s += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for s>>16 != 0 {
		s = s&65535 + s>>16
	}
	return ^uint16(s)
}
