package nat

import (
	"encoding/json"
	"fmt"
	"net"
)

// candidateWire is the JSON wire format for Candidate serialization.
// We use a helper struct because net.UDPAddr does not have a clean
// JSON representation by default.
type candidateWire struct {
	Type        CandidateType `json:"type"`
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	Priority    uint32        `json:"priority"`
	Foundation  string        `json:"foundation"`
	RelatedIP   string        `json:"related_ip,omitempty"`
	RelatedPort int           `json:"related_port,omitempty"`
}

// MarshalCandidate serializes a Candidate to JSON bytes.
func MarshalCandidate(c Candidate) ([]byte, error) {
	w := candidateWire{
		Type:       c.Type,
		Priority:   c.Priority,
		Foundation: c.Foundation,
	}
	if c.Address != nil {
		w.IP = c.Address.IP.String()
		w.Port = c.Address.Port
	}
	if c.RelatedAddr != nil {
		w.RelatedIP = c.RelatedAddr.IP.String()
		w.RelatedPort = c.RelatedAddr.Port
	}
	return json.Marshal(w)
}

// UnmarshalCandidate deserializes a Candidate from JSON bytes.
func UnmarshalCandidate(data []byte) (Candidate, error) {
	var w candidateWire
	if err := json.Unmarshal(data, &w); err != nil {
		return Candidate{}, fmt.Errorf("nat: unmarshal candidate: %w", err)
	}

	c := Candidate{
		Type:       w.Type,
		Priority:   w.Priority,
		Foundation: w.Foundation,
	}

	ip := net.ParseIP(w.IP)
	if ip == nil && w.IP != "" {
		return Candidate{}, fmt.Errorf("nat: invalid candidate IP: %q", w.IP)
	}
	if ip != nil {
		c.Address = &net.UDPAddr{IP: ip, Port: w.Port}
	}

	if w.RelatedIP != "" {
		rip := net.ParseIP(w.RelatedIP)
		if rip == nil {
			return Candidate{}, fmt.Errorf("nat: invalid related IP: %q", w.RelatedIP)
		}
		c.RelatedAddr = &net.UDPAddr{IP: rip, Port: w.RelatedPort}
	}

	return c, nil
}
