package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
)

func TestPeerDescriptorJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	descriptor := PeerDescriptor{
		NodeID:    "node-a",
		PublicKey: "pub-a",
		VirtualIP: "10.77.0.2",
		Capability: rproto.Capability{
			Strategies: []string{"legacy_ice_udp"},
			Features:   []string{"probe_lab_v1"},
		},
		LastPathID: "direct/path",
		Candidates: []CandidateHint{{
			Strategy: "legacy_ice_udp",
			Type:     "host",
			Address:  "192.0.2.10:51820",
			Source:   "local_gather",
		}},
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Minute),
	}

	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	decoded, err := DecodePeerDescriptor(raw)
	if err != nil {
		t.Fatalf("DecodePeerDescriptor() error = %v", err)
	}
	if decoded.NodeID != descriptor.NodeID || decoded.Candidates[0].Address != "192.0.2.10:51820" {
		t.Fatalf("decoded descriptor = %#v", decoded)
	}
}

func TestPeerDescriptorValidateRejectsExpiredDescriptor(t *testing.T) {
	now := time.Now().UTC()
	descriptor := validPeerDescriptor(now)
	descriptor.ExpiresAt = now.Add(-time.Second)

	err := descriptor.Validate()
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Validate() error = %v, want expired", err)
	}
}

func TestPeerDescriptorValidateRejectsMissingFields(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name   string
		mutate func(*PeerDescriptor)
		want   string
	}{
		{name: "node id", mutate: func(d *PeerDescriptor) { d.NodeID = "" }, want: "node_id"},
		{name: "public key", mutate: func(d *PeerDescriptor) { d.PublicKey = "" }, want: "public_key"},
		{name: "virtual ip", mutate: func(d *PeerDescriptor) { d.VirtualIP = "" }, want: "virtual_ip"},
		{name: "capability", mutate: func(d *PeerDescriptor) { d.Capability = rproto.Capability{} }, want: "capability"},
		{name: "updated at", mutate: func(d *PeerDescriptor) { d.UpdatedAt = time.Time{} }, want: "updated_at"},
		{name: "expires at", mutate: func(d *PeerDescriptor) { d.ExpiresAt = time.Time{} }, want: "expires_at"},
		{name: "candidate", mutate: func(d *PeerDescriptor) { d.Candidates[0].Address = "" }, want: "candidate hint 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := validPeerDescriptor(now)
			tt.mutate(&descriptor)
			err := descriptor.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCandidateHintJSONRoundTrip(t *testing.T) {
	hint := CandidateHint{
		Strategy: "tcp_framed",
		Type:     "explicit_tcp",
		Address:  "203.0.113.20:443",
		Source:   "broker_cache",
	}
	raw, err := json.Marshal(hint)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded CandidateHint
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if decoded != hint {
		t.Fatalf("decoded hint = %#v, want %#v", decoded, hint)
	}
}

func TestEnvelopeJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	envelope := Envelope{
		Version: EnvelopeVersion,
		From:    "node-a",
		To:      "node-c",
		Type:    "peer_descriptor",
		Seq:     7,
		Payload: json.RawMessage(`{"node_id":"node-a"}`),
		SentAt:  now,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	decoded, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	if decoded.Version != EnvelopeVersion || decoded.Seq != 7 || string(decoded.Payload) != `{"node_id":"node-a"}` {
		t.Fatalf("decoded envelope = %#v", decoded)
	}
}

func validPeerDescriptor(now time.Time) PeerDescriptor {
	return PeerDescriptor{
		NodeID:    "node-a",
		PublicKey: "pub-a",
		VirtualIP: "10.77.0.2",
		Capability: rproto.Capability{
			Strategies: []string{"legacy_ice_udp"},
		},
		Candidates: []CandidateHint{{
			Strategy: "legacy_ice_udp",
			Type:     "host",
			Address:  "192.0.2.10:51820",
		}},
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Minute),
	}
}
