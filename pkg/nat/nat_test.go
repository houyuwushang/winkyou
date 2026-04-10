package nat

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestNewNATTraversal(t *testing.T) {
	nt, err := NewNATTraversal(&Config{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
	})
	if err != nil {
		t.Fatalf("NewNATTraversal() error: %v", err)
	}
	if nt == nil {
		t.Fatal("NewNATTraversal() returned nil")
	}
}

func TestNewNATTraversalNilConfig(t *testing.T) {
	nt, err := NewNATTraversal(nil)
	if err != nil {
		t.Fatalf("NewNATTraversal(nil) error: %v", err)
	}
	if nt == nil {
		t.Fatal("NewNATTraversal(nil) returned nil")
	}
}

func TestDetectNATTypeNoServers(t *testing.T) {
	nt, _ := NewNATTraversal(nil)
	natType, err := nt.DetectNATType(context.Background())
	if err == nil {
		t.Error("DetectNATType() with no servers should return error")
	}
	if natType != NATTypeUnknown {
		t.Errorf("DetectNATType() = %v, want NATTypeUnknown", natType)
	}
}

func TestNewICEAgent(t *testing.T) {
	nt, _ := NewNATTraversal(nil)
	agent, err := nt.NewICEAgent(ICEConfig{})
	if err != nil {
		t.Fatalf("NewICEAgent() error: %v", err)
	}
	if agent == nil {
		t.Fatal("NewICEAgent() returned nil")
	}
}

func TestICEAgentStubMethods(t *testing.T) {
	nt, _ := NewNATTraversal(nil)
	agent, _ := nt.NewICEAgent(ICEConfig{})

	ctx := context.Background()

	// GatherCandidates is now real — it should return host candidates
	// (or empty on CI with no interfaces), not ErrNotImplemented.
	candidates, err := agent.GatherCandidates(ctx)
	if errors.Is(err, ErrNotImplemented) {
		t.Error("GatherCandidates() should no longer return ErrNotImplemented")
	}
	// It's OK if candidates is empty (e.g. in a container), but no error expected.
	_ = candidates

	err = agent.SetRemoteCandidates(nil)
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("SetRemoteCandidates() error = %v, want ErrNotImplemented", err)
	}

	_, _, err = agent.Connect(ctx)
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Connect() error = %v, want ErrNotImplemented", err)
	}

	if err := agent.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestMarshalUnmarshalCandidate(t *testing.T) {
	c := Candidate{
		Type:       CandidateTypeHost,
		Address:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
		Priority:   100,
		Foundation: "host-udp-1",
	}

	data, err := MarshalCandidate(c)
	if err != nil {
		t.Fatalf("MarshalCandidate() error: %v", err)
	}

	got, err := UnmarshalCandidate(data)
	if err != nil {
		t.Fatalf("UnmarshalCandidate() error: %v", err)
	}

	if got.Type != c.Type {
		t.Errorf("Type = %v, want %v", got.Type, c.Type)
	}
	if got.Address.IP.String() != c.Address.IP.String() {
		t.Errorf("Address.IP = %v, want %v", got.Address.IP, c.Address.IP)
	}
	if got.Address.Port != c.Address.Port {
		t.Errorf("Address.Port = %d, want %d", got.Address.Port, c.Address.Port)
	}
	if got.Priority != c.Priority {
		t.Errorf("Priority = %d, want %d", got.Priority, c.Priority)
	}
	if got.Foundation != c.Foundation {
		t.Errorf("Foundation = %q, want %q", got.Foundation, c.Foundation)
	}
}

func TestMarshalUnmarshalCandidateWithRelated(t *testing.T) {
	c := Candidate{
		Type:        CandidateTypeSrflx,
		Address:     &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 5000},
		Priority:    50,
		Foundation:  "srflx-udp-1",
		RelatedAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	}

	data, err := MarshalCandidate(c)
	if err != nil {
		t.Fatalf("MarshalCandidate() error: %v", err)
	}

	got, err := UnmarshalCandidate(data)
	if err != nil {
		t.Fatalf("UnmarshalCandidate() error: %v", err)
	}

	if got.RelatedAddr == nil {
		t.Fatal("RelatedAddr is nil after round-trip")
	}
	if got.RelatedAddr.IP.String() != c.RelatedAddr.IP.String() {
		t.Errorf("RelatedAddr.IP = %v, want %v", got.RelatedAddr.IP, c.RelatedAddr.IP)
	}
	if got.RelatedAddr.Port != c.RelatedAddr.Port {
		t.Errorf("RelatedAddr.Port = %d, want %d", got.RelatedAddr.Port, c.RelatedAddr.Port)
	}
}

func TestUnmarshalCandidateInvalidJSON(t *testing.T) {
	_, err := UnmarshalCandidate([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUnmarshalCandidateInvalidIP(t *testing.T) {
	_, err := UnmarshalCandidate([]byte(`{"type":0,"ip":"not-an-ip","port":1234}`))
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestNATTypeString(t *testing.T) {
	tests := []struct {
		nt   NATType
		want string
	}{
		{NATTypeUnknown, "unknown"},
		{NATTypeNone, "none"},
		{NATTypeFullCone, "full_cone"},
		{NATTypeRestrictedCone, "restricted_cone"},
		{NATTypePortRestricted, "port_restricted"},
		{NATTypeSymmetric, "symmetric"},
	}
	for _, tt := range tests {
		if got := tt.nt.String(); got != tt.want {
			t.Errorf("NATType(%d).String() = %q, want %q", tt.nt, got, tt.want)
		}
	}
}

func TestCandidateTypeString(t *testing.T) {
	tests := []struct {
		ct   CandidateType
		want string
	}{
		{CandidateTypeHost, "host"},
		{CandidateTypeSrflx, "srflx"},
		{CandidateTypePrflx, "prflx"},
		{CandidateTypeRelay, "relay"},
	}
	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("CandidateType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}
