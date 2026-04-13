package nat

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	relayserver "winkyou/pkg/relay/server"
)

func TestICEAgentsConnectAndSelectedPair(t *testing.T) {
	nt, _ := NewNATTraversal(nil)

	a1, err := nt.NewICEAgent(ICEConfig{ConnectTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewICEAgent(a1) error: %v", err)
	}
	a2, err := nt.NewICEAgent(ICEConfig{ConnectTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewICEAgent(a2) error: %v", err)
	}
	defer a1.Close()
	defer a2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c1, err := a1.GatherCandidates(ctx)
	if err != nil || len(c1) == 0 {
		t.Fatalf("a1 GatherCandidates() = %d, err=%v", len(c1), err)
	}
	c2, err := a2.GatherCandidates(ctx)
	if err != nil || len(c2) == 0 {
		t.Fatalf("a2 GatherCandidates() = %d, err=%v", len(c2), err)
	}

	if err := a1.SetRemoteCandidates(c2); err != nil {
		t.Fatalf("a1 SetRemoteCandidates() error: %v", err)
	}
	if err := a2.SetRemoteCandidates(c1); err != nil {
		t.Fatalf("a2 SetRemoteCandidates() error: %v", err)
	}

	type result struct {
		conn net.Conn
		pair *CandidatePair
		err  error
	}
	ch1 := make(chan result, 1)
	ch2 := make(chan result, 1)
	go func() {
		conn, pair, err := a1.Connect(ctx)
		ch1 <- result{conn: conn, pair: pair, err: err}
	}()
	go func() {
		conn, pair, err := a2.Connect(ctx)
		ch2 <- result{conn: conn, pair: pair, err: err}
	}()

	r1 := <-ch1
	r2 := <-ch2
	if r1.err != nil || r2.err != nil {
		t.Fatalf("connect errors: a1=%v a2=%v", r1.err, r2.err)
	}
	defer r1.conn.Close()
	defer r2.conn.Close()

	if r1.pair == nil || r2.pair == nil {
		t.Fatal("selected pair should not be nil")
	}
	if r1.pair.Remote == nil || r2.pair.Remote == nil {
		t.Fatal("selected pair remote should not be nil")
	}

}

func TestICEPayloadRoundTripAndRelayCandidates(t *testing.T) {
	offer := ICESessionDescriptionPayload{
		Ufrag: "ufrag-a",
		Pwd:   "pwd-a",
		Role:  "controlling",
		Candidates: []Candidate{{
			Type:       CandidateTypeHost,
			Address:    &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5000},
			Priority:   100,
			Foundation: "h1",
		}},
	}
	blob, err := MarshalICESessionDescriptionPayload(offer)
	if err != nil {
		t.Fatalf("MarshalICESessionDescriptionPayload() error: %v", err)
	}
	decoded, err := UnmarshalICESessionDescriptionPayload(blob)
	if err != nil {
		t.Fatalf("UnmarshalICESessionDescriptionPayload() error: %v", err)
	}
	if decoded.Ufrag != offer.Ufrag || decoded.Role != offer.Role || len(decoded.Candidates) != 1 {
		t.Fatalf("decoded offer mismatch: %+v", decoded)
	}

	candBlob, err := MarshalICECandidatePayload(ICECandidatePayload{Candidate: offer.Candidates[0]})
	if err != nil {
		t.Fatalf("MarshalICECandidatePayload() error: %v", err)
	}
	candDecoded, err := UnmarshalICECandidatePayload(candBlob)
	if err != nil {
		t.Fatalf("UnmarshalICECandidatePayload() error: %v", err)
	}
	if candDecoded.Candidate.Type != CandidateTypeHost {
		t.Fatalf("candidate type = %v, want host", candDecoded.Candidate.Type)
	}

	relays := gatherRelayCandidates(context.Background(), []TURNServer{{URL: "turn:127.0.0.1:3478", Username: "u", Password: "p"}})
	if len(relays) != 1 || relays[0].Type != CandidateTypeRelay {
		t.Fatalf("relay candidates = %+v", relays)
	}
}

func TestICERelayFallbackWhenDirectFails(t *testing.T) {
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error: %v", err)
	}
	defer ln.Close()
	turnPort := ln.LocalAddr().(*net.UDPAddr).Port
	turnURL := fmt.Sprintf("turn:127.0.0.1:%d", turnPort)

	nt, _ := NewNATTraversal(&Config{TURNServers: []TURNServer{{URL: turnURL, Username: "u", Password: "p"}}})
	agent, err := nt.NewICEAgent(ICEConfig{ConnectTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewICEAgent() error: %v", err)
	}
	defer agent.Close()

	ctx := context.Background()
	locals, err := agent.GatherCandidates(ctx)
	if err != nil {
		t.Fatalf("GatherCandidates() error: %v", err)
	}
	var hasRelay bool
	for _, c := range locals {
		if c.Type == CandidateTypeRelay {
			hasRelay = true
			break
		}
	}
	if !hasRelay {
		t.Fatal("expected local relay candidate")
	}

	remote := Candidate{Type: CandidateTypeRelay, Address: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: turnPort}, Priority: 1, Foundation: "relay-remote"}
	if err := agent.SetRemoteCandidates([]Candidate{remote}); err != nil {
		t.Fatalf("SetRemoteCandidates() error: %v", err)
	}

	conn, pair, err := agent.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer conn.Close()
	if pair == nil || pair.Local == nil || pair.Remote == nil {
		t.Fatal("pair should not be nil")
	}
	if pair.Local.Type != CandidateTypeRelay || pair.Remote.Type != CandidateTypeRelay {
		t.Fatalf("pair types = %v/%v, want relay/relay", pair.Local.Type, pair.Remote.Type)
	}
}

func TestGatherRelayCandidatesUsesTURNAllocation(t *testing.T) {
	srv, err := relayserver.New(relayserver.Config{
		ListenAddress: "127.0.0.1:0",
		Realm:         "winkyou",
		Users:         map[string]string{"u": "p"},
	})
	if err != nil {
		t.Fatalf("relay server new error: %v", err)
	}
	defer srv.Close()
	if err := srv.Start(); err != nil {
		t.Fatalf("relay server start error: %v", err)
	}

	turnURL := "turn:" + srv.Addr().String()
	cands := gatherRelayCandidates(context.Background(), []TURNServer{{URL: turnURL, Username: "u", Password: "p"}})
	if len(cands) == 0 {
		t.Fatal("expected at least one relay candidate")
	}
	if cands[0].Type != CandidateTypeRelay {
		t.Fatalf("candidate type = %v, want relay", cands[0].Type)
	}
	if cands[0].Address == nil {
		t.Fatal("relay candidate address is nil")
	}

	_, portStr, _ := net.SplitHostPort(srv.Addr().String())
	var serverPort int
	_, _ = fmt.Sscanf(portStr, "%d", &serverPort)
	if cands[0].Address.Port == serverPort {
		t.Fatalf("expected allocated relayed port (not server listen port), got %d", cands[0].Address.Port)
	}
}
