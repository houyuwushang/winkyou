package nat

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	pionice "github.com/pion/ice/v2"
	"github.com/pion/stun"
)

func TestICEAgentsConnectAndSelectedPair(t *testing.T) {
	nt, _ := NewNATTraversal(nil)

	a1, err := nt.NewICEAgent(ICEConfig{ConnectTimeout: 3 * time.Second, Controlling: true})
	if err != nil {
		t.Fatalf("NewICEAgent(a1) error: %v", err)
	}
	a2, err := nt.NewICEAgent(ICEConfig{ConnectTimeout: 3 * time.Second, Controlling: false})
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
	a1Ufrag, a1Pwd, err := a1.GetLocalCredentials()
	if err != nil {
		t.Fatalf("a1 GetLocalCredentials() error: %v", err)
	}
	a2Ufrag, a2Pwd, err := a2.GetLocalCredentials()
	if err != nil {
		t.Fatalf("a2 GetLocalCredentials() error: %v", err)
	}
	if err := a1.SetRemoteCredentials(a2Ufrag, a2Pwd); err != nil {
		t.Fatalf("a1 SetRemoteCredentials() error: %v", err)
	}
	if err := a2.SetRemoteCredentials(a1Ufrag, a1Pwd); err != nil {
		t.Fatalf("a2 SetRemoteCredentials() error: %v", err)
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

	if err := r1.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("a1 SetDeadline() error: %v", err)
	}
	if err := r2.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("a2 SetDeadline() error: %v", err)
	}
	wantAB := []byte("wink-a-to-b")
	if _, err := r1.conn.Write(wantAB); err != nil {
		t.Fatalf("a1 Write() error: %v", err)
	}
	gotAB := make([]byte, len(wantAB))
	if _, err := r2.conn.Read(gotAB); err != nil {
		t.Fatalf("a2 Read() error: %v", err)
	}
	if !bytes.Equal(gotAB, wantAB) {
		t.Fatalf("a2 payload = %q, want %q", gotAB, wantAB)
	}

	wantBA := []byte("wink-b-to-a")
	if _, err := r2.conn.Write(wantBA); err != nil {
		t.Fatalf("a2 Write() error: %v", err)
	}
	gotBA := make([]byte, len(wantBA))
	if _, err := r1.conn.Read(gotBA); err != nil {
		t.Fatalf("a1 Read() error: %v", err)
	}
	if !bytes.Equal(gotBA, wantBA) {
		t.Fatalf("a1 payload = %q, want %q", gotBA, wantBA)
	}

	connAgain, pairAgain, err := a1.Connect(ctx)
	if err != nil {
		t.Fatalf("a1 Connect() second call error: %v", err)
	}
	if connAgain != r1.conn {
		t.Fatal("a1 Connect() should reuse selected transport")
	}
	if pairAgain == nil || pairAgain.Local == nil || pairAgain.Remote == nil {
		t.Fatal("a1 second selected pair should be preserved")
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

	relayTypes := candidateTypesForConfig(ICEConfig{relayOnly: true})
	if len(relayTypes) != 1 || relayTypes[0] != pionice.CandidateTypeRelay {
		t.Fatalf("relay candidate types = %+v", relayTypes)
	}
}

func TestPublicDirectCandidateConfigSkipsRelayAndTURN(t *testing.T) {
	publicTypes := candidateTypesForConfig(ICEConfig{PublicDirectCandidate: true})
	if len(publicTypes) != 2 ||
		publicTypes[0] != pionice.CandidateTypeHost ||
		publicTypes[1] != pionice.CandidateTypeServerReflexive {
		t.Fatalf("public direct candidate types = %+v, want host and server reflexive", publicTypes)
	}

	urls, err := buildPionURLs(ICEConfig{
		PublicDirectCandidate: true,
		STUNServers:           []string{"stun:stun.example.com:3478"},
		TURNServers: []TURNServer{{
			URL:      "turn:turn.example.com:3478?transport=udp",
			Username: "wink",
			Password: "secret",
		}},
	})
	if err != nil {
		t.Fatalf("buildPionURLs(public direct) error = %v", err)
	}
	if len(urls) != 1 || urls[0].Scheme != stun.SchemeTypeSTUN {
		t.Fatalf("public direct URLs = %+v, want only STUN URL", urls)
	}

	checkInterval := checkIntervalForConfig(ICEConfig{PublicDirectCandidate: true})
	if checkInterval == nil || *checkInterval != publicDirectCheckInterval {
		t.Fatalf("public direct check interval = %v, want %v", checkInterval, publicDirectCheckInterval)
	}
	maxRequests := maxBindingRequestsForConfig(ICEConfig{PublicDirectCandidate: true})
	if maxRequests == nil || *maxRequests != publicDirectMaxBindingRequests {
		t.Fatalf("public direct max binding requests = %v, want %d", maxRequests, publicDirectMaxBindingRequests)
	}
	acceptanceWait := acceptanceMinWaitForConfig(ICEConfig{PublicDirectCandidate: true})
	if acceptanceWait == nil || *acceptanceWait != publicDirectAcceptanceMinWait {
		t.Fatalf("public direct acceptance wait = %v, want %v", acceptanceWait, publicDirectAcceptanceMinWait)
	}

	relayTypes := candidateTypesForConfig(ICEConfig{PublicDirectCandidate: true, ForceRelay: true})
	if len(relayTypes) != 1 || relayTypes[0] != pionice.CandidateTypeRelay {
		t.Fatalf("force relay candidate types = %+v, want relay override", relayTypes)
	}
	if checkInterval := checkIntervalForConfig(ICEConfig{PublicDirectCandidate: true, ForceRelay: true}); checkInterval != nil {
		t.Fatalf("force relay check interval = %v, want nil", checkInterval)
	}
	if maxRequests := maxBindingRequestsForConfig(ICEConfig{PublicDirectCandidate: true, ForceRelay: true}); maxRequests != nil {
		t.Fatalf("force relay max binding requests = %v, want nil", maxRequests)
	}
	if acceptanceWait := acceptanceMinWaitForConfig(ICEConfig{PublicDirectCandidate: true, ForceRelay: true}); acceptanceWait != nil {
		t.Fatalf("force relay acceptance wait = %v, want nil", acceptanceWait)
	}
	if checkInterval := checkIntervalForConfig(ICEConfig{}); checkInterval != nil {
		t.Fatalf("default check interval = %v, want nil", checkInterval)
	}
	if maxRequests := maxBindingRequestsForConfig(ICEConfig{}); maxRequests != nil {
		t.Fatalf("default max binding requests = %v, want nil", maxRequests)
	}
	if acceptanceWait := acceptanceMinWaitForConfig(ICEConfig{}); acceptanceWait != nil {
		t.Fatalf("default acceptance wait = %v, want nil", acceptanceWait)
	}
}

func TestNAT1To1ConfigHelpers(t *testing.T) {
	cfg := ICEConfig{
		NAT1To1IPs:           []string{"203.0.113.10/192.168.0.10"},
		NAT1To1CandidateType: "srflx",
	}
	gotType, err := nat1To1CandidateTypeForConfig(cfg)
	if err != nil {
		t.Fatalf("nat1To1CandidateTypeForConfig() error = %v", err)
	}
	if gotType != pionice.CandidateTypeServerReflexive {
		t.Fatalf("nat1To1 candidate type = %v, want server reflexive", gotType)
	}
	gotIPs := nat1To1IPsForConfig(cfg)
	if len(gotIPs) != 1 || gotIPs[0] != "203.0.113.10/192.168.0.10" {
		t.Fatalf("nat1To1 IPs = %#v, want configured mapping", gotIPs)
	}

	cfg.ForceRelay = true
	gotType, err = nat1To1CandidateTypeForConfig(cfg)
	if err != nil {
		t.Fatalf("nat1To1CandidateTypeForConfig(force relay) error = %v", err)
	}
	if gotType != pionice.CandidateTypeUnspecified {
		t.Fatalf("force relay nat1To1 candidate type = %v, want unspecified", gotType)
	}
	if gotIPs := nat1To1IPsForConfig(cfg); gotIPs != nil {
		t.Fatalf("force relay nat1To1 IPs = %#v, want nil", gotIPs)
	}
}

func TestNAT1To1ConfigRejectsInvalidCandidateType(t *testing.T) {
	_, err := nat1To1CandidateTypeForConfig(ICEConfig{
		NAT1To1IPs:           []string{"203.0.113.10"},
		NAT1To1CandidateType: "relay",
	})
	if err == nil {
		t.Fatal("nat1To1CandidateTypeForConfig() error = nil, want invalid candidate type")
	}
}
