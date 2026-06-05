package solver

import (
	"context"
	"fmt"
	"net"
	"testing"

	"winkyou/pkg/transport"
)

func TestMessageKindsAreGeneric(t *testing.T) {
	msg := Message{
		Kind:      MessageKindStrategy,
		Namespace: "legacyice",
		Type:      "offer",
		Payload:   []byte("payload"),
	}

	if msg.Kind != MessageKindStrategy {
		t.Fatalf("Kind = %q, want %q", msg.Kind, MessageKindStrategy)
	}
	if msg.Namespace != "legacyice" || msg.Type != "offer" {
		t.Fatalf("message namespace/type = %q/%q, want legacyice/offer", msg.Namespace, msg.Type)
	}
}

type mockTransport struct{}

func (m *mockTransport) ReadPacket(_ context.Context, _ []byte) (int, PacketMeta, error) {
	return 0, PacketMeta{}, nil
}
func (m *mockTransport) WritePacket(_ context.Context, _ []byte) error { return nil }
func (m *mockTransport) LocalAddr() net.Addr                           { return nil }
func (m *mockTransport) RemoteAddr() net.Addr                          { return nil }
func (m *mockTransport) Close() error                                  { return nil }

type PacketMeta = transport.PacketMeta

func TestScoreOutcome(t *testing.T) {
	tests := []struct {
		name     string
		outcome  CandidateOutcome
		wantZero bool
	}{
		{
			name: "failed outcome scores zero",
			outcome: CandidateOutcome{
				Err: fmt.Errorf("failed"),
			},
			wantZero: true,
		},
		{
			name: "nil result scores zero",
			outcome: CandidateOutcome{
				Result: nil,
			},
			wantZero: true,
		},
		{
			name:     "direct success scores positive",
			wantZero: false,
			outcome: CandidateOutcome{
				Result: &Result{
					Transport: &mockTransport{},
					Summary: PathSummary{
						PathID:         "path1",
						ConnectionType: "direct",
					},
				},
			},
		},
		{
			name:     "relay success scores positive",
			wantZero: false,
			outcome: CandidateOutcome{
				Result: &Result{
					Transport: &mockTransport{},
					Summary: PathSummary{
						PathID:         "path2",
						ConnectionType: "relay",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := ScoreOutcome(tt.outcome)
			if tt.wantZero && score != 0 {
				t.Errorf("ScoreOutcome() = %d, want 0", score)
			}
			if !tt.wantZero && score <= 0 {
				t.Errorf("ScoreOutcome() = %d, want > 0", score)
			}
		})
	}

	// Direct must score higher than relay
	directScore := ScoreOutcome(CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary:   PathSummary{PathID: "p1", ConnectionType: "direct"},
		},
	})
	relayScore := ScoreOutcome(CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary:   PathSummary{PathID: "p2", ConnectionType: "relay"},
		},
	})
	if directScore <= relayScore {
		t.Errorf("direct score (%d) should be > relay score (%d)", directScore, relayScore)
	}
}

func TestScoreOutcomeWithPolicyKeepsDefaultWhenDisabled(t *testing.T) {
	outcome := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "relay/path",
				ConnectionType: "relay",
				Dependencies:   []PathDependency{{Kind: PathDependencyRelay}},
				Metrics:        map[string]string{"rtt_ms": "1"},
			},
		},
	}
	if got, want := ScoreOutcomeWithPolicy(outcome, PathPolicy{}), ScoreOutcome(outcome); got != want {
		t.Fatalf("ScoreOutcomeWithPolicy disabled = %d, want default %d", got, want)
	}
}

func TestScoreOutcomeWithPolicyLowLatencyRelayCanBeatDirect(t *testing.T) {
	policy := PathPolicy{
		MultipathEnabled:      true,
		ProtectDirect:         true,
		DependencyPenalty:     50,
		DirectProtectionBonus: 100,
	}
	relay := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "relay/path",
				ConnectionType: "relay",
				Dependencies:   []PathDependency{{Kind: PathDependencyRelay}},
				Metrics:        map[string]string{"rtt_ms": "1"},
			},
		},
	}
	direct := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "direct/path",
				ConnectionType: "direct",
				Role:           PathRoleProtectedDirect,
				Metrics:        map[string]string{"rtt_ms": "400"},
			},
		},
	}
	if relayScore, directScore := ScoreOutcomeWithPolicy(relay, policy), ScoreOutcomeWithPolicy(direct, policy); relayScore <= directScore {
		t.Fatalf("policy scores relay=%d direct=%d, want low-latency relay primary possible", relayScore, directScore)
	}
}

func TestScoreOutcomeWithPolicyDirectCanWin(t *testing.T) {
	policy := PathPolicy{
		MultipathEnabled:      true,
		ProtectDirect:         true,
		DependencyPenalty:     50,
		DirectProtectionBonus: 100,
	}
	relay := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "relay/path",
				ConnectionType: "relay",
				Dependencies:   []PathDependency{{Kind: PathDependencyRelay}},
				Metrics:        map[string]string{"rtt_ms": "90"},
			},
		},
	}
	direct := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "direct/path",
				ConnectionType: "direct",
				Role:           PathRoleProtectedDirect,
				Metrics:        map[string]string{"rtt_ms": "20"},
			},
		},
	}
	if directScore, relayScore := ScoreOutcomeWithPolicy(direct, policy), ScoreOutcomeWithPolicy(relay, policy); directScore <= relayScore {
		t.Fatalf("policy scores direct=%d relay=%d, want direct primary when better", directScore, relayScore)
	}
}

func TestScoreOutcomeWithPolicyDoesNotBonusDependentDirectLikePath(t *testing.T) {
	policy := PathPolicy{
		MultipathEnabled:      true,
		ProtectDirect:         true,
		DependencyPenalty:     50,
		DirectProtectionBonus: 100,
	}
	plainDirect := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "direct/path",
				ConnectionType: "direct",
				Role:           PathRoleProtectedDirect,
			},
		},
	}
	dependentDirect := CandidateOutcome{
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "overlay/path",
				ConnectionType: "direct",
				Role:           PathRolePrimaryCandidate,
				Dependencies: []PathDependency{{
					Kind:   PathDependencyUnknown,
					Reason: "remote_cgnat_or_overlay_candidate",
				}},
			},
		},
	}
	if protectedScore, dependentScore := ScoreOutcomeWithPolicy(plainDirect, policy), ScoreOutcomeWithPolicy(dependentDirect, policy); protectedScore <= dependentScore {
		t.Fatalf("policy scores protected=%d dependent=%d, want protected direct bonus only for independent path", protectedScore, dependentScore)
	}
}

func TestSelectBestOutcome(t *testing.T) {
	directOutcome := CandidateOutcome{
		Plan: Plan{ID: "direct"},
		Result: &Result{
			Transport: &mockTransport{},
			Summary:   PathSummary{PathID: "path1", ConnectionType: "direct"},
		},
	}
	relayOutcome := CandidateOutcome{
		Plan: Plan{ID: "relay"},
		Result: &Result{
			Transport: &mockTransport{},
			Summary:   PathSummary{PathID: "path2", ConnectionType: "relay"},
		},
	}
	failedOutcome := CandidateOutcome{
		Plan: Plan{ID: "failed"},
		Err:  fmt.Errorf("connection failed"),
	}

	tests := []struct {
		name     string
		outcomes []CandidateOutcome
		wantID   string
		wantNil  bool
	}{
		{
			name:     "empty outcomes returns nil",
			outcomes: []CandidateOutcome{},
			wantNil:  true,
		},
		{
			name:     "all failed returns nil",
			outcomes: []CandidateOutcome{failedOutcome},
			wantNil:  true,
		},
		{
			name:     "direct wins over relay",
			outcomes: []CandidateOutcome{relayOutcome, directOutcome},
			wantID:   "direct",
		},
		{
			name:     "relay wins when direct fails",
			outcomes: []CandidateOutcome{failedOutcome, relayOutcome},
			wantID:   "relay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			best := SelectBestOutcome(tt.outcomes)
			if tt.wantNil {
				if best != nil {
					t.Errorf("SelectBestOutcome() = %v, want nil", best)
				}
				return
			}
			if best == nil {
				t.Fatal("SelectBestOutcome() = nil, want non-nil")
			}
			if best.Plan.ID != tt.wantID {
				t.Errorf("SelectBestOutcome().Plan.ID = %s, want %s", best.Plan.ID, tt.wantID)
			}
		})
	}
}

func TestSelectBestOutcomePrefersProtectedDirectTie(t *testing.T) {
	dependentDirect := CandidateOutcome{
		Plan: Plan{ID: "legacyice/direct_prefer"},
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "legacyice:direct:session/node-a/node-b",
				ConnectionType: "direct",
				Role:           PathRolePrimaryCandidate,
				Dependencies: []PathDependency{{
					Kind:   PathDependencyUnknown,
					Reason: "remote_cgnat_or_overlay_candidate",
				}},
			},
		},
	}
	protectedDirect := CandidateOutcome{
		Plan: Plan{ID: "legacyice/public_direct"},
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "legacyice:direct:public_direct:session/node-a/node-b",
				ConnectionType: "direct",
				Role:           PathRoleProtectedDirect,
			},
		},
	}

	if ScoreOutcome(dependentDirect) != ScoreOutcome(protectedDirect) {
		t.Fatalf("test setup expected equal base scores, got dependent=%d protected=%d", ScoreOutcome(dependentDirect), ScoreOutcome(protectedDirect))
	}
	best := SelectBestOutcome([]CandidateOutcome{dependentDirect, protectedDirect})
	if best == nil || best.Plan.ID != "legacyice/public_direct" {
		t.Fatalf("SelectBestOutcome() = %#v, want public_direct protected path", best)
	}
}

func TestSelectBestOutcomeWithPolicyPrefersProtectedDirectTie(t *testing.T) {
	dependentDirect := CandidateOutcome{
		Plan: Plan{ID: "legacyice/direct_prefer"},
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "legacyice:direct:session/node-a/node-b",
				ConnectionType: "direct",
				Role:           PathRolePrimaryCandidate,
				Dependencies: []PathDependency{{
					Kind:   PathDependencyUnknown,
					Reason: "remote_cgnat_or_overlay_candidate",
				}},
			},
		},
	}
	protectedDirect := CandidateOutcome{
		Plan: Plan{ID: "legacyice/public_direct"},
		Result: &Result{
			Transport: &mockTransport{},
			Summary: PathSummary{
				PathID:         "legacyice:direct:public_direct:session/node-a/node-b",
				ConnectionType: "direct",
				Role:           PathRoleProtectedDirect,
			},
		},
	}
	policy := PathPolicy{MultipathEnabled: true, ProtectDirect: true}

	if ScoreOutcomeWithPolicy(dependentDirect, policy) != ScoreOutcomeWithPolicy(protectedDirect, policy) {
		t.Fatalf("test setup expected equal policy scores, got dependent=%d protected=%d", ScoreOutcomeWithPolicy(dependentDirect, policy), ScoreOutcomeWithPolicy(protectedDirect, policy))
	}
	best := SelectBestOutcomeWithPolicy([]CandidateOutcome{dependentDirect, protectedDirect}, policy)
	if best == nil || best.Plan.ID != "legacyice/public_direct" {
		t.Fatalf("SelectBestOutcomeWithPolicy() = %#v, want public_direct protected path", best)
	}
}

func TestDefaultBudget(t *testing.T) {
	budget := DefaultBudget()
	if budget.MaxCandidates <= 0 {
		t.Errorf("DefaultBudget().MaxCandidates = %d, want > 0", budget.MaxCandidates)
	}
	if budget.TimeBudget <= 0 {
		t.Errorf("DefaultBudget().TimeBudget = %v, want > 0", budget.TimeBudget)
	}
}
