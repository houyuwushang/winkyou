package solver

import (
	"context"
	"fmt"
	"net"
	"testing"
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
func (m *mockTransport) LocalAddr() net.Addr                          { return nil }
func (m *mockTransport) RemoteAddr() net.Addr                         { return nil }
func (m *mockTransport) Close() error                                 { return nil }

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

func TestDefaultBudget(t *testing.T) {
	budget := DefaultBudget()
	if budget.MaxCandidates <= 0 {
		t.Errorf("DefaultBudget().MaxCandidates = %d, want > 0", budget.MaxCandidates)
	}
	if budget.TimeBudget <= 0 {
		t.Errorf("DefaultBudget().TimeBudget = %v, want > 0", budget.TimeBudget)
	}
}
