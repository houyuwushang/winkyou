package legacyice

import (
	"testing"

	"winkyou/pkg/solver"
)

func TestRelevantObservationForSessionFiltersCorrectly(t *testing.T) {
	input := solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
	}

	tests := []struct {
		name string
		obs  solver.Observation
		want bool
	}{
		{
			name: "matching session and peer",
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-b",
				},
			},
			want: true,
		},
		{
			name: "wrong session",
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-x/node-y",
					"peer_id":    "node-b",
				},
			},
			want: false,
		},
		{
			name: "wrong peer",
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-x",
				},
			},
			want: false,
		},
		{
			name: "wrong strategy",
			obs: solver.Observation{
				Strategy: "other_strategy",
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-b",
				},
			},
			want: false,
		},
		{
			name: "no details",
			obs: solver.Observation{
				Strategy: StrategyName,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relevantObservationForSession(input, tt.obs)
			if got != tt.want {
				t.Fatalf("relevantObservationForSession() = %v, want %v", got, tt.want)
			}
		})
	}
}
