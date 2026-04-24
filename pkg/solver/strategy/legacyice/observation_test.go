package legacyice

import (
	"testing"

	"winkyou/pkg/solver"
)

func TestRelevantObservationForInputScopesLocalAndRemoteEvidence(t *testing.T) {
	input := solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
	}

	tests := []struct {
		name     string
		source   observationSource
		obs      solver.Observation
		wantOK   bool
		wantPrune bool
	}{
		{
			name:   "local matching session and remote peer",
			source: observationSourceLocal,
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-b",
				},
			},
			wantOK:    true,
			wantPrune: true,
		},
		{
			name:   "remote matching session and local peer",
			source: observationSourceRemote,
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-a",
				},
			},
			wantOK:    true,
			wantPrune: true,
		},
		{
			name:   "wrong session",
			source: observationSourceLocal,
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-x/node-y",
					"peer_id":    "node-b",
				},
			},
			wantOK: false,
		},
		{
			name:   "local wrong peer",
			source: observationSourceLocal,
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-x",
				},
			},
			wantOK: false,
		},
		{
			name:   "remote peer id is from remote perspective",
			source: observationSourceRemote,
			obs: solver.Observation{
				Strategy: StrategyName,
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-b",
				},
			},
			wantOK: false,
		},
		{
			name:   "wrong strategy",
			source: observationSourceLocal,
			obs: solver.Observation{
				Strategy: "other_strategy",
				Details: map[string]string{
					"session_id": "session/node-a/node-b",
					"peer_id":    "node-b",
				},
			},
			wantOK: false,
		},
		{
			name:   "no details is weak evidence only",
			source: observationSourceLocal,
			obs: solver.Observation{
				Strategy: StrategyName,
			},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := relevantObservationForInput(input, tt.obs, tt.source)
			if ok != tt.wantOK {
				t.Fatalf("relevantObservationForInput() ok = %v, want %v", ok, tt.wantOK)
			}
			if got.CanDrivePruning != tt.wantPrune {
				t.Fatalf("CanDrivePruning = %v, want %v", got.CanDrivePruning, tt.wantPrune)
			}
		})
	}
}
