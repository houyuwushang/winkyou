package gateb

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"winkyou/internal/governor"
)

func TestFrozenProgressAndStableFailureClasses(t *testing.T) {
	wantProgress := []string{
		StagePreflight, StageOOBAdopt, StagePresent, StageBurned, StageActivated,
		StageHandshake, StagePrepare, StageSockets, StageEvidence, StagePlan,
		StageReady, StageFire, StageCandidates, StageWinner, StageVerify,
		StageTransportLease, StageHandoff, StageDataPlaneChallenge, StageTerminal,
	}
	if !reflect.DeepEqual(ProgressSequence, wantProgress) {
		t.Fatalf("progress=%v, want=%v", ProgressSequence, wantProgress)
	}
	wantClasses := []string{
		ClassProfileUnsupported, ClassEvidenceInsufficient, ClassEvidenceDrifted,
		ClassPlanMismatch, ClassInsufficientBudget, ClassCandidateExhausted,
		ClassCampaignRateLimited, ClassCampaignCircuitOpen, ClassPacketRejected,
	}
	if !reflect.DeepEqual(StableFailureClasses, wantClasses) {
		t.Fatalf("classes=%v, want=%v", StableFailureClasses, wantClasses)
	}
}

func TestPersistentAdmissionFailuresKeepDistinctStableClasses(t *testing.T) {
	for _, test := range []struct {
		name  string
		cause error
		class string
	}{
		{name: "rolling window", cause: governor.ErrPairingAdmissionRateLimited, class: ClassCampaignRateLimited},
		{name: "persistent circuit", cause: governor.ErrPairingAdmissionCircuitOpen, class: ClassCampaignCircuitOpen},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := preflightFailure(test.cause)
			var stable *Failure
			if !errors.As(failure, &stable) || stable.Class != test.class || stable.Stage != StagePreflight ||
				stable.CredentialBurned || stable.Retryable {
				t.Fatalf("failure=%+v", stable)
			}
			encoded, err := json.Marshal(stable)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if _, leaked := fields["cause"]; leaked || len(fields) != 4 {
				t.Fatalf("stable error schema=%s", encoded)
			}
		})
	}
}
