package gateb

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
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

func TestGateB2ProductionDefaultCannotAcquireNonLoopbackAuthority(t *testing.T) {
	topology := hardnatobserve.Topology{
		Primary: netip.MustParseAddrPort("198.51.100.2:3478"),
		Other:   netip.MustParseAddrPort("203.0.113.1:3479"),
	}
	if _, err := validateTopology(topology, topologyLoopback); err == nil {
		t.Fatal("default topology accepted non-loopback observer targets")
	}
	runtime := &runtime{config: Config{ObserverTopology: topology}}
	if _, err := runtime.probeFactory(); err == nil {
		t.Fatal("default factory constructed a non-loopback UDP capability")
	}

	raw, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.MustParseAddrPort("0.0.0.0:0"), AllowedTargetScope: probeio.AllowedTargetScopeUnicast,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime.config.ProbeFactory = raw
	if _, err := runtime.probeFactory(); err == nil {
		t.Fatal("generic harness seam accepted a raw unicast OS factory")
	}

	runtime.config.ProbeFactory = nil
	if err := runtime.validateExecutionAddresses(
		hardnatplan.Address4([4]byte{127, 0, 0, 1}),
		hardnatplan.Address4([4]byte{198, 51, 100, 20}),
	); err == nil {
		t.Fatal("peer SourcePayload selected a non-loopback production target")
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
