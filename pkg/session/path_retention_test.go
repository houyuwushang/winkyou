package session

import (
	"testing"

	"winkyou/pkg/solver"
)

func TestCloseUnusedOutcomesClosesNonSelectedWhenPolicyDisabled(t *testing.T) {
	session := &Session{}
	selectedTransport := &fakeTransport{}
	directTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/path", selectedTransport, solver.PathSummary{PathID: "relay/path", ConnectionType: "relay"}),
		successfulOutcome("direct/path", directTransport, solver.PathSummary{PathID: "direct/path", ConnectionType: "direct", Role: solver.PathRoleProtectedDirect}),
	}
	selected := &outcomes[0]

	session.closeUnusedOutcomes(outcomes, selected, nil)

	if selectedTransport.closed {
		t.Fatal("selected transport was closed")
	}
	if !directTransport.closed {
		t.Fatal("non-selected direct transport was not closed")
	}
}

func TestRetainSuccessfulOutcomesKeepsProtectedDirectWhenPolicyEnabled(t *testing.T) {
	session := &Session{}
	selectedTransport := &fakeTransport{}
	directTransport := &fakeTransport{}
	otherTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/path", selectedTransport, solver.PathSummary{PathID: "relay/path", ConnectionType: "relay"}),
		successfulOutcome("direct/path", directTransport, solver.PathSummary{PathID: "direct/path", ConnectionType: "direct", Role: solver.PathRoleProtectedDirect}),
		successfulOutcome("other/path", otherTransport, solver.PathSummary{PathID: "other/path", ConnectionType: "relay"}),
	}
	selected := &outcomes[0]
	policy := solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2}

	retained := retainSuccessfulOutcomes(outcomes, selected, policy)
	if len(retained) != 1 || retained[0].Result.Summary.PathID != "direct/path" {
		t.Fatalf("retained = %#v, want direct/path", retained)
	}
	session.setRetainedOutcomes(retained)
	session.closeUnusedOutcomes(outcomes, selected, retained)

	if selectedTransport.closed {
		t.Fatal("selected transport was closed")
	}
	if directTransport.closed {
		t.Fatal("protected direct transport was closed")
	}
	if !otherTransport.closed {
		t.Fatal("unused relay transport was not closed")
	}

	session.closeRetainedOutcomes()
	if !directTransport.closed {
		t.Fatal("retained direct transport was not closed on retained cleanup")
	}
}

func TestRetainSuccessfulOutcomesDoesNotTreatDependentDirectAsProtected(t *testing.T) {
	selectedTransport := &fakeTransport{}
	dependentDirectTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/path", selectedTransport, solver.PathSummary{PathID: "relay/path", ConnectionType: "relay"}),
		successfulOutcome("overlay/path", dependentDirectTransport, solver.PathSummary{
			PathID:         "overlay/path",
			ConnectionType: "direct",
			Role:           solver.PathRolePrimaryCandidate,
			Dependencies: []solver.PathDependency{{
				Kind:   solver.PathDependencyUnknown,
				Reason: "remote_cgnat_or_overlay_candidate",
			}},
		}),
	}
	policy := solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2}

	if protected := selectProtectedDirectOutcome(outcomes, policy); protected != nil {
		t.Fatalf("protected direct = %#v, want nil for dependent direct-like path", protected)
	}
	retained := retainSuccessfulOutcomes(outcomes, &outcomes[0], policy)
	if len(retained) != 1 || retained[0].Result.Summary.PathID != "overlay/path" {
		t.Fatalf("retained = %#v, want generic standby retention for max_paths", retained)
	}
}

func TestSelectPrimaryOutcomeUsesPolicyScoring(t *testing.T) {
	relayTransport := &fakeTransport{}
	directTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/path", relayTransport, solver.PathSummary{
			PathID:         "relay/path",
			ConnectionType: "relay",
			Dependencies:   []solver.PathDependency{{Kind: solver.PathDependencyRelay}},
			Metrics:        map[string]string{"rtt_ms": "1"},
		}),
		successfulOutcome("direct/path", directTransport, solver.PathSummary{
			PathID:         "direct/path",
			ConnectionType: "direct",
			Role:           solver.PathRoleProtectedDirect,
			Metrics:        map[string]string{"rtt_ms": "400"},
		}),
	}
	policy := solver.PathPolicy{
		MultipathEnabled:      true,
		ProtectDirect:         true,
		MaxPaths:              2,
		DependencyPenalty:     50,
		DirectProtectionBonus: 100,
	}

	selected := selectPrimaryOutcome(outcomes, policy)
	if selected == nil || selected.Result.Summary.PathID != "relay/path" {
		t.Fatalf("selected primary = %#v, want relay/path", selected)
	}
	protected := selectProtectedDirectOutcome(outcomes, policy)
	if protected == nil || protected.Result.Summary.PathID != "direct/path" {
		t.Fatalf("protected direct = %#v, want direct/path", protected)
	}
}

func TestSelectPrimaryOutcomeKeepsOldScoringWithoutPolicy(t *testing.T) {
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/path", &fakeTransport{}, solver.PathSummary{PathID: "relay/path", ConnectionType: "relay"}),
		successfulOutcome("direct/path", &fakeTransport{}, solver.PathSummary{PathID: "direct/path", ConnectionType: "direct"}),
	}

	selected := selectPrimaryOutcome(outcomes, solver.PathPolicy{})
	if selected == nil || selected.Result.Summary.PathID != "direct/path" {
		t.Fatalf("selected primary = %#v, want direct/path under old scoring", selected)
	}
}

func successfulOutcome(pathID string, transport *fakeTransport, summary solver.PathSummary) solver.CandidateOutcome {
	return solver.CandidateOutcome{
		Plan:   solver.Plan{ID: pathID + "/plan"},
		PlanID: pathID + "/plan",
		PathID: pathID,
		Result: &solver.Result{
			Transport: transport,
			Summary:   summary,
		},
		Score: 100,
	}
}
