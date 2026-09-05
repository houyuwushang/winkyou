package probeio

import (
	"context"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

func TestWireGuardProductLeaseRejectsBindingAndMissingPromotionWithoutIO(t *testing.T) {
	for _, mode := range []string{"peer", "attempt", "generation", "target", "path", "profile", "consumer", "not-promoted", "consumer-crash"} {
		t.Run(mode, func(t *testing.T) {
			envelope, err := hardnatbudget.For(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
			if err != nil {
				t.Fatal(err)
			}
			attempt := newFakeLease(envelope.Cost.Resources)
			attempt.request.Operation, attempt.request.Cost = governor.OperationPrediction, envelope.Cost
			binding := productBinding(attempt, WireGuardProfilePredictiveEDM, WireGuardPredictivePath, targetA)
			lease, err := issueTransportLease(attempt, binding)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lease.Close() })
			if lease.Witness().Attached || lease.Witness().Adopted {
				t.Fatal("issuing the product lease performed a handoff")
			}
			packets := newWireGuardGateTransport()
			t.Cleanup(func() { _ = packets.Close() })
			if mode != "not-promoted" {
				if err := lease.attach(Promotion{PeerID: binding.PeerID, AttemptID: binding.AttemptID,
					Generation: binding.Generation, Target: binding.Target, Transport: packets}); err != nil {
					t.Fatal(err)
				}
			}
			candidate := binding
			switch mode {
			case "peer":
				candidate.PeerID += "-wrong"
			case "attempt":
				candidate.AttemptID += "-wrong"
			case "generation":
				candidate.Generation++
			case "target":
				candidate.Target = targetB
			case "path":
				candidate.PathID = WireGuardAsymmetricPath
			case "profile":
				candidate.Profile = WireGuardProfileAsymmetricBirthday
			case "consumer":
				candidate.ConsumerKind = GateB2TestConsumer
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			gate, adoptErr := lease.AdoptWireGuardSession(ctx, candidate, WireGuardInitiator, time.Now().Add(time.Second))
			if mode == "consumer-crash" {
				if adoptErr != nil || gate == nil {
					t.Fatal("standby consumer was not created")
				}
				if err := gate.Close(); err != nil || !packets.isClosed() {
					t.Fatal("standby consumer death did not close its sole transport")
				}
			} else if adoptErr == nil || gate != nil || lease.Witness().Adopted {
				t.Fatal("invalid product adoption granted a consumer")
			}
			if mode == "not-promoted" && !lease.Witness().Closed {
				t.Fatal("adopt timeout did not consume the inactive lease")
			}
			if packets.writeCount() != 0 || lease.Witness().AttemptDetached {
				t.Fatal("failed handoff emitted or released the unfinished attempt")
			}
		})
	}
}
