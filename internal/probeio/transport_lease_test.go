package probeio

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
)

const gateATestPath = "gate-a/easy-direct"

func TestPromoteToLeaseRetainsAttemptAndPoisonsProbeHandles(t *testing.T) {
	harness := newHarness(t, normalResources())
	winner, datagram := openSocket(t, harness)
	sibling, siblingDatagram := openSocket(t, harness)
	if err := winner.RegisterTarget(targetA); err != nil {
		t.Fatalf("register winner: %v", err)
	}
	if err := sibling.RegisterTarget(targetB); err != nil {
		t.Fatalf("register sibling: %v", err)
	}
	diagram := []byte("verified-direct")
	datagram.queueRead(diagram, targetA)
	if _, _, err := winner.ReceiveReply(context.Background(), make([]byte, 64), func(packet []byte, _ netip.AddrPort) error {
		if string(packet) != string(diagram) {
			return errors.New("unexpected authenticated packet")
		}
		return nil
	}); err != nil {
		t.Fatalf("verify direct target: %v", err)
	}

	binding := TransportLeaseBinding{
		PeerID: harness.lease.PeerID(), AttemptID: harness.lease.Request().ID, Generation: 7,
		PathID: gateATestPath, Target: targetA, ConsumerKind: GateATestConsumer,
	}
	lease, err := issueTransportLease(harness.lease, binding)
	if err != nil {
		t.Fatalf("issue transport lease: %v", err)
	}
	if err := winner.PromoteToLease(targetA, gateATestPath, lease); err != nil {
		t.Fatalf("promote to lease: %v", err)
	}
	if datagram.isClosed() {
		t.Fatal("promote closed transferred datagram")
	}
	if !siblingDatagram.isClosed() {
		t.Fatal("promote did not close sibling")
	}
	if err := winner.SendProbe(context.Background(), targetA, []byte("old")); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("old ProbeSocket write = %v, want ErrLeaseClosed", err)
	}
	if _, err := harness.controller.OpenProbeSocket(context.Background()); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("old Controller open = %v, want ErrLeaseClosed", err)
	}
	select {
	case <-harness.lease.Stopping():
		t.Fatal("PromoteToLease released attempt before durable FINISH")
	default:
	}

	owned, err := lease.Adopt(context.Background(), binding)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if err := lease.MarkStandby(); err != nil {
		t.Fatalf("mark standby: %v", err)
	}
	if err := owned.WritePacket(context.Background(), []byte("challenge")); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	datagram.queueRead([]byte("answer"), targetA)
	if _, _, err := owned.ReadPacket(context.Background(), make([]byte, 32)); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if err := lease.MarkChallengePassed(); err != nil {
		t.Fatalf("mark challenge: %v", err)
	}
	if err := lease.DetachAfterFinish(); err != nil {
		t.Fatalf("detach after simulated FINISH: %v", err)
	}
	if err := harness.controller.Close(); err != nil {
		t.Fatalf("release attempt: %v", err)
	}
	select {
	case <-harness.lease.Done():
	case <-time.After(time.Second):
		t.Fatal("attempt did not release after detach")
	}
	if datagram.isClosed() {
		t.Fatal("attempt release closed independently owned transport")
	}
	if err := owned.WritePacket(context.Background(), []byte("post-finish")); err != nil {
		t.Fatalf("independent transport write: %v", err)
	}
	if err := owned.Close(); err != nil {
		t.Fatalf("close owned transport: %v", err)
	}
	if !datagram.isClosed() {
		t.Fatal("transport close did not close datagram")
	}
	witness := lease.Witness()
	if witness.PacketsRead != 1 || witness.PacketsWritten != 2 || !witness.AttemptDetached ||
		!witness.DrainRegistered || !witness.Drained || !witness.Closed {
		t.Fatalf("witness = %+v", witness)
	}
}

func TestTransportLeaseBindingMismatchIsZeroHandoff(t *testing.T) {
	for _, name := range []string{"peer", "attempt", "generation", "target", "path"} {
		t.Run(name, func(t *testing.T) {
			harness := newHarness(t, normalResources())
			socket, datagram := openSocket(t, harness)
			if err := socket.RegisterTarget(targetA); err != nil {
				t.Fatalf("register: %v", err)
			}
			datagram.queueRead([]byte("verified"), targetA)
			if _, _, err := socket.ReceiveReply(context.Background(), make([]byte, 32), func([]byte, netip.AddrPort) error { return nil }); err != nil {
				t.Fatalf("verify: %v", err)
			}
			leaseAttempt := harness.lease
			binding := TransportLeaseBinding{
				PeerID: harness.lease.PeerID(), AttemptID: harness.lease.Request().ID, Generation: 7,
				PathID: gateATestPath, Target: targetA, ConsumerKind: GateATestConsumer,
			}
			target, path := targetA, gateATestPath
			switch name {
			case "peer":
				leaseAttempt = newFakeLease(normalResources())
				leaseAttempt.peerID = "peer-other"
				binding.PeerID = leaseAttempt.PeerID()
			case "attempt":
				leaseAttempt = newFakeLease(normalResources())
				leaseAttempt.request.ID = "attempt-other"
				binding.AttemptID = leaseAttempt.Request().ID
			case "generation":
				binding.Generation++
			case "target":
				binding.Target = targetB
			case "path":
				path = "gate-a/wrong"
			}
			lease, err := issueTransportLease(leaseAttempt, binding)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if err := socket.PromoteToLease(target, path, lease); !errors.Is(err, ErrTransportBinding) {
				t.Fatalf("mismatch = %v, want ErrTransportBinding", err)
			}
			if datagram.isClosed() {
				t.Fatal("binding precheck touched datagram")
			}
			if err := socket.SendProbe(context.Background(), targetA, []byte("still-probe")); err != nil {
				t.Fatalf("binding precheck poisoned socket: %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatalf("close lease: %v", err)
			}
			if err := harness.controller.Close(); err != nil {
				t.Fatalf("close attempt: %v", err)
			}
		})
	}

	harness := newHarness(t, normalResources())
	socket, _ := openSocket(t, harness)
	if err := socket.PromoteToLease(targetA, gateATestPath, nil); !errors.Is(err, ErrTransportLease) {
		t.Fatalf("nil destination = %v, want ErrTransportLease", err)
	}
}

func TestTransportLeaseRequiresReviewedConsumerAndClosesOnAttemptCancellation(t *testing.T) {
	lease := newFakeLease(normalResources())
	binding := TransportLeaseBinding{
		PeerID: lease.PeerID(), AttemptID: lease.Request().ID, Generation: 7,
		PathID: gateATestPath, Target: targetA, ConsumerKind: "unreviewed-consumer/1",
	}
	if _, err := issueTransportLease(lease, binding); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("unreviewed consumer = %v, want ErrTransportBinding", err)
	}
	binding.ConsumerKind = GateATestConsumer
	session, err := issueTransportLease(lease, binding)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	lease.mu.Lock()
	lease.startStoppingLocked()
	lease.mu.Unlock()
	select {
	case <-session.closed:
	case <-time.After(time.Second):
		t.Fatal("attempt cancellation did not close transport lease")
	}
	if witness := session.Witness(); !witness.Closed || !witness.Drained {
		t.Fatalf("cancellation witness = %+v", witness)
	}
}

func TestTransportLeaseAdoptTimeoutClosesLease(t *testing.T) {
	lease := newFakeLease(normalResources())
	binding := TransportLeaseBinding{
		PeerID: lease.PeerID(), AttemptID: lease.Request().ID, Generation: 7,
		PathID: gateATestPath, Target: targetA, ConsumerKind: GateATestConsumer,
	}
	session, err := issueTransportLease(lease, binding)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := session.Adopt(ctx, binding); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("adopt timeout = %v, want deadline", err)
	}
	if witness := session.Witness(); !witness.Closed || !witness.Drained {
		t.Fatalf("timeout witness = %+v", witness)
	}
}

func TestIssueTransportLeaseRejectsNonConnectAttempt(t *testing.T) {
	lease := newFakeLease(normalResources())
	lease.request.Operation = governor.OperationDiagnose
	binding := TransportLeaseBinding{
		PeerID: lease.PeerID(), AttemptID: lease.Request().ID, Generation: 7,
		PathID: gateATestPath, Target: targetA, ConsumerKind: GateATestConsumer,
	}
	if _, err := issueTransportLease(lease, binding); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("diagnostic lease = %v, want binding rejection", err)
	}
}

func TestGateB2TransportLeaseConsumerIsOperationSeparated(t *testing.T) {
	for _, operation := range []governor.Operation{governor.OperationPrediction, governor.OperationBirthday} {
		lease := newFakeLease(normalResources())
		lease.request.Operation = operation
		binding := TransportLeaseBinding{
			PeerID: lease.PeerID(), AttemptID: lease.Request().ID, Generation: 7,
			PathID: "gate-b2/frozen-plan", Target: targetA, ConsumerKind: GateB2TestConsumer,
		}
		session, err := issueTransportLease(lease, binding)
		if err != nil {
			t.Fatalf("%s Gate B2 lease = %v", operation, err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		binding.ConsumerKind = GateATestConsumer
		if _, err := issueTransportLease(lease, binding); !errors.Is(err, ErrTransportBinding) {
			t.Fatalf("%s accepted Gate A consumer = %v", operation, err)
		}
	}

	connect := newFakeLease(normalResources())
	binding := TransportLeaseBinding{
		PeerID: connect.PeerID(), AttemptID: connect.Request().ID, Generation: 7,
		PathID: "gate-b2/frozen-plan", Target: targetA, ConsumerKind: GateB2TestConsumer,
	}
	if _, err := issueTransportLease(connect, binding); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("connect_test accepted Gate B2 consumer = %v", err)
	}
}

func TestGateB3TransportLeaseRequiresExactCampaignReservation(t *testing.T) {
	lease := newFakeLease(governor.Resources{
		Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512,
	})
	lease.request.Operation = governor.OperationBirthday
	lease.request.Cost.Duration = 47 * time.Second
	lease.request.Cost.Heavyweight = true
	binding := TransportLeaseBinding{
		PeerID: lease.PeerID(), AttemptID: lease.Request().ID, Generation: 7,
		PathID: "gate-b3/hard_birthday_campaign/1", Target: netip.MustParseAddrPort("192.0.2.10:49152"),
		ConsumerKind: GateB3TestConsumer,
	}
	session, err := issueTransportLease(lease, binding)
	if err != nil {
		t.Fatalf("exact Gate B3 lease = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*fakeLease, *TransportLeaseBinding)
	}{
		{name: "lower cost", mutate: func(lease *fakeLease, _ *TransportLeaseBinding) { lease.request.Cost.Resources.Packets-- }},
		{name: "wrong path", mutate: func(_ *fakeLease, binding *TransportLeaseBinding) {
			binding.PathID = "gate-b2/hard_birthday_campaign/1"
		}},
		{name: "port outside universe", mutate: func(_ *fakeLease, binding *TransportLeaseBinding) {
			binding.Target = netip.MustParseAddrPort("192.0.2.10:49151")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := newFakeLease(lease.request.Cost.Resources)
			candidate.request.Operation = governor.OperationBirthday
			candidate.request.Cost = lease.request.Cost
			candidateBinding := binding
			test.mutate(candidate, &candidateBinding)
			if _, err := issueTransportLease(candidate, candidateBinding); !errors.Is(err, ErrTransportBinding) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
}
