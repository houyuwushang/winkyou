package probeio

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/pkg/transport"
)

func TestWireGuardProductConsumerMatchesFrozenGateBBudgets(t *testing.T) {
	tests := []struct {
		name     string
		profile  hardnatplan.Profile
		resource hardnatplan.ResourceClass
		path     string
		target   netip.AddrPort
	}{
		{"predictive", hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, WireGuardPredictivePath, targetA},
		{"asymmetric", hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, WireGuardAsymmetricPath, targetA},
		{"hard16", hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab, WireGuardHardBirthdayPath, netip.MustParseAddrPort("192.0.2.10:50000")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, err := hardnatbudget.For(test.profile, test.resource)
			if err != nil {
				t.Fatal(err)
			}
			operation, err := hardnatbudget.Operation(test.profile)
			if err != nil {
				t.Fatal(err)
			}
			attempt := newFakeLease(envelope.Cost.Resources)
			attempt.request.Operation = operation
			attempt.request.Cost = envelope.Cost
			binding := productBinding(attempt, string(test.profile), test.path, test.target)
			lease, err := issueTransportLease(attempt, binding)
			if err != nil {
				t.Fatalf("exact product lease = %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}

			mutations := []struct {
				name string
				edit func(*fakeLease, *TransportLeaseBinding)
			}{
				{"lower cost", func(a *fakeLease, _ *TransportLeaseBinding) { a.request.Cost.Resources.Packets-- }},
				{"wrong operation", func(a *fakeLease, _ *TransportLeaseBinding) { a.request.Operation = governor.OperationConnectTest }},
				{"test path", func(_ *fakeLease, b *TransportLeaseBinding) { b.PathID = "gate-b2/" + b.Profile }},
				{"test consumer", func(_ *fakeLease, b *TransportLeaseBinding) { b.ConsumerKind = GateB2TestConsumer }},
				{"missing profile", func(_ *fakeLease, b *TransportLeaseBinding) { b.Profile = "" }},
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					candidate := newFakeLease(envelope.Cost.Resources)
					candidate.request.Operation = operation
					candidate.request.Cost = envelope.Cost
					candidateBinding := productBinding(candidate, string(test.profile), test.path, test.target)
					mutation.edit(candidate, &candidateBinding)
					if _, err := issueTransportLease(candidate, candidateBinding); !errors.Is(err, ErrTransportBinding) {
						t.Fatalf("mutation lease = %v, want ErrTransportBinding", err)
					}
				})
			}
		})
	}
}

func TestWireGuardSessionGateOptionBTraceGoldenAndActivation(t *testing.T) {
	initiatorGate, initiatorTransport, initiatorLease := newWireGuardGate(t, WireGuardInitiator)
	if err := beginReadyChallenge(initiatorGate, initiatorTransport); err != nil {
		t.Fatal(err)
	}
	if err := initiatorGate.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation)); err != nil {
		t.Fatal(err)
	}
	initiatorTransport.queueRead(wireGuardPacket(WireGuardHandshakeResponse))
	if _, _, err := initiatorGate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	if err := initiatorGate.WritePacket(context.Background(), wireGuardPacket(WireGuardTransportData)); err != nil {
		t.Fatal(err)
	}
	if err := initiatorGate.CompleteChallenge(); err != nil {
		t.Fatal(err)
	}
	finishCalls := 0
	initiatorTransport.queueRead(fakeConsumerFinishedFrame())
	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), time.Second)
	defer sessionCancel()
	if err := initiatorGate.FinishAndActivate(sessionCtx, func() error {
		finishCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if finishCalls != 1 {
		t.Fatalf("FINISH calls = %d, want 1", finishCalls)
	}
	if err := initiatorGate.WritePacket(context.Background(), []byte("post-finish-wireguard")); err != nil {
		t.Fatalf("active write = %v", err)
	}
	initiatorTransport.queueRead([]byte("post-finish-wireguard"))
	if _, _, err := initiatorGate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatalf("active read = %v", err)
	}
	initiatorWitness := initiatorGate.Witness()
	if initiatorWitness.State != WireGuardGateActive || !initiatorWitness.FinishRecorded ||
		!initiatorWitness.AttemptDetached || initiatorWitness.ActiveWrites != 1 || initiatorWitness.ActiveReads != 1 {
		t.Fatalf("initiator witness = %+v", initiatorWitness)
	}
	if witness := initiatorLease.Witness(); !witness.ChallengePassed || !witness.AttemptDetached {
		t.Fatalf("lease witness = %+v", witness)
	}

	responderGate, responderTransport, _ := newWireGuardGate(t, WireGuardResponder)
	if err := beginReadyChallenge(responderGate, responderTransport); err != nil {
		t.Fatal(err)
	}
	responderTransport.queueRead(wireGuardPacket(WireGuardHandshakeInitiation))
	if _, _, err := responderGate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	if err := responderGate.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeResponse)); err != nil {
		t.Fatal(err)
	}
	responderTransport.queueRead(wireGuardPacket(WireGuardTransportData))
	if _, _, err := responderGate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	if err := responderGate.CompleteChallenge(); err != nil {
		t.Fatal(err)
	}
	responderWitness := responderGate.Witness()

	golden := struct {
		Schema    string                      `json:"schema"`
		Initiator WireGuardSessionGateWitness `json:"initiator"`
		Responder WireGuardSessionGateWitness `json:"responder"`
	}{
		Schema:    "winkyou-gate-c-wireguard-option-b-trace/1",
		Initiator: traceOnly(initiatorWitness), Responder: traceOnly(responderWitness),
	}
	payload, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	want, err := os.ReadFile("testdata/wireguard_option_b_trace.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
	if !bytes.Equal(payload, want) {
		t.Fatalf("trace golden drifted\nwant:\n%s\ngot:\n%s", want, payload)
	}
}

func TestWireGuardSessionGateFourthWriteFailsBeforeUnderlyingIO(t *testing.T) {
	gate, underlying, _ := newWireGuardGate(t, WireGuardInitiator)
	if err := beginReadyChallenge(gate, underlying); err != nil {
		t.Fatal(err)
	}
	for _, messageType := range []WireGuardMessageType{
		WireGuardHandshakeInitiation, WireGuardTransportData,
	} {
		if err := gate.WritePacket(context.Background(), wireGuardPacket(messageType)); err != nil {
			t.Fatalf("write %d = %v", messageType, err)
		}
	}
	if err := gate.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation)); !errors.Is(err, ErrWireGuardGateLimit) {
		t.Fatalf("fourth write = %v, want ErrWireGuardGateLimit", err)
	}
	if got := underlying.writeCount(); got != WireGuardChallengePackets {
		t.Fatalf("underlying writes = %d, want %d", got, WireGuardChallengePackets)
	}
	if !underlying.isClosed() {
		t.Fatal("limit violation did not close transport")
	}
}

func TestWireGuardSessionGateRejectsCookieReplayAndWrongTrace(t *testing.T) {
	tests := []struct {
		name string
		run  func(*WireGuardSessionGate, *wireGuardGateTransport) error
	}{
		{"cookie", func(g *WireGuardSessionGate, _ *wireGuardGateTransport) error {
			return g.WritePacket(context.Background(), wireGuardPacket(WireGuardCookieReply))
		}},
		{"replay", func(g *WireGuardSessionGate, _ *wireGuardGateTransport) error {
			if err := g.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation)); err != nil {
				return err
			}
			return g.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation))
		}},
		{"wrong role trace", func(g *WireGuardSessionGate, tr *wireGuardGateTransport) error {
			if err := g.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeResponse)); err != nil {
				return err
			}
			tr.queueRead(wireGuardPacket(WireGuardHandshakeInitiation))
			if _, _, err := g.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
				return err
			}
			return g.CompleteChallenge()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate, underlying, _ := newWireGuardGate(t, WireGuardInitiator)
			if err := beginReadyChallenge(gate, underlying); err != nil {
				t.Fatal(err)
			}
			if err := test.run(gate, underlying); err == nil {
				t.Fatal("invalid challenge was accepted")
			}
		})
	}
}

func TestWireGuardSessionGateFinishFailureNeverUnlocks(t *testing.T) {
	gate, underlying, lease := newWireGuardGate(t, WireGuardInitiator)
	completeInitiatorChallenge(t, gate, underlying)
	sessionCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gate.FinishAndActivate(sessionCtx, func() error { return errors.New("durable store unavailable") }); err == nil {
		t.Fatal("FINISH failure was accepted")
	}
	witness := gate.Witness()
	if witness.State != WireGuardGateClosed || witness.FinishRecorded || witness.AttemptDetached {
		t.Fatalf("gate witness = %+v", witness)
	}
	if lease.Witness().AttemptDetached {
		t.Fatal("FINISH failure detached attempt")
	}
	if !underlying.isClosed() {
		t.Fatal("FINISH failure did not close transport")
	}
}

func TestWireGuardSessionGateOverridesBackgroundWithBoundedContext(t *testing.T) {
	gate, underlying, _ := newWireGuardGate(t, WireGuardInitiator)
	if err := beginReadyChallenge(gate, underlying); err != nil {
		t.Fatal(err)
	}
	if err := gate.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation)); err != nil {
		t.Fatal(err)
	}
	deadline, ok := underlying.lastWriteDeadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > WireGuardChallengeTimeout {
		t.Fatalf("underlying deadline = %v/%v", deadline, ok)
	}
}

func TestWireGuardSessionGateCallerReadPollTimeoutDoesNotCloseSession(t *testing.T) {
	gate, underlying, _ := newWireGuardGate(t, WireGuardInitiator)
	if err := beginReadyChallenge(gate, underlying); err != nil {
		t.Fatal(err)
	}
	pollCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, _, err := gate.ReadPacket(pollCtx, make([]byte, 256)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("poll = %v, want context deadline", err)
	}
	if underlying.isClosed() || gate.Witness().State != WireGuardGateChallengeCapped {
		t.Fatalf("ordinary caller poll closed gate: %+v", gate.Witness())
	}
	underlying.queueRead(wireGuardPacket(WireGuardHandshakeResponse))
	if _, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatalf("read after poll = %v", err)
	}
}

func TestWireGuardSessionGateDrainsWireGuardGoPendingReadBeforeChallengeCommit(t *testing.T) {
	gate, underlying, _ := newWireGuardGate(t, WireGuardInitiator)
	if err := beginReadyChallenge(gate, underlying); err != nil {
		t.Fatal(err)
	}
	if err := gate.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation)); err != nil {
		t.Fatal(err)
	}
	underlying.queueRead(wireGuardPacket(WireGuardHandshakeResponse))
	if _, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	if err := gate.WritePacket(context.Background(), wireGuardPacket(WireGuardTransportData)); err != nil {
		t.Fatal(err)
	}
	pendingDone := make(chan error, 1)
	go func() {
		_, _, err := gate.ReadPacket(context.Background(), make([]byte, 256))
		pendingDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		gate.mu.Lock()
		inFlight := gate.inFlight
		gate.mu.Unlock()
		if inFlight == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pending reader did not enter the gate")
		}
		time.Sleep(time.Millisecond)
	}
	if err := gate.CompleteChallenge(); err != nil {
		t.Fatalf("complete with pending read = %v", err)
	}
	select {
	case err := <-pendingDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("drained read = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending read did not drain")
	}
	if witness := gate.Witness(); witness.State != WireGuardGateChallengePassed || underlying.isClosed() {
		t.Fatalf("post-drain witness=%+v underlying closed=%v", witness, underlying.isClosed())
	}
}

func completeInitiatorChallenge(t *testing.T, gate *WireGuardSessionGate, underlying *wireGuardGateTransport) {
	t.Helper()
	if err := beginReadyChallenge(gate, underlying); err != nil {
		t.Fatal(err)
	}
	if err := gate.WritePacket(context.Background(), wireGuardPacket(WireGuardHandshakeInitiation)); err != nil {
		t.Fatal(err)
	}
	underlying.queueRead(wireGuardPacket(WireGuardHandshakeResponse))
	if _, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	if err := gate.WritePacket(context.Background(), wireGuardPacket(WireGuardTransportData)); err != nil {
		t.Fatal(err)
	}
	if err := gate.CompleteChallenge(); err != nil {
		t.Fatal(err)
	}
}

func newWireGuardGate(t *testing.T, role WireGuardRole) (*WireGuardSessionGate, *wireGuardGateTransport, *TransportLease) {
	t.Helper()
	envelope, err := hardnatbudget.For(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
	if err != nil {
		t.Fatal(err)
	}
	attempt := newFakeLease(envelope.Cost.Resources)
	attempt.request.Operation = governor.OperationPrediction
	attempt.request.Cost = envelope.Cost
	binding := productBinding(attempt, WireGuardProfilePredictiveEDM, WireGuardPredictivePath, targetA)
	lease, err := issueTransportLease(attempt, binding)
	if err != nil {
		t.Fatal(err)
	}
	underlying := newWireGuardGateTransport()
	if err := lease.attach(Promotion{
		PeerID: binding.PeerID, AttemptID: binding.AttemptID, Generation: binding.Generation,
		Target: binding.Target, Transport: underlying,
	}); err != nil {
		t.Fatal(err)
	}
	gate, err := lease.AdoptWireGuardSession(context.Background(), binding, role, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	return gate, underlying, lease
}

func productBinding(attempt *fakeLease, profile, path string, target netip.AddrPort) TransportLeaseBinding {
	return TransportLeaseBinding{
		PeerID: attempt.PeerID(), AttemptID: attempt.Request().ID, Generation: 1,
		PathID: path, Target: target, ConsumerKind: WireGuardDirectSessionConsumer, Profile: profile,
	}
}

func wireGuardPacket(messageType WireGuardMessageType) []byte {
	packet := make([]byte, 32)
	binary.LittleEndian.PutUint32(packet, uint32(messageType))
	return packet
}

func traceOnly(witness WireGuardSessionGateWitness) WireGuardSessionGateWitness {
	return WireGuardSessionGateWitness{
		ConsumerReady: witness.ConsumerReady, ReadinessWrites: witness.ReadinessWrites, ReadinessReads: witness.ReadinessReads,
		Outbound: append([]WireGuardMessageType(nil), witness.Outbound...),
		Inbound:  append([]WireGuardMessageType(nil), witness.Inbound...),
	}
}

type wireGuardGateTransport struct {
	mu             sync.Mutex
	writes         [][]byte
	writeDeadlines []time.Time
	reads          chan []byte
	closed         chan struct{}
	closeOnce      sync.Once
	peer           *wireGuardGateTransport
}

func newWireGuardGateTransport() *wireGuardGateTransport {
	return &wireGuardGateTransport{reads: make(chan []byte, 8), closed: make(chan struct{})}
}

func (underlying *wireGuardGateTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	select {
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-underlying.closed:
		return 0, transport.PacketMeta{}, net.ErrClosed
	case packet := <-underlying.reads:
		return copy(dst, packet), transport.PacketMeta{}, nil
	}
}

func (underlying *wireGuardGateTransport) WritePacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-underlying.closed:
		return net.ErrClosed
	default:
	}
	deadline, _ := ctx.Deadline()
	underlying.mu.Lock()
	underlying.writes = append(underlying.writes, append([]byte(nil), packet...))
	underlying.writeDeadlines = append(underlying.writeDeadlines, deadline)
	underlying.mu.Unlock()
	if underlying.peer != nil {
		select {
		case underlying.peer.reads <- append([]byte(nil), packet...):
		case <-ctx.Done():
			return ctx.Err()
		case <-underlying.closed:
			return net.ErrClosed
		}
	}
	return nil
}

func (underlying *wireGuardGateTransport) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:32000"))
}

func (underlying *wireGuardGateTransport) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:32001"))
}

func (underlying *wireGuardGateTransport) Close() error {
	underlying.closeOnce.Do(func() { close(underlying.closed) })
	return nil
}

func (underlying *wireGuardGateTransport) queueRead(packet []byte) {
	underlying.reads <- append([]byte(nil), packet...)
}

func (underlying *wireGuardGateTransport) writeCount() int {
	underlying.mu.Lock()
	defer underlying.mu.Unlock()
	return len(underlying.writes)
}

func (underlying *wireGuardGateTransport) lastWriteDeadline() (time.Time, bool) {
	underlying.mu.Lock()
	defer underlying.mu.Unlock()
	if len(underlying.writeDeadlines) == 0 {
		return time.Time{}, false
	}
	return underlying.writeDeadlines[len(underlying.writeDeadlines)-1], true
}

func (underlying *wireGuardGateTransport) isClosed() bool {
	select {
	case <-underlying.closed:
		return true
	default:
		return false
	}
}

var _ transport.PacketTransport = (*wireGuardGateTransport)(nil)

type fakeConsumerReadyCodec struct{}

func (fakeConsumerReadyCodec) Seal() ([]byte, error) {
	return make([]byte, consumerReadinessFrameBytes), nil
}
func (fakeConsumerReadyCodec) Open(frame []byte) error {
	if len(frame) != consumerReadinessFrameBytes {
		return ErrWireGuardGate
	}
	return nil
}
func (fakeConsumerReadyCodec) Close() error { return nil }

func fakeConsumerFinishedFrame() []byte {
	frame := make([]byte, consumerFinishedFrameBytes)
	copy(frame, "WYCF")
	return frame
}
func (fakeConsumerReadyCodec) SealFinish() ([]byte, error) { return fakeConsumerFinishedFrame(), nil }
func (fakeConsumerReadyCodec) OpenFinish(frame []byte) error {
	if !bytes.Equal(frame, fakeConsumerFinishedFrame()) {
		return ErrWireGuardGate
	}
	return nil
}

func beginReadyChallenge(gate *WireGuardSessionGate, underlying *wireGuardGateTransport) error {
	if err := gate.BeginChallenge(); err != nil {
		return err
	}
	underlying.queueRead(make([]byte, consumerReadinessFrameBytes))
	return gate.ConsumerReady(context.Background(), fakeConsumerReadyCodec{})
}

func TestConsumerReadyHoldsBinderReaderUntilBothLocalConsumersInstalled(t *testing.T) {
	left, leftIO, _ := newWireGuardGate(t, WireGuardInitiator)
	right, rightIO, _ := newWireGuardGate(t, WireGuardResponder)
	leftIO.peer, rightIO.peer = rightIO, leftIO
	if err := left.BeginChallenge(); err != nil {
		t.Fatal(err)
	}
	if err := right.BeginChallenge(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	leftDone := make(chan error, 1)
	go func() { leftDone <- left.ConsumerReady(ctx, fakeConsumerReadyCodec{}) }()
	// This is the AddPeer race: AttachTransport has started a binder reader,
	// but IpcSet has deliberately not returned on the responder yet.
	pollCtx, pollCancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer pollCancel()
	if _, _, err := right.ReadPacket(pollCtx, make([]byte, 256)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pre-install binder read = %v", err)
	}
	if leftIO.writeCount() != 1 || rightIO.writeCount() != 0 || len(rightIO.reads) != 1 ||
		len(left.Witness().Outbound) != 0 || len(right.Witness().Inbound) != 0 {
		t.Fatal("pre-install reader consumed readiness or WireGuard emitted early")
	}
	if err := right.ConsumerReady(ctx, fakeConsumerReadyCodec{}); err != nil {
		t.Fatal(err)
	}
	if err := <-leftDone; err != nil {
		t.Fatal(err)
	}
	for _, gate := range []*WireGuardSessionGate{left, right} {
		if witness := gate.Witness(); !witness.ConsumerReady || witness.ReadinessWrites != 1 || witness.ReadinessReads != 1 {
			t.Fatalf("readiness witness = %+v", witness)
		}
	}
}

func TestConsumerReadyNoHandshakeBeforeBarrierAndBoundedFailure(t *testing.T) {
	for _, mode := range []string{"early-write", "cancel", "deadline", "oversize", "writer-error"} {
		t.Run(mode, func(t *testing.T) {
			gate, underlying, _ := newWireGuardGate(t, WireGuardInitiator)
			if err := gate.BeginChallenge(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "early-write" {
				if err := gate.WritePacket(ctx, wireGuardPacket(WireGuardHandshakeInitiation)); err == nil {
					t.Fatal("early write accepted")
				}
				if underlying.writeCount() != 0 {
					t.Fatal("early write reached underlying")
				}
				return
			}
			switch mode {
			case "cancel":
				cancel()
			case "deadline":
				gate.challengeStop()
				gate.challengeCtx, gate.challengeStop = context.WithTimeout(gate.attemptCtx, 10*time.Millisecond)
			case "oversize":
				underlying.queueRead(make([]byte, consumerReadinessFrameBytes+1))
			case "writer-error":
				_ = underlying.Close()
			}
			start := time.Now()
			if err := gate.ConsumerReady(ctx, fakeConsumerReadyCodec{}); err == nil {
				t.Fatal("failure accepted")
			}
			if time.Since(start) > time.Second || !underlying.isClosed() || underlying.writeCount() > 1 {
				t.Fatal("failure did not stop and drain within its existing allowance")
			}
		})
	}
}
