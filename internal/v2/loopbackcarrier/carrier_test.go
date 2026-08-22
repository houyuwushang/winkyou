package loopbackcarrier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/punchproto"
)

func TestRealLoopbackNoisePunchPromoteAndTerminalFinish(t *testing.T) {
	baseline := runtime.NumGoroutine()
	pair := runRealLoopbackPair(t, repeatedSecret(21), repeatedSecret(21), nil, 5*time.Second)
	for role, endpoint := range map[string]pairEndpoint{"initiator": pair.initiator, "responder": pair.responder} {
		if endpoint.err != nil {
			t.Fatalf("%s carrier: %v (peer errors initiator=%v responder=%v witness=%d/%d)", role, endpoint.err, pair.initiator.err, pair.responder.err, pair.witness.initiatorPackets.Load(), pair.witness.responderPackets.Load())
		}
		if err := endpoint.result.validate(); err != nil {
			t.Fatalf("%s result: %+v/%v", role, endpoint.result, err)
		}
		if endpoint.authorization.reason != governor.PairingTerminalSuccess || endpoint.authorization.finishAfterStopping {
			t.Fatalf("%s terminal ordering = reason %s after-stopping=%t", role, endpoint.authorization.reason, endpoint.authorization.finishAfterStopping)
		}
	}
	if pair.initiator.result.OutboundPackets != 3 || pair.responder.result.OutboundPackets != 2 {
		t.Fatalf("outbound results = %d/%d, want 3/2", pair.initiator.result.OutboundPackets, pair.responder.result.OutboundPackets)
	}
	if pair.witness.initiatorPackets.Load() != 3 || pair.witness.responderPackets.Load() != 2 {
		t.Fatalf("real UDP witness = %d/%d, want 3/2", pair.witness.initiatorPackets.Load(), pair.witness.responderPackets.Load())
	}
	if pair.witness.initiatorPackets.Load() > MaxOutboundPackets || pair.witness.responderPackets.Load() > MaxOutboundPackets {
		t.Fatal("real UDP witness exceeded the durable packet envelope")
	}
	assertEndpointReusable(t, pair.initiatorLocal)
	assertEndpointReusable(t, pair.responderLocal)
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if current := runtime.NumGoroutine(); current > baseline+2 {
		t.Fatalf("goroutine residue = baseline %d current %d", baseline, current)
	}
}

func TestRealLoopbackWrongPSKTamperAndReplayFailClosed(t *testing.T) {
	tests := []struct {
		name         string
		initiatorPSK [32]byte
		responderPSK [32]byte
		mutate       packetMutation
	}{
		{name: "wrong psk", initiatorPSK: repeatedSecret(31), responderPSK: repeatedSecret(32)},
		{name: "tamper", initiatorPSK: repeatedSecret(33), responderPSK: repeatedSecret(33), mutate: func(direction packetDirection, ordinal int, packet []byte) [][]byte {
			if direction == directionInitiatorToResponder && ordinal == 2 {
				packet[len(packet)-1] ^= 0x80
			}
			return [][]byte{packet}
		}},
		{name: "replay", initiatorPSK: repeatedSecret(34), responderPSK: repeatedSecret(34), mutate: func(direction packetDirection, ordinal int, packet []byte) [][]byte {
			if direction == directionInitiatorToResponder && ordinal == 2 {
				return [][]byte{append([]byte(nil), packet...), append([]byte(nil), packet...)}
			}
			return [][]byte{packet}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pair := runRealLoopbackPair(t, test.initiatorPSK, test.responderPSK, test.mutate, 750*time.Millisecond)
			if pair.initiator.err == nil && pair.responder.err == nil {
				t.Fatal("negative loopback attempt unexpectedly succeeded on both endpoints")
			}
			if pair.initiator.authorization.reason == governor.PairingTerminalSuccess && pair.responder.authorization.reason == governor.PairingTerminalSuccess {
				t.Fatal("negative loopback attempt recorded two successes")
			}
			if pair.witness.initiatorPackets.Load() > MaxOutboundPackets || pair.witness.responderPackets.Load() > MaxOutboundPackets {
				t.Fatalf("negative witness exceeded envelope: %d/%d", pair.witness.initiatorPackets.Load(), pair.witness.responderPackets.Load())
			}
			assertEndpointReusable(t, pair.initiatorLocal)
			assertEndpointReusable(t, pair.responderLocal)
		})
	}
}

func TestSocketReadyProgressFailureStopsBeforeFirstEmission(t *testing.T) {
	target := listenLoopback(t)
	defer target.Close()
	localHolder := listenLoopback(t)
	local := udpAddrPort(localHolder.LocalAddr())
	if err := localHolder.Close(); err != nil {
		t.Fatalf("release carrier endpoint: %v", err)
	}

	lease := newFakeAttemptLease("progress-failure-peer")
	defer lease.Close()
	authorization := &fakeAuthorization{lease: lease}
	carrier := &admittedCarrier{
		authorization: authorization,
		attempt:       lease,
		bundle:        testPreparedBundle(punchproto.RoleResponder, local, udpAddrPort(target.LocalAddr()), repeatedSecret(41)),
		buildVersion:  "loopback-progress-failure-test",
		progress: func(ProgressStage) error {
			return errors.New("progress sink unavailable")
		},
	}
	defer carrier.bundle.zeroize()

	result, err := carrier.run(context.Background())
	if err == nil || result != (Result{}) {
		t.Fatalf("progress failure result = %+v/%v, want zero result and error", result, err)
	}
	if authorization.first {
		t.Fatal("progress failure reached first-emission authorization")
	}
	if authorization.reason != governor.PairingTerminalCarrierError {
		t.Fatalf("terminal reason = %q, want carrier_error", authorization.reason)
	}
	buffer := make([]byte, 1)
	if err := target.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, readErr := target.ReadFromUDPAddrPort(buffer); readErr == nil {
		t.Fatal("progress failure emitted a UDP packet")
	}
	assertEndpointReusable(t, local)
}

type pairRun struct {
	initiator      pairEndpoint
	responder      pairEndpoint
	witness        *udpWitness
	initiatorLocal netip.AddrPort
	responderLocal netip.AddrPort
}

type pairEndpoint struct {
	result        Result
	err           error
	authorization *fakeAuthorization
}

func runRealLoopbackPair(t *testing.T, initiatorPSK, responderPSK [32]byte, mutate packetMutation, timeout time.Duration) pairRun {
	t.Helper()
	witness, initiatorLocal, responderLocal := newUDPTopology(t, mutate)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	witness.start(ctx)

	initiatorLease := newFakeAttemptLease("initiator-peer")
	responderLease := newFakeAttemptLease("responder-peer")
	initiatorAuthorization := &fakeAuthorization{lease: initiatorLease}
	responderAuthorization := &fakeAuthorization{lease: responderLease}
	initiatorCarrier := &admittedCarrier{
		authorization: initiatorAuthorization,
		attempt:       initiatorLease,
		bundle:        testPreparedBundle(punchproto.RoleInitiator, initiatorLocal, witness.initiatorProxy, initiatorPSK),
		buildVersion:  "loopback-carrier-test",
	}
	responderCarrier := &admittedCarrier{
		authorization: responderAuthorization,
		attempt:       responderLease,
		bundle:        testPreparedBundle(punchproto.RoleResponder, responderLocal, witness.responderProxy, responderPSK),
		buildVersion:  "loopback-carrier-test",
	}
	responderReady := make(chan struct{}, 1)
	responderCarrier.progress = func(stage ProgressStage) error {
		if stage == ProgressStageSocketReady {
			responderReady <- struct{}{}
		}
		return nil
	}

	responderDone := make(chan pairEndpoint, 1)
	go func() {
		result, err := responderCarrier.run(ctx)
		responderDone <- pairEndpoint{result: result, err: err, authorization: responderAuthorization}
	}()
	select {
	case <-responderReady:
	case <-time.After(2 * time.Second):
		t.Fatal("responder did not publish socket readiness")
	}
	initiatorDone := make(chan pairEndpoint, 1)
	go func() {
		result, err := initiatorCarrier.run(ctx)
		initiatorDone <- pairEndpoint{result: result, err: err, authorization: initiatorAuthorization}
	}()

	initiator := <-initiatorDone
	responder := <-responderDone
	cancel()
	witness.close()
	initiatorCarrier.bundle.zeroize()
	responderCarrier.bundle.zeroize()
	return pairRun{
		initiator: initiator, responder: responder, witness: witness,
		initiatorLocal: initiatorLocal, responderLocal: responderLocal,
	}
}

func testPreparedBundle(role punchproto.Role, local, peer netip.AddrPort, psk [32]byte) *preparedBundle {
	now := time.Now().UTC().Truncate(time.Second)
	context := pairingcontext.PairingContext{
		Artifact: pairingcontext.PairingArtifactAcceptance, Protocol: pairingcontext.ProtocolVersion, AuthScope: pairingcontext.AuthScope,
		CredentialID: testID(1), AttemptID: testID(2), ObservationGeneration: "1",
		InitiatorParticipantID: testID(3), ResponderParticipantID: testID(4),
		InitiatorGovernorScope: pairingcontext.GovernorScopeMachine, ResponderGovernorScope: pairingcontext.GovernorScopeMachine,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile,
		IssuedAt:             now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339),
		OfferFingerprint: testFingerprint(5), InitiatorChannelRole: pairingcontext.ChannelRoleInitiator,
		ResponderChannelRole: pairingcontext.ChannelRoleResponder, EarlyData: pairingcontext.FeatureDisabled,
		Resumption: pairingcontext.FeatureDisabled, RuntimeFallback: pairingcontext.FeatureDisabled,
	}
	return &preparedBundle{
		role: role, local: local, peer: peer, peerID: testID(4), credentialID: testID(1), attemptID: testID(2),
		expiresAt: now.Add(5 * time.Minute), context: context, psk: psk,
	}
}

func testFingerprint(seed byte) string {
	secret := repeatedSecret(seed)
	return base64RawURL(secret[:])
}

func base64RawURL(payload []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	encoded := make([]byte, (len(payload)*8+5)/6)
	var buffer uint32
	bits := 0
	output := 0
	for _, current := range payload {
		buffer = buffer<<8 | uint32(current)
		bits += 8
		for bits >= 6 {
			bits -= 6
			encoded[output] = alphabet[(buffer>>bits)&0x3f]
			output++
		}
	}
	if bits > 0 {
		encoded[output] = alphabet[(buffer<<(6-bits))&0x3f]
	}
	return string(encoded)
}

type packetDirection uint8

const (
	directionInitiatorToResponder packetDirection = iota + 1
	directionResponderToInitiator
)

type packetMutation func(packetDirection, int, []byte) [][]byte

type udpWitness struct {
	initiatorConn  *net.UDPConn
	responderConn  *net.UDPConn
	initiatorProxy netip.AddrPort
	responderProxy netip.AddrPort
	initiatorDest  netip.AddrPort
	responderDest  netip.AddrPort
	mutate         packetMutation

	initiatorPackets atomic.Int64
	responderPackets atomic.Int64
	wait             sync.WaitGroup
}

func newUDPTopology(t *testing.T, mutate packetMutation) (*udpWitness, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	// Keep proxy ports occupied while choosing the carrier ports so the Windows
	// ephemeral allocator cannot recycle a released carrier port into a proxy.
	initiatorConn := listenLoopback(t)
	responderConn := listenLoopback(t)
	initiatorLocalConn := listenLoopback(t)
	responderLocalConn := listenLoopback(t)
	initiatorDest := udpAddrPort(initiatorLocalConn.LocalAddr())
	responderDest := udpAddrPort(responderLocalConn.LocalAddr())
	if err := initiatorLocalConn.Close(); err != nil {
		t.Fatalf("release initiator carrier endpoint: %v", err)
	}
	if err := responderLocalConn.Close(); err != nil {
		t.Fatalf("release responder carrier endpoint: %v", err)
	}
	witness := &udpWitness{
		initiatorConn: initiatorConn, responderConn: responderConn,
		initiatorProxy: udpAddrPort(initiatorConn.LocalAddr()), responderProxy: udpAddrPort(responderConn.LocalAddr()),
		initiatorDest: initiatorDest, responderDest: responderDest, mutate: mutate,
	}
	return witness, initiatorDest, responderDest
}

func (witness *udpWitness) start(ctx context.Context) {
	witness.wait.Add(2)
	go witness.forward(ctx, witness.initiatorConn, witness.responderConn, witness.responderDest, directionInitiatorToResponder, &witness.initiatorPackets)
	go witness.forward(ctx, witness.responderConn, witness.initiatorConn, witness.initiatorDest, directionResponderToInitiator, &witness.responderPackets)
}

func (witness *udpWitness) forward(ctx context.Context, reader, writer *net.UDPConn, destination netip.AddrPort, direction packetDirection, counter *atomic.Int64) {
	defer witness.wait.Done()
	buffer := make([]byte, punchproto.MaxPacketBytes+1)
	defer clear(buffer)
	for {
		_ = reader.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, _, err := reader.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			var networkErr net.Error
			if errors.As(err, &networkErr) && networkErr.Timeout() {
				continue
			}
			return
		}
		ordinal := int(counter.Add(1))
		packet := append([]byte(nil), buffer[:n]...)
		packets := [][]byte{packet}
		if witness.mutate != nil {
			packets = witness.mutate(direction, ordinal, packet)
		}
		for _, forwarded := range packets {
			_, _ = writer.WriteToUDPAddrPort(forwarded, destination)
			clear(forwarded)
		}
	}
}

func (witness *udpWitness) close() {
	_ = witness.initiatorConn.Close()
	_ = witness.responderConn.Close()
	witness.wait.Wait()
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("listen loopback witness: %v", err)
	}
	return connection
}

func udpAddrPort(address net.Addr) netip.AddrPort {
	return address.(*net.UDPAddr).AddrPort()
}

func assertEndpointReusable(t *testing.T, endpoint netip.AddrPort) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		t.Fatalf("carrier left endpoint busy: %v", err)
	}
	_ = connection.Close()
}

type fakeAuthorization struct {
	mu                  sync.Mutex
	lease               *fakeAttemptLease
	first               bool
	reason              governor.PairingTerminalReason
	finishAfterStopping bool
}

func (authorization *fakeAuthorization) BeforeFirstEmission(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	if authorization.first {
		return governor.ErrFirstEmissionAlreadyAuthorized
	}
	authorization.first = true
	return nil
}

func (authorization *fakeAuthorization) CheckActive(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	if !authorization.first || authorization.reason != "" {
		return governor.ErrCommittedAttemptInvalid
	}
	return nil
}

func (authorization *fakeAuthorization) Finish(reason governor.PairingTerminalReason) error {
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	authorization.reason = reason
	select {
	case <-authorization.lease.Stopping():
		authorization.finishAfterStopping = true
	default:
	}
	return nil
}

type fakeAttemptLease struct {
	request  governor.AttemptRequest
	peerID   string
	stopping chan struct{}
	done     chan struct{}

	mu             sync.Mutex
	drains         int
	stoppingClosed bool
	doneClosed     bool
}

func newFakeAttemptLease(peerID string) *fakeAttemptLease {
	return &fakeAttemptLease{
		request: governor.AttemptRequest{ID: testID(2), Operation: governor.OperationConnectTest, Cost: AttemptCost()},
		peerID:  peerID, stopping: make(chan struct{}), done: make(chan struct{}),
	}
}

func (lease *fakeAttemptLease) Request() governor.AttemptRequest { return lease.request }
func (lease *fakeAttemptLease) PeerID() string                   { return lease.peerID }
func (lease *fakeAttemptLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *fakeAttemptLease) Done() <-chan struct{}            { return lease.done }

func (lease *fakeAttemptLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stoppingClosed {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &fakeCarrierDrain{lease: lease}, nil
}

func (lease *fakeAttemptLease) Close() error {
	lease.mu.Lock()
	if !lease.stoppingClosed {
		lease.stoppingClosed = true
		close(lease.stopping)
	}
	if lease.drains == 0 && !lease.doneClosed {
		lease.doneClosed = true
		close(lease.done)
	}
	done := lease.done
	lease.mu.Unlock()
	<-done
	return nil
}

func (lease *fakeAttemptLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.mu.Lock()
	if !lease.stoppingClosed {
		lease.stoppingClosed = true
		close(lease.stopping)
	}
	lease.mu.Unlock()
	return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true, Record: governor.SafetyTripRecord{SchemaVersion: 1, State: governor.SafetyTripTripped, Reason: event.Reason}}, nil
}

type fakeCarrierDrain struct {
	lease *fakeAttemptLease
	once  sync.Once
}

func (drain *fakeCarrierDrain) Complete() error {
	drain.once.Do(func() {
		drain.lease.mu.Lock()
		if drain.lease.drains > 0 {
			drain.lease.drains--
		}
		if drain.lease.stoppingClosed && drain.lease.drains == 0 && !drain.lease.doneClosed {
			drain.lease.doneClosed = true
			close(drain.lease.done)
		}
		drain.lease.mu.Unlock()
	})
	return nil
}
