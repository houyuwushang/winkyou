package rendezvouscarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
)

var testAssociation = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 16))

func TestN2CCarrierRealLoopbackNoiseAndControlRoundTripBothDeploymentTiers(t *testing.T) {
	for _, tier := range []DeploymentTier{DeploymentSelfHosted, DeploymentMinimumTrust} {
		t.Run(string(tier), func(t *testing.T) {
			server := startTestRendezvousServer(t, false)
			left, right, leftLease, rightLease := connectCarrierPair(t, server, tier)
			leftAuth, rightAuth := &fakeAuthorization{}, &fakeAuthorization{}
			activatePair(t, left, right, leftAuth, rightAuth)

			initiatorSession, responderSession := noiseSessionPair(t)
			first, err := initiatorSession.WriteMessage(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := left.SendHandshake(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			clear(first)
			received, err := right.ReceiveHandshake(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if payload, err := responderSession.ReadMessage(received); err != nil || len(payload) != 0 {
				t.Fatalf("responder handshake = %x, %v", payload, err)
			}
			clear(received)
			second, err := responderSession.WriteMessage(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := right.SendHandshake(context.Background(), second); err != nil {
				t.Fatal(err)
			}
			clear(second)
			received, err = left.ReceiveHandshake(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if payload, err := initiatorSession.ReadMessage(received); err != nil || len(payload) != 0 {
				t.Fatalf("initiator handshake = %x, %v", payload, err)
			}
			clear(received)
			if err := left.MarkHandshakeComplete(); err != nil {
				t.Fatal(err)
			}
			if err := right.MarkHandshakeComplete(); err != nil {
				t.Fatal(err)
			}

			initiator, responder, _ := protocolPairFromSessions(t, initiatorSession, responderSession)
			defer initiator.Close()
			defer responder.Close()
			leftPrepare, err := initiator.Seal(directattempt.FramePrepare, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := left.SendControl(context.Background(), leftPrepare); err != nil {
				t.Fatal(err)
			}
			clear(leftPrepare)
			opened, err := right.ReceiveControl(context.Background(), responder)
			if err != nil || opened.Type != directattempt.FramePrepare {
				t.Fatalf("receive prepare = %+v, %v", opened, err)
			}
			rightPrepare, err := responder.Seal(directattempt.FramePrepare, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := right.SendControl(context.Background(), rightPrepare); err != nil {
				t.Fatal(err)
			}
			clear(rightPrepare)
			opened, err = left.ReceiveControl(context.Background(), initiator)
			if err != nil || opened.Type != directattempt.FramePrepare {
				t.Fatalf("receive peer prepare = %+v, %v", opened, err)
			}

			if leftAuth.before.Load() != 1 || rightAuth.before.Load() != 1 || leftAuth.check.Load() == 0 || rightAuth.check.Load() == 0 {
				t.Fatalf("authorization checks left=%d/%d right=%d/%d", leftAuth.before.Load(), leftAuth.check.Load(), rightAuth.before.Load(), rightAuth.check.Load())
			}
			if err := left.Close(); err != nil {
				t.Fatal(err)
			}
			if err := right.Close(); err != nil {
				t.Fatal(err)
			}
			if err := server.waitForActive(0); err != nil {
				t.Fatal(err)
			}
			for name, witness := range map[string]Witness{"left": left.Witness(), "right": right.Witness()} {
				if witness.Tier != tier || witness.Connections != 1 || witness.DNSResolutions != 0 || !witness.DrainRegistered || !witness.Drained || !witness.Closed {
					t.Fatalf("%s witness = %+v", name, witness)
				}
			}
			if leftLease.drain.completions.Load() != 1 || rightLease.drain.completions.Load() != 1 || server.accepted.Load() != 2 {
				t.Fatalf("resource witness drains=%d/%d accepts=%d", leftLease.drain.completions.Load(), rightLease.drain.completions.Load(), server.accepted.Load())
			}
		})
	}
}

func TestN2CPresenceTimeoutDoesNotCrossBurnBoundary(t *testing.T) {
	server := startTestRendezvousServer(t, false)
	lease := newFakeLease()
	carrier, err := Dial(context.Background(), Config{
		testLease: lease, Endpoint: server.Endpoint(), Tier: DeploymentSelfHosted,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
		PresenceDeadline: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := &fakeAuthorization{}
	if err := carrier.AwaitPresence(context.Background()); !errors.Is(err, ErrPresenceTimeout) {
		t.Fatalf("presence error = %v", err)
	}
	if authorization.before.Load() != 0 || authorization.check.Load() != 0 {
		t.Fatal("presence failure touched durable authorization")
	}
	if err := carrier.Close(); !errors.Is(err, ErrPresenceTimeout) {
		t.Fatalf("close error = %v", err)
	}
	if lease.drain.completions.Load() != 1 || !carrier.Witness().Drained {
		t.Fatalf("drain witness = %+v/%d", carrier.Witness(), lease.drain.completions.Load())
	}
}

func TestN2CPreBurnHandshakeIsRejectedWithoutAuthorization(t *testing.T) {
	server := startTestRendezvousServer(t, true)
	carrier, err := Dial(context.Background(), Config{
		testLease: newFakeLease(), Endpoint: server.Endpoint(), Tier: DeploymentMinimumTrust,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.AwaitPresence(context.Background()); !errors.Is(err, ErrPreBurnSecureFrame) {
		t.Fatalf("pre-burn frame error = %v", err)
	}
	_ = carrier.Close()
}

func TestN2CAuthenticatedDirectPunchOnCarrierIsTerminalAfterOpen(t *testing.T) {
	server := startTestRendezvousServer(t, false)
	left, right, _, _ := connectCarrierPair(t, server, DeploymentSelfHosted)
	activatePair(t, left, right, &fakeAuthorization{}, &fakeAuthorization{})
	right.mu.Lock()
	right.handshakeSent = true
	right.handshakeRead = true
	right.mu.Unlock()
	if err := right.MarkHandshakeComplete(); err != nil {
		t.Fatal(err)
	}
	initiatorSession, responderSession := noiseSessionPair(t)
	completeNoisePairInMemory(t, initiatorSession, responderSession)
	initiator, responder, binding := protocolPairFromSessions(t, initiatorSession, responderSession)
	defer initiator.Close()
	defer responder.Close()
	driveProtocolsToFire(t, initiator, responder, binding)
	frame, err := initiator.Seal(directattempt.FrameSYN, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Inject(testAssociation, PresenceSlotB, wireControl, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := right.ReceiveControl(context.Background(), responder); !errors.Is(err, ErrCarrierDomain) {
		t.Fatalf("domain error = %v", err)
	}
	if status := responder.Status(); !status.Terminal || status.Received != 4 {
		t.Fatalf("real protocol did not authenticate/open SYN before carrier rejection: %+v", status)
	}
	left.mu.Lock()
	left.handshakeSent = true
	left.handshakeRead = true
	left.mu.Unlock()
	if err := left.MarkHandshakeComplete(); err != nil {
		t.Fatal(err)
	}
	if err := left.SendControl(context.Background(), frame); !errors.Is(err, ErrCarrierDomain) {
		t.Fatalf("outbound domain error = %v", err)
	}
	_ = left.Close()
	_ = right.Close()
}

func TestN2CCarrierCostTargetAndSecretBoundaryAreFrozen(t *testing.T) {
	want := governor.AttemptCost{
		Resources: governor.Resources{Sockets: 3, Targets: 4, PacketsPerSecond: 5, Packets: 5, FiveTuples: 4},
		Duration:  15 * time.Second, Heavyweight: true,
	}
	if got := N2AttemptCost(); got != want || MaxConnections != 1 || MaxRendezvousTargets != 1 || MaxDNSResolutions != 1 ||
		MaxFramesPerDirection != 8 || MaxApplicationBytes != 8256 || ActiveEnvelope != 13*time.Second {
		t.Fatalf("frozen carrier cost/limits drifted: cost=%+v bytes=%d envelope=%s", got, MaxApplicationBytes, ActiveEnvelope)
	}

	configType := reflect.TypeOf(Config{})
	for index := 0; index < configType.NumField(); index++ {
		name := strings.ToLower(configType.Field(index).Name)
		if strings.Contains(name, "secret") || strings.Contains(name, "psk") || strings.Contains(name, "credential") {
			t.Fatalf("carrier config gained secret-bearing field %s", configType.Field(index).Name)
		}
	}

	lease := newFakeLease()
	lease.request.Cost.Resources.Targets++
	if _, err := Dial(context.Background(), Config{
		testLease: lease, Endpoint: "127.0.0.1:9", Tier: DeploymentSelfHosted,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("non-exact reservation error = %v", err)
	}
	if lease.drain.completions.Load() != 0 {
		t.Fatal("invalid reservation registered network drain")
	}
	if _, err := Dial(context.Background(), Config{
		testLease: newFakeLease(), Endpoint: "192.0.2.10:443", Tier: DeploymentSelfHosted,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
	}); !errors.Is(err, ErrTargetForbidden) {
		t.Fatalf("default non-loopback policy error = %v", err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedEndpoint := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	connectionLease := newFakeLease()
	if _, err := Dial(context.Background(), Config{
		testLease: connectionLease, Endpoint: closedEndpoint, Tier: DeploymentSelfHosted,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
	}); !errors.Is(err, ErrCarrierTransport) || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), closedEndpoint) {
		t.Fatalf("redacted transport error = %q", err)
	}
	if _, err := Dial(context.Background(), Config{
		testLease: connectionLease, Endpoint: closedEndpoint, Tier: DeploymentSelfHosted,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
	}); !errors.Is(err, governor.ErrExclusiveClaimUsed) {
		t.Fatalf("same-attempt reconnect error = %v", err)
	}
}

func TestN2CApplicationBudgetDeadlineAndWriterFailureDrain(t *testing.T) {
	t.Run("application byte ceiling", func(t *testing.T) {
		server := startTestRendezvousServer(t, false)
		left, right, _, _ := connectCarrierPair(t, server, DeploymentSelfHosted)
		activatePair(t, left, right, &fakeAuthorization{}, &fakeAuthorization{})
		left.mu.Lock()
		left.bytesWritten = MaxApplicationBytes
		left.mu.Unlock()
		if err := left.SendHandshake(context.Background(), make([]byte, 48)); !errors.Is(err, ErrApplicationBudget) {
			t.Fatalf("budget error = %v", err)
		}
		_ = left.Close()
		_ = right.Close()
		if !left.Witness().Drained {
			t.Fatal("byte-limit path did not drain")
		}
	})

	t.Run("operation deadline", func(t *testing.T) {
		server := startTestRendezvousServer(t, false)
		left, right, _, _ := connectCarrierPairWithDeadline(t, server, DeploymentSelfHosted, 50*time.Millisecond)
		// Activate only one side; the server deliberately withholds its marker.
		if err := left.activate(context.Background(), &fakeAuthorization{}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline error = %v", err)
		}
		_ = left.Close()
		_ = right.Close()
		if !left.Witness().Drained {
			t.Fatal("deadline path did not drain")
		}
	})

	t.Run("writer failure", func(t *testing.T) {
		server := startTestRendezvousServer(t, false)
		left, right, _, _ := connectCarrierPair(t, server, DeploymentSelfHosted)
		activatePair(t, left, right, &fakeAuthorization{}, &fakeAuthorization{})
		left.mu.Lock()
		left.conn = writeFailConn{Conn: left.conn}
		left.mu.Unlock()
		sendErr := left.SendHandshake(context.Background(), make([]byte, 48))
		if !errors.Is(sendErr, ErrCarrierTransport) || strings.Contains(sendErr.Error(), "127.0.0.1") {
			t.Fatalf("redacted writer failure = %q", sendErr)
		}
		_ = left.Close()
		_ = right.Close()
		if !left.Witness().Drained {
			t.Fatal("writer failure path did not drain")
		}
	})

	t.Run("lease cancellation", func(t *testing.T) {
		server := startTestRendezvousServer(t, false)
		left, right, leftLease, _ := connectCarrierPair(t, server, DeploymentSelfHosted)
		close(leftLease.stopping)
		select {
		case <-left.closed:
		case <-time.After(time.Second):
			t.Fatal("lease cancellation did not close carrier")
		}
		if err := left.Close(); !errors.Is(err, governor.ErrLeaseClosed) {
			t.Fatalf("lease cancellation error = %v", err)
		}
		_ = right.Close()
		if !left.Witness().Drained || leftLease.drain.completions.Load() != 1 {
			t.Fatalf("lease-cancellation drain = %+v/%d", left.Witness(), leftLease.drain.completions.Load())
		}
	})
}

func TestN2CLiteralEndpointUsesZeroDNSAndInjectedResolverExactlyOnce(t *testing.T) {
	server := startTestRendezvousServer(t, false)
	_, port, ok := strings.Cut(server.Endpoint(), ":")
	if !ok {
		t.Fatal("unexpected loopback endpoint")
	}
	resolver := &countingResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	carrier, err := Dial(context.Background(), Config{
		testLease: newFakeLease(), Endpoint: "rendezvous.invalid:" + port, Tier: DeploymentSelfHosted,
		AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator, resolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls.Load() != 1 || carrier.Witness().DNSResolutions != 1 {
		t.Fatalf("DNS witness calls=%d witness=%+v", resolver.calls.Load(), carrier.Witness())
	}
	_ = carrier.Close()
}

func TestN2CCarrierCrashSubprocessLeavesNoServerSocket(t *testing.T) {
	if os.Getenv("WINKYOU_N2C_CRASH_HELPER") == "1" {
		carrier, err := Dial(context.Background(), Config{
			testLease: newFakeLease(), Endpoint: os.Getenv("WINKYOU_N2C_ENDPOINT"), Tier: DeploymentSelfHosted,
			AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator,
		})
		if err != nil {
			os.Exit(3)
		}
		_ = carrier
		_, _ = os.Stdout.WriteString("ready\n")
		select {}
	}
	server := startTestRendezvousServer(t, false)
	command := exec.Command(os.Args[0], "-test.run=^TestN2CCarrierCrashSubprocessLeavesNoServerSocket$")
	command.Env = append(os.Environ(), "WINKYOU_N2C_CRASH_HELPER=1", "WINKYOU_N2C_ENDPOINT="+server.Endpoint())
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 6)
	if _, err := stdout.Read(buffer); err != nil || string(buffer) != "ready\n" {
		_ = command.Process.Kill()
		t.Fatalf("helper readiness failed: %q %v", buffer, err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if err := server.waitForActive(0); err != nil {
		t.Fatal(err)
	}
}

func connectCarrierPair(t testing.TB, server *testRendezvousServer, tier DeploymentTier) (*Carrier, *Carrier, *fakeLease, *fakeLease) {
	return connectCarrierPairWithDeadline(t, server, tier, 0)
}

func connectCarrierPairWithDeadline(t testing.TB, server *testRendezvousServer, tier DeploymentTier, operationDeadline time.Duration) (*Carrier, *Carrier, *fakeLease, *fakeLease) {
	t.Helper()
	leftLease, rightLease := newFakeLease(), newFakeLease()
	left, err := Dial(context.Background(), Config{testLease: leftLease, Endpoint: server.Endpoint(), Tier: tier, AssociationID: testAssociation, Slot: PresenceSlotA, Role: directattempt.RoleInitiator, OperationDeadline: operationDeadline})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Dial(context.Background(), Config{testLease: rightLease, Endpoint: server.Endpoint(), Tier: tier, AssociationID: testAssociation, Slot: PresenceSlotB, Role: directattempt.RoleResponder, OperationDeadline: operationDeadline})
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	if err := left.AwaitPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := right.AwaitPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	return left, right, leftLease, rightLease
}

func activatePair(t testing.TB, left, right *Carrier, leftAuth, rightAuth emissionAuthorization) {
	t.Helper()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- left.activate(context.Background(), leftAuth) }()
	go func() { errorsChannel <- right.activate(context.Background(), rightAuth) }()
	for range 2 {
		if err := <-errorsChannel; err != nil {
			t.Fatalf("activate carrier: %v", err)
		}
	}
}

type fixedPSK [noisecore.PSKSize]byte

func (source fixedPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

func noiseSessionPair(t testing.TB) (*noisecore.Session, *noisecore.Session) {
	t.Helper()
	var psk fixedPSK
	for index := range psk {
		psk[index] = 0x44
	}
	initiator, err := noisecore.NewInitiator(noisecore.Config{Prologue: []byte("n2c synthetic prologue"), PSK: psk, Random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	responder, err := noisecore.NewResponder(noisecore.Config{Prologue: []byte("n2c synthetic prologue"), PSK: psk, Random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 32))})
	if err != nil {
		initiator.Close()
		t.Fatal(err)
	}
	return initiator, responder
}

func completeNoisePairInMemory(t testing.TB, initiator, responder *noisecore.Session) {
	t.Helper()
	first, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := responder.ReadMessage(first); err != nil || len(payload) != 0 {
		t.Fatalf("complete responder handshake = %x, %v", payload, err)
	}
	clear(first)
	second, err := responder.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := initiator.ReadMessage(second); err != nil || len(payload) != 0 {
		t.Fatalf("complete initiator handshake = %x, %v", payload, err)
	}
	clear(second)
}

func protocolPairFromSessions(t testing.TB, initiatorSession, responderSession *noisecore.Session) (*directattempt.Protocol, *directattempt.Protocol, directattempt.Binding) {
	t.Helper()
	iHash, err := initiatorSession.HandshakeHash()
	if err != nil {
		t.Fatal(err)
	}
	rHash, err := responderSession.HandshakeHash()
	if err != nil || iHash != rHash {
		t.Fatalf("handshake hash mismatch: %v", err)
	}
	iPackets, err := initiatorSession.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	rPackets, err := responderSession.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		iPackets.Close()
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("n2c synthetic context"))
	binding := directattempt.Binding{AttemptID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 16)), ContextDigest: digest, HandshakeHash: iHash, Generation: directattempt.Generation}
	initiator, err := directattempt.NewProtocol(directattempt.RoleInitiator, binding, iPackets)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := directattempt.NewProtocol(directattempt.RoleResponder, binding, rPackets)
	if err != nil {
		initiator.Close()
		t.Fatal(err)
	}
	return initiator, responder, binding
}

func driveProtocolsToFire(t testing.TB, initiator, responder *directattempt.Protocol, binding directattempt.Binding) {
	t.Helper()
	forward := func(sender, receiver *directattempt.Protocol, frameType directattempt.FrameType, ready *directattempt.ReadyPayload) {
		frame, err := sender.Seal(frameType, ready)
		if err != nil {
			t.Fatalf("seal %s: %v", frameType, err)
		}
		if _, err := receiver.Open(frame); err != nil {
			t.Fatalf("open %s: %v", frameType, err)
		}
		clear(frame)
	}
	forward(initiator, responder, directattempt.FramePrepare, nil)
	forward(responder, initiator, directattempt.FramePrepare, nil)
	iReady, err := directattempt.NewReadyPayload(binding, directattempt.RoleInitiator, netip.MustParseAddrPort("192.0.2.10:41000"))
	if err != nil {
		t.Fatal(err)
	}
	rReady, err := directattempt.NewReadyPayload(binding, directattempt.RoleResponder, netip.MustParseAddrPort("198.51.100.20:42000"))
	if err != nil {
		t.Fatal(err)
	}
	forward(initiator, responder, directattempt.FrameReady, &iReady)
	forward(responder, initiator, directattempt.FrameReady, &rReady)
	forward(initiator, responder, directattempt.FrameFire, nil)
}

type fakeAuthorization struct {
	before atomic.Int32
	check  atomic.Int32
}

type writeFailConn struct{ net.Conn }

func (connection writeFailConn) Write([]byte) (int, error) {
	return 0, errors.New("injected writer failure at 127.0.0.1:1")
}

func (authorization *fakeAuthorization) BeforeFirstEmission(context.Context) error {
	if authorization.before.Add(1) != 1 {
		return errors.New("first emission authorization reused")
	}
	return nil
}

func (authorization *fakeAuthorization) CheckActive(context.Context) error {
	authorization.check.Add(1)
	return nil
}

type fakeLease struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	drain    *fakeDrain
	claimed  atomic.Bool
}

func newFakeLease() *fakeLease {
	return &fakeLease{
		request:  governor.AttemptRequest{ID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 16)), Operation: governor.OperationConnectTest, Cost: N2AttemptCost()},
		stopping: make(chan struct{}), drain: &fakeDrain{},
	}
}

func (lease *fakeLease) Request() governor.AttemptRequest { return lease.request }
func (lease *fakeLease) ClaimExclusive(name string) error {
	if name != carrierClaimName {
		return governor.ErrInvalidRequest
	}
	if !lease.claimed.CompareAndSwap(false, true) {
		return governor.ErrExclusiveClaimUsed
	}
	return nil
}
func (lease *fakeLease) Stopping() <-chan struct{} { return lease.stopping }
func (lease *fakeLease) RegisterDrain(string) (governor.DrainHandle, error) {
	return lease.drain, nil
}

type fakeDrain struct{ completions atomic.Int32 }

func (drain *fakeDrain) Complete() error {
	drain.completions.Add(1)
	return nil
}

type countingResolver struct {
	calls     atomic.Int32
	addresses []netip.Addr
}

func (resolver *countingResolver) Resolve(context.Context, string, string) ([]netip.Addr, error) {
	resolver.calls.Add(1)
	return append([]netip.Addr(nil), resolver.addresses...), nil
}
