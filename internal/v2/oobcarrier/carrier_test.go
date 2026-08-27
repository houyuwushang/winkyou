package oobcarrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/rendezvouswire"
)

const testChannelID = "QEFCQ0RFRkdISUpLTE1OTw"

type fakeAttempt struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	mu       sync.Mutex
	claim    bool
	drains   int
}

func newFakeAttempt(t *testing.T, role directattempt.Role) *fakeAttempt {
	t.Helper()
	cost, err := AttemptCost(role)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAttempt{
		request:  governor.AttemptRequest{ID: "EBESExQVFhcYGRobHB0eHw", Operation: governor.OperationConnectTest, Cost: cost},
		stopping: make(chan struct{}),
	}
}

func (attempt *fakeAttempt) Request() governor.AttemptRequest { return attempt.request }
func (attempt *fakeAttempt) Stopping() <-chan struct{}        { return attempt.stopping }
func (attempt *fakeAttempt) ClaimExclusive(name string) error {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if name != carrierClaimName || attempt.claim {
		return governor.ErrExclusiveClaimUsed
	}
	attempt.claim = true
	return nil
}
func (attempt *fakeAttempt) RegisterDrain(string) (governor.DrainHandle, error) {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	attempt.drains++
	return &fakeDrain{attempt: attempt}, nil
}

type fakeDrain struct {
	attempt *fakeAttempt
	once    sync.Once
}

func (drain *fakeDrain) Complete() error {
	drain.once.Do(func() {
		drain.attempt.mu.Lock()
		drain.attempt.drains--
		drain.attempt.mu.Unlock()
	})
	return nil
}

type fakeAuthorization struct {
	mu       sync.Mutex
	first    int
	checks   int
	firstErr error
	checkErr error
}

func (authorization *fakeAuthorization) BeforeFirstEmission(context.Context) error {
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	authorization.first++
	return authorization.firstErr
}
func (authorization *fakeAuthorization) CheckActive(context.Context) error {
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	authorization.checks++
	return authorization.checkErr
}

type fixedPSK [noisecore.PSKSize]byte

func (source fixedPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

func TestCarrierFullPresenceBurnHandshakeAndControlSequence(t *testing.T) {
	leftStream, rightStream := net.Pipe()
	leftAttempt := newFakeAttempt(t, directattempt.RoleInitiator)
	rightAttempt := newFakeAttempt(t, directattempt.RoleResponder)
	left, err := Adopt(Config{Stream: leftStream, OOBChannelID: testChannelID, Role: directattempt.RoleInitiator, testLease: leftAttempt})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Adopt(Config{Stream: rightStream, OOBChannelID: testChannelID, Role: directattempt.RoleResponder, testLease: rightAttempt})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()

	runPair(t, func() error { return left.AwaitPresence(context.Background()) }, func() error { return right.AwaitPresence(context.Background()) })
	leftAuth, rightAuth := &fakeAuthorization{}, &fakeAuthorization{}
	runPair(t, func() error { return left.activate(context.Background(), leftAuth) }, func() error { return right.activate(context.Background(), rightAuth) })
	if leftAuth.first != 1 || rightAuth.first != 1 {
		t.Fatalf("first emission authorization = %d/%d", leftAuth.first, rightAuth.first)
	}

	psk := fixedPSK{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	initiator, err := noisecore.NewInitiator(noisecore.Config{Prologue: []byte("gate-a-carrier-test"), PSK: psk})
	if err != nil {
		t.Fatal(err)
	}
	responder, err := noisecore.NewResponder(noisecore.Config{Prologue: []byte("gate-a-carrier-test"), PSK: psk})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	var receivedFirst []byte
	runPair(t, func() error { return left.SendHandshake(context.Background(), first) }, func() error {
		var receiveErr error
		receivedFirst, receiveErr = right.ReceiveHandshake(context.Background())
		return receiveErr
	})
	if payload, err := responder.ReadMessage(receivedFirst); err != nil || len(payload) != 0 {
		t.Fatalf("responder ReadMessage = %x/%v", payload, err)
	}
	clear(first)
	clear(receivedFirst)
	second, err := responder.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	var receivedSecond []byte
	runPair(t, func() error {
		var receiveErr error
		receivedSecond, receiveErr = left.ReceiveHandshake(context.Background())
		return receiveErr
	}, func() error { return right.SendHandshake(context.Background(), second) })
	if payload, err := initiator.ReadMessage(receivedSecond); err != nil || len(payload) != 0 {
		t.Fatalf("initiator ReadMessage = %x/%v", payload, err)
	}
	clear(second)
	clear(receivedSecond)
	if err := left.MarkHandshakeComplete(); err != nil {
		t.Fatal(err)
	}
	if err := right.MarkHandshakeComplete(); err != nil {
		t.Fatal(err)
	}
	leftPackets, err := initiator.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	rightPackets, err := responder.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	binding := directattempt.Binding{
		AttemptID: "EBESExQVFhcYGRobHB0eHw", Generation: directattempt.Generation,
		ContextDigest: [32]byte{1}, HandshakeHash: [32]byte{2},
	}
	leftProtocol, err := directattempt.NewProtocolForProfile(directattempt.RoleInitiator, binding, leftPackets, directattempt.OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	rightProtocol, err := directattempt.NewProtocolForProfile(directattempt.RoleResponder, binding, rightPackets, directattempt.OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	leftFrame, err := leftProtocol.Seal(directattempt.FramePrepare, nil)
	if err != nil {
		t.Fatal(err)
	}
	runPair(t, func() error { return left.SendControl(context.Background(), leftFrame) }, func() error {
		opened, receiveErr := right.ReceiveControl(context.Background(), rightProtocol)
		if receiveErr == nil && opened.Type != directattempt.FramePrepare {
			return errors.New("wrong control type")
		}
		return receiveErr
	})
	clear(leftFrame)
	rightFrame, err := rightProtocol.Seal(directattempt.FramePrepare, nil)
	if err != nil {
		t.Fatal(err)
	}
	runPair(t, func() error {
		opened, receiveErr := left.ReceiveControl(context.Background(), leftProtocol)
		if receiveErr == nil && opened.Type != directattempt.FramePrepare {
			return errors.New("wrong control type")
		}
		return receiveErr
	}, func() error { return right.SendControl(context.Background(), rightFrame) })
	clear(rightFrame)

	leftReady, err := directattempt.NewReadyPayloadForProfile(binding, directattempt.RoleInitiator,
		netip.MustParseAddrPort("127.0.0.1:40000"), directattempt.OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	leftReadyFrame, err := leftProtocol.Seal(directattempt.FrameReady, &leftReady)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rightProtocol.Open(leftReadyFrame); err != nil {
		t.Fatal(err)
	}
	clear(leftReadyFrame)
	rightReady, err := directattempt.NewReadyPayloadForProfile(binding, directattempt.RoleResponder,
		netip.MustParseAddrPort("127.0.0.1:40001"), directattempt.OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	rightReadyFrame, err := rightProtocol.Seal(directattempt.FrameReady, &rightReady)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leftProtocol.Open(rightReadyFrame); err != nil {
		t.Fatal(err)
	}
	clear(rightReadyFrame)
	fireFrame, err := leftProtocol.Seal(directattempt.FrameFire, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rightProtocol.Open(fireFrame); err != nil {
		t.Fatal(err)
	}
	clear(fireFrame)
	authenticatedDirectFrame, err := leftProtocol.Seal(directattempt.FrameSYN, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := left.SendControl(context.Background(), authenticatedDirectFrame); !errors.Is(err, ErrCarrierDomain) {
		t.Fatalf("authenticated direct-punch carrier frame = %v, want domain rejection", err)
	}
	clear(authenticatedDirectFrame)

	if err := left.Close(); !errors.Is(err, ErrCarrierDomain) {
		t.Fatalf("left Close = %v", err)
	}
	if err := right.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrCarrierTransport) {
		t.Fatalf("right Close = %v", err)
	}
	for name, carrier := range map[string]*Carrier{"left": left, "right": right} {
		witness := carrier.Witness()
		if witness.FramesRead != 4 || witness.FramesWritten != 4 || !witness.DrainRegistered || !witness.Drained || !witness.Closed {
			t.Fatalf("%s witness = %+v", name, witness)
		}
	}
	leftAttempt.mu.Lock()
	leftDrains := leftAttempt.drains
	leftAttempt.mu.Unlock()
	rightAttempt.mu.Lock()
	rightDrains := rightAttempt.drains
	rightAttempt.mu.Unlock()
	if leftDrains != 0 || rightDrains != 0 {
		t.Fatalf("residual drains = %d/%d", leftDrains, rightDrains)
	}
}

func TestCarrierCancellationDeadlineAndEOFAreTerminalAndDrained(t *testing.T) {
	tests := []struct {
		name     string
		run      func(context.Context, context.CancelFunc, net.Conn)
		want     error
		deadline bool
		eof      bool
	}{
		{
			name: "parent cancellation", want: context.Canceled,
			run: func(_ context.Context, cancel context.CancelFunc, _ net.Conn) { cancel() },
		},
		{
			name: "deadline", want: ErrPresenceTimeout, deadline: true,
			run: func(context.Context, context.CancelFunc, net.Conn) {},
		},
		{
			name: "peer EOF", want: ErrCarrierTransport, eof: true,
			run: func(_ context.Context, _ context.CancelFunc, peer net.Conn) {
				go func() {
					time.Sleep(10 * time.Millisecond)
					_ = peer.Close()
				}()
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			victimStream, peerStream := net.Pipe()
			victim, err := Adopt(Config{
				Stream: victimStream, OOBChannelID: testChannelID, Role: directattempt.RoleResponder,
				testLease: newFakeAttempt(t, directattempt.RoleResponder),
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			testCase.run(ctx, cancel, peerStream)
			runErr := victim.AwaitPresence(ctx)
			if !errors.Is(runErr, testCase.want) {
				t.Fatalf("terminal error = %v, want %v", runErr, testCase.want)
			}
			_ = peerStream.Close()
			_ = victim.Close()
			witness := victim.Witness()
			if !witness.Closed || !witness.Drained || witness.Deadline != testCase.deadline || witness.EOF != testCase.eof {
				t.Fatalf("terminal witness = %+v", witness)
			}
		})
	}
}

func TestCarrierConcurrentBackpressureEndsAtCallerDeadline(t *testing.T) {
	leftStream, rightStream := net.Pipe()
	left, err := Adopt(Config{
		Stream: leftStream, OOBChannelID: testChannelID, Role: directattempt.RoleInitiator,
		testLease: newFakeAttempt(t, directattempt.RoleInitiator),
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Adopt(Config{
		Stream: rightStream, OOBChannelID: testChannelID, Role: directattempt.RoleResponder,
		testLease: newFakeAttempt(t, directattempt.RoleResponder),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	payload := make([]byte, rendezvouswire.MinControlPayloadBytes)
	results := make(chan error, 2)
	go func() { results <- left.write(ctx, rendezvouswire.KindControl, payload, false, false) }()
	go func() { results <- right.write(ctx, rendezvouswire.KindControl, payload, false, false) }()
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("backpressured write = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent backpressure exceeded its bounded deadline")
		}
	}
	_ = left.Close()
	_ = right.Close()
	if !left.Witness().Drained || !right.Witness().Drained {
		t.Fatal("backpressured carriers did not drain")
	}
}

func TestCarrierRejectsSecureFrameBeforeBurn(t *testing.T) {
	victimStream, peerStream := net.Pipe()
	attempt := newFakeAttempt(t, directattempt.RoleResponder)
	victim, err := Adopt(Config{Stream: victimStream, OOBChannelID: testChannelID, Role: directattempt.RoleResponder, testLease: attempt})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := rendezvouswire.EncodeForProfile(rendezvouswire.CallerProvidedStreamProfile, rendezvouswire.KindHandshake, make([]byte, rendezvouswire.HandshakePayloadBytes))
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { _, writeErr := peerStream.Write(frame); writeDone <- writeErr }()
	if err := victim.AwaitPresence(context.Background()); !errors.Is(err, ErrPreBurnSecureFrame) {
		t.Fatalf("AwaitPresence = %v, want secure-frame rejection", err)
	}
	_ = peerStream.Close()
	<-writeDone
	if witness := victim.Witness(); witness.FramesRead != 1 || !witness.Closed || !witness.Drained {
		t.Fatalf("witness = %+v", witness)
	}
}

func TestCarrierCloseUnblocksPendingReadAndDrains(t *testing.T) {
	victimStream, peerStream := net.Pipe()
	defer peerStream.Close()
	victim, err := Adopt(Config{
		Stream: victimStream, OOBChannelID: testChannelID, Role: directattempt.RoleResponder,
		testLease: newFakeAttempt(t, directattempt.RoleResponder),
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- victim.AwaitPresence(context.Background()) }()
	time.Sleep(10 * time.Millisecond)
	if err := victim.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the in-flight read")
	}
	if witness := victim.Witness(); !witness.Drained || !witness.Closed {
		t.Fatalf("witness = %+v", witness)
	}
}

func TestCarrierWriterFailureAndBudgetAreTerminal(t *testing.T) {
	t.Run("writer error", func(t *testing.T) {
		stream := &memoryStream{writeErr: errors.New("synthetic writer failure")}
		carrier, err := Adopt(Config{
			Stream: stream, OOBChannelID: testChannelID, Role: directattempt.RoleInitiator,
			testLease: newFakeAttempt(t, directattempt.RoleInitiator),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := carrier.AwaitPresence(context.Background()); !errors.Is(err, ErrCarrierTransport) {
			t.Fatalf("writer failure = %v", err)
		}
		if witness := carrier.Witness(); !witness.Closed || !witness.Drained {
			t.Fatalf("witness = %+v", witness)
		}
	})

	t.Run("ninth frame", func(t *testing.T) {
		stream := &memoryStream{}
		carrier, err := Adopt(Config{
			Stream: stream, OOBChannelID: testChannelID, Role: directattempt.RoleInitiator,
			testLease: newFakeAttempt(t, directattempt.RoleInitiator),
		})
		if err != nil {
			t.Fatal(err)
		}
		carrier.authorization = &fakeAuthorization{}
		payload := make([]byte, rendezvouswire.MinControlPayloadBytes)
		for index := 0; index < MaxFramesPerDirection; index++ {
			if err := carrier.write(context.Background(), rendezvouswire.KindControl, payload, true, false); err != nil {
				t.Fatalf("frame %d: %v", index, err)
			}
		}
		if err := carrier.write(context.Background(), rendezvouswire.KindControl, payload, true, false); !errors.Is(err, ErrApplicationBudget) {
			t.Fatalf("ninth frame = %v", err)
		}
		carrier.fail(ErrApplicationBudget)
		if witness := carrier.Witness(); witness.FramesWritten != MaxFramesPerDirection || !witness.Drained {
			t.Fatalf("witness = %+v", witness)
		}
	})
}

func TestCarrierCostMustMatchBeforeStreamOwnership(t *testing.T) {
	attempt := newFakeAttempt(t, directattempt.RoleInitiator)
	attempt.request.Cost.Resources.Packets--
	stream := &memoryStream{}
	if _, err := Adopt(Config{Stream: stream, OOBChannelID: testChannelID, Role: directattempt.RoleInitiator, testLease: attempt}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Adopt = %v, want invalid config", err)
	}
	if stream.closed {
		t.Fatal("invalid cost transferred stream ownership")
	}
}

func runPair(t *testing.T, left, right func() error) {
	t.Helper()
	results := make(chan error, 2)
	go func() { results <- left() }()
	go func() { results <- right() }()
	for index := 0; index < 2; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("paired operation: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("paired operation exceeded bounded liveness")
		}
	}
}

type memoryStream struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	writeErr error
	closed   bool
}

func (stream *memoryStream) Read(dst []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return 0, io.EOF
	}
	return stream.buffer.Read(dst)
}
func (stream *memoryStream) Write(src []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return 0, io.ErrClosedPipe
	}
	if stream.writeErr != nil {
		return 0, stream.writeErr
	}
	return stream.buffer.Write(src)
}
func (stream *memoryStream) Close() error {
	stream.mu.Lock()
	stream.closed = true
	stream.mu.Unlock()
	return nil
}
func (*memoryStream) SetDeadline(time.Time) error { return nil }
