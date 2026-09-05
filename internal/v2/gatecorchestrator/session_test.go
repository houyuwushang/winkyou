package gatecorchestrator

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/pkg/netif"
)

func TestPostOOBEchoCrossesOnlyTheBoundMemoryInterfaces(t *testing.T) {
	left, err := netif.NewGateCMemoryInterface("wink-c1b-left", 1280)
	if err != nil {
		t.Fatal(err)
	}
	right, err := netif.NewGateCMemoryInterface("wink-c1b-right", 1280)
	if err != nil {
		t.Fatal(err)
	}
	bridgeDone := bridgeMemoryInterfaces(t, left, right)
	defer func() {
		_ = left.Close()
		_ = right.Close()
		<-bridgeDone
	}()

	digest := [32]byte{1, 2, 3, 4}
	leftBinding := echoBinding{Role: directattempt.RoleInitiator, Local: netip.MustParseAddr("10.99.0.1"),
		Remote: netip.MustParseAddr("10.99.0.2"), AttemptID: "attempt-echo", ContextDigest: digest}
	rightBinding := echoBinding{Role: directattempt.RoleResponder, Local: leftBinding.Remote,
		Remote: leftBinding.Local, AttemptID: leftBinding.AttemptID, ContextDigest: digest}
	type outcome struct {
		witness EchoWitness
		err     error
	}
	results := make(chan outcome, 2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		witness, runErr := postOOBEcho(ctx, directattempt.RoleInitiator, left, leftBinding,
			bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		results <- outcome{witness: witness, err: runErr}
	}()
	go func() {
		witness, runErr := postOOBEcho(ctx, directattempt.RoleResponder, right, rightBinding,
			bytes.NewReader([]byte{9, 8, 7, 6, 5, 4, 3, 2}))
		results <- outcome{witness: witness, err: runErr}
	}()
	var requestSide, responseSide bool
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		requestSide = requestSide || got.witness.RequestsWritten == 1 && got.witness.ResponsesRead == 1
		responseSide = responseSide || got.witness.RequestsRead == 1 && got.witness.ResponsesWritten == 1
	}
	if !requestSide || !responseSide {
		t.Fatal("echo direction witnesses were incomplete")
	}
}

func TestForegroundResponderSessionTerminationModes(t *testing.T) {
	binding := echoBinding{Role: directattempt.RoleResponder, Local: netip.MustParseAddr("10.99.0.2"),
		Remote: netip.MustParseAddr("10.99.0.1"), AttemptID: "attempt-session", ContextDigest: [32]byte{1, 3, 5, 7}}
	peerBinding := binding
	peerBinding.Role = directattempt.RoleInitiator
	peerBinding.Local, peerBinding.Remote = binding.Remote, binding.Local
	nonce := [8]byte{2, 4, 6, 8, 1, 3, 5, 7}
	closePacket, err := buildEchoPacket(peerBinding, echoClose, nonce)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		prepare    func(context.CancelFunc, context.CancelFunc, *sessionTestInterface)
		want       string
		wantClosed int
	}{
		{
			name: "authenticated close",
			prepare: func(_, _ context.CancelFunc, iface *sessionTestInterface) {
				iface.queueReceive(closePacket)
			},
			want: "authenticated_close", wantClosed: 1,
		},
		{
			name:    "inactivity ceiling",
			prepare: func(_, _ context.CancelFunc, _ *sessionTestInterface) {},
			want:    "inactivity_ceiling",
		},
		{
			name:    "parent cancel",
			prepare: func(cancelCaller, _ context.CancelFunc, _ *sessionTestInterface) { cancelCaller() },
			want:    "parent_cancel",
		},
		{
			name:    "absolute ceiling",
			prepare: func(_, cancelSession context.CancelFunc, _ *sessionTestInterface) { cancelSession() },
			want:    "absolute_ceiling",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			iface := newSessionTestInterface()
			defer iface.Close()
			callerCtx, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			sessionCtx, cancelSession := context.WithTimeout(context.Background(), time.Second)
			defer cancelSession()
			test.prepare(cancelCaller, cancelSession, iface)
			end, witness, runErr := foregroundSession(callerCtx, sessionCtx, directattempt.RoleResponder,
				iface, &gateb.ProductHandoff{}, binding, bytes.NewReader(make([]byte, 8)), 5*time.Millisecond)
			if runErr != nil || end != test.want || !witness.Drained || witness.CloseRead != test.wantClosed {
				t.Fatalf("end=%q witness=%+v err=%v", end, witness, runErr)
			}
		})
	}
}

type sessionTestInterface struct {
	receive chan []byte
	closed  chan struct{}
	once    sync.Once
}

func newSessionTestInterface() *sessionTestInterface {
	return &sessionTestInterface{receive: make(chan []byte, 4), closed: make(chan struct{})}
}

func (*sessionTestInterface) Name() string                      { return "gate-c-session-test" }
func (*sessionTestInterface) Type() string                      { return "memory" }
func (*sessionTestInterface) MTU() int                          { return 1280 }
func (*sessionTestInterface) SetIP(net.IP, net.IPMask) error    { return netif.ErrNotImplemented }
func (*sessionTestInterface) AddRoute(*net.IPNet, net.IP) error { return netif.ErrNotImplemented }
func (*sessionTestInterface) RemoveRoute(*net.IPNet) error      { return netif.ErrNotImplemented }
func (iface *sessionTestInterface) Read([]byte) (int, error) {
	<-iface.closed
	return 0, net.ErrClosed
}
func (iface *sessionTestInterface) Write(packet []byte) (int, error) {
	return len(packet), nil
}
func (iface *sessionTestInterface) InjectPacket(packet []byte) (int, error) {
	return len(packet), nil
}
func (iface *sessionTestInterface) ReceivePacket(destination []byte) (int, error) {
	select {
	case <-iface.closed:
		return 0, net.ErrClosed
	case packet := <-iface.receive:
		return copy(destination, packet), nil
	}
}

func TestCanceledInnerReceiveClosesAndJoinsItsReader(t *testing.T) {
	iface := newSessionTestInterface()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := receiveInnerPacket(ctx, iface); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled receive = %v", err)
	}
	select {
	case <-iface.closed:
	default:
		t.Fatal("canceled receive left interface open")
	}
}
func (iface *sessionTestInterface) Close() error {
	iface.once.Do(func() { close(iface.closed) })
	return nil
}
func (iface *sessionTestInterface) queueReceive(packet []byte) {
	iface.receive <- append([]byte(nil), packet...)
}

var _ netif.MemoryTestInterface = (*sessionTestInterface)(nil)

func bridgeMemoryInterfaces(t *testing.T, left, right netif.MemoryTestInterface) <-chan struct{} {
	t.Helper()
	var workers sync.WaitGroup
	done := make(chan struct{})
	for _, direction := range [][2]netif.MemoryTestInterface{{left, right}, {right, left}} {
		source, destination := direction[0], direction[1]
		workers.Add(1)
		go func() {
			defer workers.Done()
			buffer := make([]byte, 65535)
			for {
				n, err := source.Read(buffer)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("memory bridge read: %v", err)
					}
					return
				}
				if _, err := destination.Write(buffer[:n]); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("memory bridge write: %v", err)
					}
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}
