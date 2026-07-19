package routed

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
)

func TestTCPListenerAcceptFailureReleasesSocketAndRegistry(t *testing.T) {
	node := newMeshNode(t, mesh.NodeConfig{NodeID: "listener-cleanup"})
	endpoint := newEndpoint(t, node)
	forwarder, err := NewTCPForwarder(endpoint, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })

	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().String()
	scripted := &scriptedAcceptListener{
		Listener: socket,
		errors: []error{
			temporaryAcceptError{},
			temporaryAcceptError{},
			errors.New("permanent accept failure"),
		},
	}
	listenerCtx, cancel := context.WithCancel(forwarder.ctx)
	listener := &TCPListener{
		forwarder: forwarder,
		listener:  scripted,
		remoteID:  "remote",
		ctx:       listenerCtx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	forwarder.mu.Lock()
	forwarder.listeners[listener] = struct{}{}
	forwarder.mu.Unlock()
	if !forwarder.startTask(listener.acceptLoop) {
		t.Fatal("startTask(acceptLoop) = false")
	}

	select {
	case <-listener.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not finish after permanent Accept error")
	}
	if got := scripted.acceptCount(); got != 3 {
		t.Fatalf("Accept call count = %d, want 3", got)
	}
	forwarder.mu.Lock()
	_, registered := forwarder.listeners[listener]
	forwarder.mu.Unlock()
	if registered {
		t.Fatal("failed listener remains in forwarder registry")
	}

	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listen again on %s after listener exit: %v", address, err)
	}
	_ = rebound.Close()
}

func TestTCPAcceptRetryDelayIsBounded(t *testing.T) {
	delay := time.Duration(0)
	for range 32 {
		delay = nextAcceptRetryDelay(delay)
		if delay > maxAcceptRetry {
			t.Fatalf("retry delay = %s, exceeds maximum %s", delay, maxAcceptRetry)
		}
	}
	if delay != maxAcceptRetry {
		t.Fatalf("retry delay = %s, want capped value %s", delay, maxAcceptRetry)
	}
}

func TestTCPListenerAcceptPolicyRejectsBeforeRoutedOpen(t *testing.T) {
	node := newMeshNode(t, mesh.NodeConfig{NodeID: "listener-policy"})
	endpoint := newEndpoint(t, node)
	forwarder, err := NewTCPForwarder(endpoint, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })

	rejected := make(chan struct{}, 1)
	listener, err := forwarder.StartListenerWithPolicy(
		context.Background(), "127.0.0.1:0", "remote",
		func() error {
			select {
			case rejected <- struct{}{}:
			default:
			}
			return errors.New("virtual address membership mismatch")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-rejected:
	case <-time.After(time.Second):
		t.Fatal("accept policy was not called")
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("policy-rejected local connection remained open")
	}

	forwarder.mu.Lock()
	flowCount := len(forwarder.flows)
	openingCount := len(forwarder.opening)
	forwarder.mu.Unlock()
	if flowCount != 0 || openingCount != 0 {
		t.Fatalf("policy rejection created routed flow/opening = %d/%d", flowCount, openingCount)
	}
}

type scriptedAcceptListener struct {
	net.Listener
	mu      sync.Mutex
	errors  []error
	accepts int
}

func (l *scriptedAcceptListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accepts++
	if len(l.errors) == 0 {
		return nil, errors.New("accept script exhausted")
	}
	err := l.errors[0]
	l.errors = l.errors[1:]
	return nil, err
}

func (l *scriptedAcceptListener) acceptCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accepts
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }
