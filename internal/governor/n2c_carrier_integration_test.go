package governor_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvouscarrier"
)

func TestN2CCarrierUsesRealGovernorAndDurableBurnBeforeActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := startN2CGovernorServer(t)
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatalf("prepare test namespace: %v", err)
		}
	}
	leftMachine, err := governor.AcquireLoopbackCarrierTestGovernor(leftNamespace, "n2c-real-governor")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireLoopbackCarrierTestGovernor(rightNamespace, "n2c-real-governor")
	if err != nil {
		t.Fatal(err)
	}
	defer rightMachine.Close()

	leftPeer, leftAttempt := acquireN2CAttempt(t, leftMachine, "left")
	defer leftPeer.Close()
	rightPeer, rightAttempt := acquireN2CAttempt(t, rightMachine, "right")
	defer rightPeer.Close()
	association := n2cOpaqueID("association")
	left, err := rendezvouscarrier.Dial(context.Background(), rendezvouscarrier.Config{
		Lease: leftAttempt, Endpoint: server.endpoint, Tier: rendezvouscarrier.DeploymentSelfHosted,
		AssociationID: association, Slot: rendezvouscarrier.PresenceSlotA, Role: directattempt.RoleInitiator,
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := rendezvouscarrier.Dial(context.Background(), rendezvouscarrier.Config{
		Lease: rightAttempt, Endpoint: server.endpoint, Tier: rendezvouscarrier.DeploymentMinimumTrust,
		AssociationID: association, Slot: rendezvouscarrier.PresenceSlotB, Role: directattempt.RoleResponder,
	})
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
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if err != nil || status.Sequence != 1 || status.Records != 1 {
			t.Fatalf("%s pre-burn journal = %+v/%v", label, status, err)
		}
	}

	leftAuthorization := commitN2CAdmission(t, leftAttempt, "left", now)
	rightAuthorization := commitN2CAdmission(t, rightAttempt, "right", now)
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if err != nil || status.Sequence != 2 || status.Records != 2 || status.OneHourAdmissions != 1 {
			t.Fatalf("%s burned journal = %+v/%v", label, status, err)
		}
	}

	activationErrors := make(chan error, 2)
	go func() { activationErrors <- left.Activate(context.Background(), leftAuthorization) }()
	go func() { activationErrors <- right.Activate(context.Background(), rightAuthorization) }()
	for range 2 {
		if err := <-activationErrors; err != nil {
			t.Fatalf("activate after burn: %v", err)
		}
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	if err := leftAuthorization.Finish(governor.PairingTerminalSuccess); err != nil {
		t.Fatal(err)
	}
	if err := rightAuthorization.Finish(governor.PairingTerminalSuccess); err != nil {
		t.Fatal(err)
	}
	if err := leftAttempt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rightAttempt.Close(); err != nil {
		t.Fatal(err)
	}
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if err != nil || status.Sequence != 3 || status.Records != 3 || status.ConsecutiveFailures != 0 {
			t.Fatalf("%s terminal journal = %+v/%v", label, status, err)
		}
	}
	server.close()
	if server.active != 0 {
		t.Fatalf("server active connections = %d, want zero", server.active)
	}
}

func TestN2CAbsentPeerDrainsWithoutPersistentSafetyTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal(err)
	}
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "n2c-absent-peer")
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(io.Discard, connection)
	}()
	defer func() {
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("absent-peer server cleanup did not finish")
		}
	}()

	peer, attempt := acquireN2CAttempt(t, machine, "absent")
	defer peer.Close()
	defer attempt.Close()
	carrier, err := rendezvouscarrier.Dial(context.Background(), rendezvouscarrier.Config{
		Lease: attempt, Endpoint: listener.Addr().String(), Tier: rendezvouscarrier.DeploymentSelfHosted,
		AssociationID: n2cOpaqueID("absent-association"), Slot: rendezvouscarrier.PresenceSlotA,
		Role: directattempt.RoleInitiator, PresenceDeadline: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer carrier.Close()
	if err := carrier.AwaitPresence(context.Background()); !errors.Is(err, rendezvouscarrier.ErrPresenceTimeout) {
		t.Fatalf("presence error = %v", err)
	}
	if err := carrier.Close(); !errors.Is(err, rendezvouscarrier.ErrPresenceTimeout) {
		t.Fatalf("carrier close = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("absent-peer server handler did not drain")
	}
	if err := machine.Close(); err != nil {
		t.Fatal(err)
	}

	reacquired, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "n2c-absent-peer-verify")
	if err != nil {
		t.Fatalf("reacquire after absent peer: %v", err)
	}
	defer reacquired.Close()
	if trip := reacquired.Snapshot().SafetyTrip; trip.State != governor.SafetyTripClear || trip.BlocksActiveWork {
		t.Fatalf("persistent trip after absent peer = %+v, want clear", trip)
	}
}

func acquireN2CAttempt(t testing.TB, machine *governor.Governor, label string) (*governor.PeerLease, *governor.AttemptLease) {
	t.Helper()
	peer, err := machine.AcquirePeer("n2c-peer-" + label)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), governor.AttemptRequest{
		ID: n2cOpaqueID("attempt-" + label), Operation: governor.OperationConnectTest,
		Cost: rendezvouscarrier.N2AttemptCost(),
	})
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	return peer, attempt
}

func commitN2CAdmission(t testing.TB, attempt *governor.AttemptLease, label string, now time.Time) *governor.CommittedCarrierAuthorization {
	t.Helper()
	digest := sha256.Sum256([]byte("n2c-context-" + label))
	committed, err := governor.NewPairingAdmissionGate().Commit(context.Background(), attempt, governor.PairingAdmissionRequest{
		CredentialID: n2cOpaqueID("credential-" + label), AttemptID: attempt.Request().ID,
		ContextDigest: hex.EncodeToString(digest[:]), Scope: governor.ScopeMachine,
		ExpiresAt: now.Add(10 * time.Minute), Envelope: governor.PairingEnvelopeFromAttemptCost(attempt.Request().Cost),
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := committed.ConsumeForCarrier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func n2cOpaqueID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

type n2cGovernorServer struct {
	listener net.Listener
	endpoint string

	mu     sync.Mutex
	active int
	wg     sync.WaitGroup
}

func startN2CGovernorServer(t testing.TB) *n2cGovernorServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &n2cGovernorServer{listener: listener, endpoint: listener.Addr().String()}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		connections := make([]net.Conn, 0, 2)
		for len(connections) < 2 {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.active++
			server.mu.Unlock()
			connections = append(connections, connection)
		}
		defer func() {
			for _, connection := range connections {
				_ = connection.Close()
			}
			server.mu.Lock()
			server.active = 0
			server.mu.Unlock()
		}()
		for _, connection := range connections {
			kind, err := readN2CTestFrame(connection)
			if err != nil || kind != 1 {
				return
			}
		}
		for _, connection := range connections {
			if err := writeN2CTestFrame(connection, 2); err != nil {
				return
			}
		}
		for _, connection := range connections {
			kind, err := readN2CTestFrame(connection)
			if err != nil || kind != 3 {
				return
			}
		}
		for _, connection := range connections {
			if err := writeN2CTestFrame(connection, 4); err != nil {
				return
			}
		}
		buffer := make([]byte, 1)
		for _, connection := range connections {
			_, _ = connection.Read(buffer)
		}
	}()
	t.Cleanup(server.close)
	return server
}

func readN2CTestFrame(connection net.Conn) (byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(connection, header); err != nil {
		return 0, err
	}
	if string(header[:4]) != "WYRC" || header[4] != 1 {
		return 0, errors.New("invalid N2c test frame")
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	if length > 1024 {
		return 0, errors.New("oversize N2c test frame")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(connection, payload)
	clear(payload)
	return header[5], err
}

func writeN2CTestFrame(connection net.Conn, kind byte) error {
	header := []byte{'W', 'Y', 'R', 'C', 1, kind, 0, 0}
	_, err := connection.Write(header)
	return err
}

func (server *n2cGovernorServer) close() {
	if server == nil || server.listener == nil {
		return
	}
	_ = server.listener.Close()
	server.wg.Wait()
}
