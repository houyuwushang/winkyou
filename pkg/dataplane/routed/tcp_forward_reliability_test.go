package routed

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/mesh"
)

func TestTCPForwarderOpenResultWaitIsBoundedWhenOpenErrorIsDropped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var deliveredOpenACKs atomic.Int32
	nodeA := newMeshNode(t, mesh.NodeConfig{
		NodeID: "A", Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventDelivered && event.Frame.Type == mesh.DataTypeStreamACK && event.Frame.Sequence == 1 {
				deliveredOpenACKs.Add(1)
			}
		},
	})
	nodeB := newMeshNode(t, mesh.NodeConfig{NodeID: "B", Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond})
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	packetA, packetB := newLossyTCPPacketPair()
	packetB.drop = map[mesh.DataType]int{mesh.DataTypeStreamOpenError: 3}
	neighborConfig := mesh.PacketNeighborConfig{
		KeepAliveInterval: 50 * time.Millisecond,
		PeerTimeout:       2 * time.Second,
		ReadPollInterval:  25 * time.Millisecond,
		WriteTimeout:      time.Second,
	}
	if err := nodeA.AttachPacketTransport("B", packetA, neighborConfig); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.AttachPacketTransport("A", packetB, neighborConfig); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, ctx, func() bool {
		_, forwardOK := nodeA.Route("B")
		_, reverseOK := nodeB.Route("A")
		return forwardOK && reverseOK
	}, "packet neighbors did not advertise reciprocal routes")

	endpointA := newEndpoint(t, nodeA)
	endpointB := newEndpoint(t, nodeB)
	const (
		dialTimeout  = 50 * time.Millisecond
		frameTimeout = 300 * time.Millisecond
	)
	forwarderA, err := NewTCPForwarderWithConfig(endpointA, TCPForwarderConfig{DialTimeout: dialTimeout, FrameTimeout: frameTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderA.Close() })
	forwarderB, err := NewTCPForwarderWithConfig(endpointB, TCPForwarderConfig{DialTimeout: dialTimeout, FrameTimeout: frameTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderB.Close() })
	if want := dialTimeout + frameTimeout; forwarderA.openTimeout != want {
		t.Fatalf("OPEN result timeout = %s, want %s", forwarderA.openTimeout, want)
	}
	listener, err := forwarderA.StartListener(ctx, "127.0.0.1:0", "B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	started := time.Now()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, readErr := conn.Read(make([]byte, 1))
	if readErr == nil {
		t.Fatal("local connection remained readable after every OPEN_ERROR was dropped")
	}
	var netErr net.Error
	if errors.As(readErr, &netErr) && netErr.Timeout() {
		t.Fatalf("local connection was not closed by bounded OPEN result wait: %v", readErr)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("OPEN result cleanup took %s, want less than 2s", elapsed)
	}
	waitForCondition(t, ctx, func() bool {
		forwarderA.mu.Lock()
		flowsA := len(forwarderA.flows)
		forwarderA.mu.Unlock()
		forwarderB.mu.Lock()
		flowsB, openingB := len(forwarderB.flows), len(forwarderB.opening)
		forwarderB.mu.Unlock()
		return flowsA == 0 && flowsB == 0 && openingB == 0
	}, "OPEN timeout did not clean up forwarder state")
	if got := deliveredOpenACKs.Load(); got == 0 {
		t.Fatal("test never observed the successful ACK for OPEN")
	}
	if got := packetB.totalDropped(); got != 3 {
		t.Fatalf("dropped OPEN_ERROR frames = %d, want 3", got)
	}
}

func TestTCPFlowQueueFullWithholdsACKAndPreservesSequence(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	forwarder := &TCPForwarder{flows: make(map[tcpFlowKey]*tcpFlow)}
	flow := newTCPFlow(forwarder, tcpFlowKey{peerID: "peer", flowID: 17}, local, false, 1)
	flow.markOpened()
	t.Cleanup(flow.shutdown)

	for index := 0; index < cap(flow.inbound); index++ {
		sequence := uint64(index + 2)
		shouldACK, err := flow.enqueueSequenced(sequence, mesh.DataTypeStreamData, []byte{byte(index)})
		if err != nil || !shouldACK {
			t.Fatalf("enqueue sequence %d = ACK %t, error %v", sequence, shouldACK, err)
		}
	}
	blockedSequence := uint64(cap(flow.inbound) + 2)
	blockedPayload := []byte("retry-me")
	shouldACK, err := flow.enqueueSequenced(blockedSequence, mesh.DataTypeStreamData, blockedPayload)
	if !errors.Is(err, errTCPInboundQueueFull) {
		t.Fatalf("full queue error = %v, want %v", err, errTCPInboundQueueFull)
	}
	if shouldACK {
		t.Fatal("full queue marked the unadmitted DATA frame ACKable")
	}
	flow.recvMu.Lock()
	recvSeqAfterFull := flow.recvSeq
	flow.recvMu.Unlock()
	if want := blockedSequence - 1; recvSeqAfterFull != want {
		t.Fatalf("recvSeq after full queue = %d, want %d", recvSeqAfterFull, want)
	}

	<-flow.inbound
	shouldACK, err = flow.enqueueSequenced(blockedSequence, mesh.DataTypeStreamData, blockedPayload)
	if err != nil || !shouldACK {
		t.Fatalf("retry enqueue = ACK %t, error %v", shouldACK, err)
	}
	flow.recvMu.Lock()
	recvSeqAfterRetry := flow.recvSeq
	flow.recvMu.Unlock()
	if recvSeqAfterRetry != blockedSequence {
		t.Fatalf("recvSeq after admitted retry = %d, want %d", recvSeqAfterRetry, blockedSequence)
	}
	var admitted tcpInbound
	for range cap(flow.inbound) {
		admitted = <-flow.inbound
	}
	if string(admitted.payload) != string(blockedPayload) {
		t.Fatalf("last admitted payload = %q, want %q", admitted.payload, blockedPayload)
	}

	queueLength := len(flow.inbound)
	shouldACK, err = flow.enqueueSequenced(blockedSequence, mesh.DataTypeStreamData, []byte("duplicate"))
	if err != nil || !shouldACK {
		t.Fatalf("duplicate enqueue = ACK %t, error %v", shouldACK, err)
	}
	if got := len(flow.inbound); got != queueLength {
		t.Fatalf("duplicate changed queue length to %d, want %d", got, queueLength)
	}
}

func TestTCPForwarderAcknowledgesRepeatedUnknownReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodeA := newMeshNode(t, mesh.NodeConfig{NodeID: "A", Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeB := newMeshNode(t, mesh.NodeConfig{NodeID: "B", Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond})
	attachDualTCPPair(t, nodeA, "B", nodeB, "A")
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, ctx, func() bool {
		_, forwardOK := nodeA.Route("B")
		_, reverseOK := nodeB.Route("A")
		return forwardOK && reverseOK
	}, "stream neighbors did not advertise reciprocal routes")

	endpointA := newEndpoint(t, nodeA)
	endpointB := newEndpoint(t, nodeB)
	forwarderA, err := NewTCPForwarder(endpointA, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderA.Close() })
	acks := make(chan mesh.DataFrame, 2)
	unregister, err := endpointB.RegisterHandler([]mesh.DataType{mesh.DataTypeStreamACK}, func(_ context.Context, frame mesh.DataFrame) error {
		acks <- frame
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unregister)

	reset := mesh.DataFrame{
		Version: mesh.DataFrameVersion, Type: mesh.DataTypeStreamReset, HopLimit: 16,
		Source: "B", Destination: "A", FlowID: 99, Sequence: 7, Payload: []byte("already gone"),
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := endpointB.Send(ctx, reset); err != nil {
			t.Fatalf("send RESET attempt %d: %v", attempt+1, err)
		}
		select {
		case ack := <-acks:
			if ack.FlowID != reset.FlowID || ack.Sequence != reset.Sequence || ack.Source != "A" || ack.Destination != "B" {
				t.Fatalf("RESET ACK attempt %d = %#v", attempt+1, ack)
			}
		case <-ctx.Done():
			t.Fatalf("RESET attempt %d was not acknowledged: %v", attempt+1, ctx.Err())
		}
	}
}

func TestTCPFlowOpenResultTerminalTransitionOrdering(t *testing.T) {
	newFlow := func(t *testing.T) *tcpFlow {
		t.Helper()
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		forwarder := &TCPForwarder{flows: make(map[tcpFlowKey]*tcpFlow)}
		flow := newTCPFlow(forwarder, tcpFlowKey{peerID: "peer", flowID: 23}, local, true, 0)
		t.Cleanup(flow.shutdown)
		return flow
	}

	t.Run("timeout wins before late OPEN_OK", func(t *testing.T) {
		flow := newFlow(t)
		timeoutErr := errors.New("controlled OPEN timeout")
		startLateResult := make(chan struct{})
		lateResultWon := make(chan bool, 1)
		go func() {
			<-startLateResult
			lateResultWon <- flow.completeOpenFrame(mesh.DataTypeStreamOpenOK, nil)
		}()

		if !flow.completeOpenLocally(timeoutErr) {
			t.Fatal("timeout did not win the pending OPEN transition")
		}
		close(startLateResult)
		if <-lateResultWon {
			t.Fatal("late OPEN_OK replaced the committed timeout")
		}
		if flow.shouldAcknowledgeOpenResult(mesh.DataTypeStreamOpenOK) {
			t.Fatal("late OPEN_OK became ACKable after timeout won")
		}
		if flow.isOpened() {
			t.Fatal("late OPEN_OK marked a timed-out flow opened")
		}
		if got := <-flow.openResult; !errors.Is(got, timeoutErr) {
			t.Fatalf("published OPEN result = %v, want %v", got, timeoutErr)
		}
	})

	t.Run("OPEN_OK wins before deadline", func(t *testing.T) {
		flow := newFlow(t)
		timeoutErr := errors.New("controlled late timeout")
		startTimeout := make(chan struct{})
		timeoutWon := make(chan bool, 1)
		go func() {
			<-startTimeout
			timeoutWon <- flow.completeOpenLocally(timeoutErr)
		}()

		if !flow.completeOpenFrame(mesh.DataTypeStreamOpenOK, nil) {
			t.Fatal("OPEN_OK did not win the pending OPEN transition")
		}
		close(startTimeout)
		if <-timeoutWon {
			t.Fatal("deadline replaced an already committed OPEN_OK")
		}
		if got := <-flow.openResult; got != nil {
			t.Fatalf("published OPEN result = %v, want success", got)
		}
		if !flow.shouldAcknowledgeOpenResult(mesh.DataTypeStreamOpenOK) {
			t.Fatal("committed OPEN_OK was not ACKable")
		}
		if !flow.isOpened() {
			t.Fatal("committed OPEN_OK did not mark the flow opened")
		}
	})
}

func TestOpenResultTimeoutIncludesDialAndFrameTimeouts(t *testing.T) {
	if got, want := saturatingDurationAdd(2*time.Second, 3*time.Second), 5*time.Second; got != want {
		t.Fatalf("normal timeout sum = %s, want %s", got, want)
	}
	const maxDuration = time.Duration(1<<63 - 1)
	if got := saturatingDurationAdd(maxDuration-time.Second, 2*time.Second); got != maxDuration {
		t.Fatalf("overflowing timeout sum = %s, want saturation at %s", got, maxDuration)
	}
}

func TestTCPFlowFutureACKCannotPreconfirmCurrentOrNextSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ackDelivered := make(chan uint64, 8)
	nodeA := newMeshNode(t, mesh.NodeConfig{
		NodeID: "send-A", Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventDelivered && event.Frame.Type == mesh.DataTypeStreamACK {
				ackDelivered <- event.Frame.Sequence
			}
		},
	})
	nodeB := newMeshNode(t, mesh.NodeConfig{NodeID: "send-B", Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond})
	attachDualTCPPair(t, nodeA, "send-B", nodeB, "send-A")
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, ctx, func() bool {
		_, forwardOK := nodeA.Route("send-B")
		_, reverseOK := nodeB.Route("send-A")
		return forwardOK && reverseOK
	}, "send test neighbors did not advertise reciprocal routes")

	endpointA := newEndpoint(t, nodeA)
	endpointB := newEndpoint(t, nodeB)
	forwarderA, err := NewTCPForwarderWithConfig(endpointA, TCPForwarderConfig{FrameTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderA.Close() })
	receivedData := make(chan mesh.DataFrame, 16)
	unregister, err := endpointB.RegisterHandler([]mesh.DataType{mesh.DataTypeStreamData}, func(_ context.Context, frame mesh.DataFrame) error {
		receivedData <- frame
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unregister)

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	flow := newTCPFlow(forwarderA, tcpFlowKey{peerID: "send-B", flowID: 77}, local, true, 0)
	flow.sendSeq = 1
	flow.markOpened()
	if !forwarderA.addFlow(flow) {
		t.Fatal("could not register send-test flow")
	}
	t.Cleanup(flow.shutdown)

	firstResult := make(chan error, 1)
	go func() { firstResult <- flow.send(mesh.DataTypeStreamData, []byte("first")) }()
	firstFrame := waitForStreamSequence(t, ctx, receivedData, 2)
	if string(firstFrame.Payload) != "first" {
		t.Fatalf("first DATA payload = %q", firstFrame.Payload)
	}
	sendTestACK(t, ctx, endpointB, "send-B", "send-A", flow.key.flowID, 3)
	waitForSequenceEvent(t, ctx, ackDelivered, 3)
	select {
	case err := <-firstResult:
		t.Fatalf("future ACK completed current send: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	sendTestACK(t, ctx, endpointB, "send-B", "send-A", flow.key.flowID, 2)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first send after exact ACK: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("first send did not accept its exact ACK: %v", ctx.Err())
	}

	secondResult := make(chan error, 1)
	go func() { secondResult <- flow.send(mesh.DataTypeStreamData, []byte("second")) }()
	secondFrame := waitForStreamSequence(t, ctx, receivedData, 3)
	if string(secondFrame.Payload) != "second" {
		t.Fatalf("second DATA payload = %q", secondFrame.Payload)
	}
	select {
	case err := <-secondResult:
		t.Fatalf("future ACK from prior pending send preconfirmed the next send: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	sendTestACK(t, ctx, endpointB, "send-B", "send-A", flow.key.flowID, 3)
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("second send after exact ACK: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("second send did not accept its exact ACK: %v", ctx.Err())
	}
}

func TestEndpointFlowSequenceStartsFromRandomNonzeroSeed(t *testing.T) {
	node := newMeshNode(t, mesh.NodeConfig{NodeID: "seed-test"})
	endpoint := newEndpoint(t, node)
	if seed := endpoint.flowSeq.Load(); seed == 0 {
		t.Fatal("Endpoint flow sequence seed is zero")
	}
	first := endpoint.nextFlowID()
	second := endpoint.nextFlowID()
	if first == 0 || second == 0 {
		t.Fatalf("generated flow IDs = %d, %d; both must be nonzero", first, second)
	}
	wantSecond := first + 1
	if wantSecond == 0 {
		wantSecond = 1
	}
	if second != wantSecond {
		t.Fatalf("second flow ID = %d, want %d after first %d", second, wantSecond, first)
	}
}

func TestTCPFlowDeadlineRecheckAcceptsRecordedACK(t *testing.T) {
	flow := &tcpFlow{}
	flow.beginPending(4)
	flow.acknowledge(4)
	if !flow.finishAcknowledgedAtDeadline(4) {
		t.Fatal("deadline recheck rejected an already-recorded ACK")
	}
	if flow.sendSeq != 4 {
		t.Fatalf("sendSeq after deadline recheck = %d, want 4", flow.sendSeq)
	}
	flow.clearPending(4)
	flow.beginPending(5)
	flow.acknowledge(6)
	if flow.finishAcknowledgedAtDeadline(5) {
		t.Fatal("deadline recheck accepted a sequence that was not ACKed")
	}
}

func waitForStreamSequence(t *testing.T, ctx context.Context, frames <-chan mesh.DataFrame, sequence uint64) mesh.DataFrame {
	t.Helper()
	for {
		select {
		case frame := <-frames:
			if frame.Sequence == sequence {
				return frame
			}
		case <-ctx.Done():
			t.Fatalf("did not receive stream sequence %d: %v", sequence, ctx.Err())
		}
	}
}

func waitForSequenceEvent(t *testing.T, ctx context.Context, sequences <-chan uint64, sequence uint64) {
	t.Helper()
	for {
		select {
		case got := <-sequences:
			if got == sequence {
				return
			}
		case <-ctx.Done():
			t.Fatalf("did not observe delivered ACK sequence %d: %v", sequence, ctx.Err())
		}
	}
}

func sendTestACK(t *testing.T, ctx context.Context, endpoint *Endpoint, source, destination string, flowID, sequence uint64) {
	t.Helper()
	err := endpoint.Send(ctx, mesh.DataFrame{
		Version: mesh.DataFrameVersion, Type: mesh.DataTypeStreamACK, HopLimit: 16,
		Source: source, Destination: destination, FlowID: flowID, Sequence: sequence,
	})
	if err != nil {
		t.Fatalf("send ACK sequence %d: %v", sequence, err)
	}
}
