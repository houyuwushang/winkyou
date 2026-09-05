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
