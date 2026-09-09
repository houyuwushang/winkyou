//go:build linux && natlab && c1bproof

package natlab

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/oobcarrier"
)

// Only the fault fixtures insert one real, harness-owned OS pipe at the child
// stdio boundary. The product still adopts a *File through the unchanged New;
// faults close the OTHER end, never a poisoned alias of the adopted descriptor.
// Normal six SSH/netns profiles continue using inherited stdin/stdout directly.
type gateC1bPeerFaultWitness struct {
	PeerClosed       bool `json:"peer_closed"`
	EOF              bool `json:"eof"`
	EPIPE            bool `json:"epipe"`
	Written          int  `json:"written"`
	Forwarded        int  `json:"forwarded"`
	PrefixForwarded  bool `json:"prefix_forwarded"`
	ForwarderDrained bool `json:"forwarder_drained"`
}

type gateC1bPeerFault struct {
	mu                  sync.Mutex
	witness             gateC1bPeerFaultWitness
	peer, adopted, sink *os.File
	forwardDone         chan struct{}
	changed             chan struct{}
	forwardErr          error
}

func newGateC1bPeerFault(mode string, deadline time.Time) (*gateC1bPeerFault, io.Reader, io.Writer, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, errors.New("fault pipe creation failed")
	}
	fault := &gateC1bPeerFault{changed: make(chan struct{}, 1)}
	if mode == "pre-finish-eof" {
		// No pairing byte is legal before this injection. The substituted input
		// therefore needs no forwarder; closing its write end creates real EOF.
		fault.adopted, fault.peer = read, write
		return fault, read, os.Stdout, nil
	}
	if mode != "writer-error" {
		_ = read.Close()
		_ = write.Close()
		return nil, nil, nil, errors.New("unknown pipe fault")
	}
	// The SSH-owned stdout is only the sink for the bounded pre-fault prefix.
	// Reopen this exact existing FIFO as a pollable file so closing the test
	// forwarder never recreates the original inherited-blocking-I/O defect.
	// No arbitrary path, network connection, SSH process or protocol is added.
	sink, err := os.OpenFile("/proc/self/fd/1", os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = read.Close()
		_ = write.Close()
		return nil, nil, nil, errors.New("fault stdout peer unavailable")
	}
	info, statErr := sink.Stat()
	if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 || sink.SetWriteDeadline(deadline) != nil || os.Stdout.Close() != nil {
		_ = read.Close()
		_ = write.Close()
		_ = sink.Close()
		return nil, nil, nil, errors.New("fault stdout peer cannot be bounded")
	}
	fault.adopted, fault.peer, fault.sink = write, read, sink
	fault.forwardDone = make(chan struct{})
	go fault.forwardPrefix()
	return fault, os.Stdin, write, nil
}

func (fault *gateC1bPeerFault) forwardPrefix() {
	defer close(fault.forwardDone)
	buffer := make([]byte, 1024)
	defer clear(buffer)
	for {
		n, readErr := fault.peer.Read(buffer)
		if n > 0 {
			fault.mu.Lock()
			within := fault.witness.Forwarded+n <= oobcarrier.MaxApplicationBytes
			fault.mu.Unlock()
			if !within {
				fault.forwardErr = errors.New("fault prefix exceeded carrier ceiling")
				return
			}
			written, err := fault.sink.Write(buffer[:n])
			fault.mu.Lock()
			fault.witness.Forwarded += written
			fault.mu.Unlock()
			select {
			case fault.changed <- struct{}{}:
			default:
			}
			if err != nil || written != n {
				fault.forwardErr = errors.New("fault prefix forwarding failed")
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// This callback sees only the actual Read/Write result of the product's
// already-adopted bounded stream. It neither substitutes errors nor sends data.
func (fault *gateC1bPeerFault) observe(write bool, n int, err error) {
	fault.mu.Lock()
	defer fault.mu.Unlock()
	if write {
		fault.witness.Written += n
		fault.witness.EPIPE = fault.witness.EPIPE || errors.Is(err, unix.EPIPE)
	} else {
		fault.witness.EOF = fault.witness.EOF || errors.Is(err, io.EOF)
	}
}

func (fault *gateC1bPeerFault) inject(ctx context.Context) error {
	if fault.forwardDone != nil {
		// Do not cut a PREPARE still buffered in the local pipe: that would
		// create a different inbound timeout instead of the next Write's EPIPE.
		bounded, cancel := context.WithTimeout(ctx, gatecorchestrator.SessionDrainTimeout)
		defer cancel()
		for {
			fault.mu.Lock()
			ready := fault.witness.Written > 0 && fault.witness.Forwarded == fault.witness.Written
			fault.mu.Unlock()
			if ready {
				break
			}
			select {
			case <-fault.changed:
			case <-fault.forwardDone:
				return errors.New("fault prefix ended before injection")
			case <-bounded.Done():
				return errors.New("fault prefix was not forwarded before injection")
			}
		}
		fault.mu.Lock()
		fault.witness.PrefixForwarded = true
		fault.mu.Unlock()
	}
	if err := fault.peer.Close(); err != nil {
		return errors.New("fault peer close failed")
	}
	_, err := fault.peer.Stat()
	fault.mu.Lock()
	fault.witness.PeerClosed = errors.Is(err, os.ErrClosed)
	fault.mu.Unlock()
	return nil
}

func (fault *gateC1bPeerFault) close() (gateC1bPeerFaultWitness, error) {
	timer := time.NewTimer(gatecorchestrator.SessionDrainTimeout)
	defer timer.Stop()
	_ = fault.peer.Close()
	_ = fault.adopted.Close() // Already invalidated by the product adopter.
	if fault.sink != nil {
		_ = fault.sink.SetWriteDeadline(time.Now())
		_ = fault.sink.Close()
	}
	drained := true
	var err error
	if fault.forwardDone != nil {
		select {
		case <-fault.forwardDone:
			err = fault.forwardErr
		case <-timer.C:
			drained = false
			err = errors.New("fault forwarder did not drain")
		}
	}
	fault.mu.Lock()
	defer fault.mu.Unlock()
	fault.witness.ForwarderDrained = drained
	return fault.witness, err
}

func validGateC1bPeerFault(mode string, peer gateC1bProcessResult) bool {
	w, carrier := peer.PipeFault, peer.Product.Witness.GateB.CarrierWitness
	if peer.OK || peer.Class == "" || !w.PeerClosed || !w.ForwarderDrained || !carrier.Closed || !carrier.Drained {
		return false
	}
	if mode == "pre-finish-eof" {
		return w.EOF && carrier.EOF && !w.EPIPE && w.Written == 0 && w.Forwarded == 0 && !peer.Product.CredentialBurned
	}
	return mode == "writer-error" && w.EPIPE && w.PrefixForwarded && w.Forwarded > 0 &&
		w.Forwarded == w.Written && w.Written <= oobcarrier.MaxApplicationBytes &&
		peer.Product.CredentialBurned && peer.Product.Witness.GateB.FinishRecorded
}

func testGateC1bPipeFaultWitnessRejectsNoopInjection(t *testing.T) {
	for _, mode := range []string{"pre-finish-eof", "writer-error"} {
		peer := gateC1bProcessResult{Class: gateb.ClassOOBStreamClosed}
		peer.Product.Witness.GateB.CarrierWitness = oobcarrier.Witness{Closed: true, Drained: true, EOF: mode == "pre-finish-eof"}
		peer.PipeFault = gateC1bPeerFaultWitness{PeerClosed: true, ForwarderDrained: true}
		if mode == "pre-finish-eof" {
			peer.PipeFault.EOF = true
		} else {
			peer.PipeFault.EPIPE, peer.PipeFault.PrefixForwarded = true, true
			peer.PipeFault.Written, peer.PipeFault.Forwarded = 123, 123
			peer.Product.CredentialBurned, peer.Product.Witness.GateB.FinishRecorded = true, true
		}
		if !validGateC1bPeerFault(mode, peer) {
			t.Fatal("valid witness rejected")
		}
		for _, mutate := range []func(*gateC1bProcessResult){
			func(p *gateC1bProcessResult) { p.PipeFault.PeerClosed = false },
			func(p *gateC1bProcessResult) { p.PipeFault.EOF, p.PipeFault.EPIPE = false, false },
			func(p *gateC1bProcessResult) { p.PipeFault.ForwarderDrained = false },
			func(p *gateC1bProcessResult) { p.Product.Witness.GateB.CarrierWitness.Drained = false },
			func(p *gateC1bProcessResult) { p.PipeFault.Forwarded++ },
			func(p *gateC1bProcessResult) { p.Product.CredentialBurned = !p.Product.CredentialBurned },
		} {
			invalid := peer
			mutate(&invalid)
			if validGateC1bPeerFault(mode, invalid) {
				t.Fatal("missing physical fault/drain witness accepted")
			}
		}
	}
}
