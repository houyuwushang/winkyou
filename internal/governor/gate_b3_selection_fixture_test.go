package governor_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatcontrol"
	"winkyou/internal/v2/rendezvouswire"
)

// Capture the inherited punch-context deadline on the first real candidate,
// not the earlier progress callback: the sender may be descheduled in between.
// probeio only merges cancellation here, so its operation context retains the
// actual candidate deadline. Forward the original context and packet unchanged.
type gateB3CandidateDeadlineFactory struct {
	base     probeio.Factory
	witness  *gateB3DelayedWriteConn
	side     int
	observed atomic.Bool
}

func (factory *gateB3CandidateDeadlineFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	datagram, err := factory.base.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &gateB3CandidateDeadlineDatagram{Datagram: datagram, owner: factory}, nil
}

type gateB3CandidateDeadlineDatagram struct {
	probeio.Datagram
	owner *gateB3CandidateDeadlineFactory
}

func (datagram *gateB3CandidateDeadlineDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if !datagram.owner.observed.Load() {
		metadata, err := hardnatcontrol.InspectFrame(packet)
		if err == nil && metadata.Type == hardnatcontrol.FrameCandidate && datagram.owner.observed.CompareAndSwap(false, true) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return 0, errors.New("candidate fixture is missing a context deadline")
			}
			datagram.owner.witness.recordCandidateDeadline(datagram.owner.side, deadline)
		}
	}
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

func TestGateB3SelectionDelayIdentifiesFirstResponderStatus(t *testing.T) {
	// A structurally valid encrypted-frame header suffices for classification;
	// the actual integration test still authenticates real protocol frames.
	header, err := hex.DecodeString("575948420101080200000000000040110000000000000010")
	if err != nil {
		t.Fatal(err)
	}
	control := append(header, make([]byte, 16)...)
	encode := func(payload []byte) []byte {
		frame, err := rendezvouswire.EncodeForProfile(rendezvouswire.CallerProvidedStreamProfile, rendezvouswire.KindControl, payload)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	selection := encode(control)
	other := append([]byte(nil), control...)
	other[6] = byte(hardnatcontrol.FramePrepare)
	initiator := append([]byte(nil), control...)
	initiator[7] = 1
	nonSelection := [][]byte{encode(other), encode(initiator), selection[:len(selection)-1], append(append([]byte(nil), selection...), 0)}
	for _, ordinal := range []int{1, 7, 9} {
		t.Run(fmt.Sprintf("selection_write_%d", ordinal), func(t *testing.T) {
			sink := &gateB3SelectionWriteSink{}
			delayed := &gateB3DelayedWriteConn{Conn: sink, startedAt: time.Now()}
			write := func(payload []byte) {
				t.Helper()
				n, err := delayed.Write(payload)
				if err != nil || n != len(payload) || !bytes.Equal(sink.payload, payload) {
					t.Fatal("delay wrapper changed a write")
				}
			}
			for index := 1; index < ordinal; index++ {
				write(nonSelection[(index-1)%len(nonSelection)])
				if delayed.triggered.Load() {
					t.Fatalf("non-selection write %d triggered the delay", index)
				}
			}
			write(selection)
			if !delayed.triggered.Load() {
				t.Fatal("responder selection did not trigger the delay")
			}
			write(selection)
			delays := 0
			for _, event := range delayed.writeEvents() {
				if event.delayed {
					delays++
					if event.ordinal != ordinal || event.frameType != hardnatcontrol.FrameWinnerSelection {
						t.Fatal("wrong frame was delayed")
					}
				}
			}
			if delays != 1 {
				t.Fatalf("delayed %d frames, want only the first status", delays)
			}
		})
	}
}

type gateB3SelectionWriteSink struct {
	net.Conn
	payload []byte
}

func (sink *gateB3SelectionWriteSink) Write(payload []byte) (int, error) {
	sink.payload = append(sink.payload[:0], payload...)
	return len(payload), nil
}
