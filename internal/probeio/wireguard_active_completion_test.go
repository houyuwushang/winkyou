package probeio

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/pkg/transport"
)

// Return from the underlying I/O only AFTER close has won. The datagram has
// already completed successfully: close cannot retract it from the wire.
type activeCompletionTransport struct {
	transport.PacketTransport
	after func()
}

func (tr *activeCompletionTransport) WritePacket(ctx context.Context, packet []byte) error {
	err := tr.PacketTransport.WritePacket(ctx, packet)
	tr.after()
	return err
}

func (tr *activeCompletionTransport) ReadPacket(ctx context.Context, packet []byte) (int, transport.PacketMeta, error) {
	n, meta, err := tr.PacketTransport.ReadPacket(ctx, packet)
	tr.after()
	return n, meta, err
}

func TestActiveSessionCountsCompletedIOWhenCloseWinsBeforeBookkeeping(t *testing.T) {
	for _, policyEnabled := range []bool{false, true} {
		for _, direction := range []string{"write", "read"} {
			name := map[bool]string{false: "legacy", true: "liveness"}[policyEnabled] + "/" + direction
			t.Run(name, func(t *testing.T) {
				gate, underlying := activePolicyGate(t)
				gate.consumerReady = true
				if policyEnabled {
					if err := gate.ArmActivePolicy(ActiveSessionPolicy{
						Ceiling: time.Minute, Permit: func() error { return nil },
						Elapsed: func() time.Duration { return 0 },
						Report:  func(SessionViolation) error { t.Error("successful completion is not a trip"); return nil },
					}); err != nil {
						t.Fatal(err)
					}
				}
				gate.transport = &activeCompletionTransport{PacketTransport: underlying, after: func() {
					gate.mu.Lock()
					inFlight := gate.inFlight
					gate.mu.Unlock()
					if inFlight != 1 {
						t.Error("test did not stop between I/O and gate completion")
					}
					if err := gate.Close(); err != nil {
						t.Error(err)
					}
				}}
				packet := activePacket(4, 128)
				if direction == "write" {
					if err := gate.WritePacket(context.Background(), packet); err != nil || underlying.writeCount() != 1 {
						t.Fatal("test datagram did not complete before close")
					}
				} else {
					underlying.queueRead(packet)
					if n, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); err != nil || n != len(packet) {
						t.Fatal("test receive did not complete before close")
					}
				}
				w := gate.Witness()
				want := 0
				if policyEnabled {
					want = 1
				}
				if w.ActiveWrites+w.ActiveReads != want || !w.Closed || !underlying.isClosed() || gate.inFlight != 0 {
					t.Fatalf("completed datagram lost at close: writes=%d reads=%d want=%d closed=%v in_flight=%d", w.ActiveWrites, w.ActiveReads, want, w.Closed, gate.inFlight)
				}
				if err := gate.WritePacket(context.Background(), packet); !errors.Is(err, ErrWireGuardGateState) || underlying.writeCount() > 1 {
					t.Fatal("counting completion must not permit any new write after close")
				}
			})
		}
	}
}
