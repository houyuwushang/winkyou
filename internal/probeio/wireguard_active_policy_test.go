package probeio

import (
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func activePolicyGate(t *testing.T) (*WireGuardSessionGate, *wireGuardGateTransport) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	io := newWireGuardGateTransport()
	gate := &WireGuardSessionGate{state: WireGuardGateActive, finishRecorded: true, detached: true, activeCtx: ctx, activeStop: stop, transport: io}
	t.Cleanup(func() { _ = gate.Close() })
	return gate, io
}
func activePacket(typ uint32, size int) []byte {
	b := make([]byte, size)
	if size >= 4 {
		binary.LittleEndian.PutUint32(b, typ)
	}
	return b
}

func TestActiveSessionPolicyPerWritePermitAndNoBackgroundEscape(t *testing.T) {
	gate, io := activePolicyGate(t)
	var expired atomic.Bool
	denied := errors.New("expired local permit")
	checks := 0
	if err := gate.ArmActivePolicy(ActiveSessionPolicy{Ceiling: time.Minute, Permit: func() error {
		checks++
		if expired.Load() {
			return denied
		}
		return nil
	}, Elapsed: func() time.Duration { return 0 }, Report: func(SessionViolation) error { t.Error("expiry is not a trip"); return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := gate.WritePacket(context.Background(), activePacket(4, 128)); err != nil {
		t.Fatal(err)
	}
	expired.Store(true)
	if err := gate.WritePacket(context.Background(), activePacket(4, 128)); !errors.Is(err, denied) {
		t.Fatal("expired write accepted")
	}
	if io.writeCount() != 1 || checks != 2 || !io.isClosed() {
		t.Fatal("permit bypass or undrained transport")
	}
}

func TestActiveSessionControlLaneRollingAndTotalBeforeWrite(t *testing.T) {
	for _, total := range []bool{false, true} {
		t.Run(map[bool]string{false: "rolling", true: "total"}[total], func(t *testing.T) {
			gate, io := activePolicyGate(t)
			now := time.Duration(0)
			trips := 0
			if err := gate.ArmActivePolicy(ActiveSessionPolicy{Ceiling: 5 * time.Second, Permit: func() error { return nil }, Elapsed: func() time.Duration { return now }, Report: func(v SessionViolation) error {
				if v != SessionControlLimit {
					t.Fatal("wrong violation")
				}
				trips++
				return nil
			}}); err != nil {
				t.Fatal(err)
			}
			limit := 4
			if total {
				limit = 20
			}
			for i := 0; i < limit; i++ {
				if total {
					now = time.Duration(i/4) * time.Second
				}
				if err := gate.WritePacket(context.Background(), activePacket(4, 32)); err != nil {
					t.Fatal(err)
				}
			}
			if total {
				now = 5 * time.Second
			}
			if err := gate.WritePacket(context.Background(), activePacket(1, 148)); !errors.Is(err, ErrSessionControlLimit) {
				t.Fatalf("excess=%v", err)
			}
			w := gate.Witness().ActivePolicy
			if io.writeCount() != limit || trips != 1 || w.ControlAdmitted != uint64(limit) || w.ControlRejected != 1 || !io.isClosed() {
				t.Fatal("lane did not stop before excess write")
			}
		})
	}
}

func TestActiveSessionControlStrictLengthsAndDataExcluded(t *testing.T) {
	for _, c := range []struct {
		typ   uint32
		size  int
		valid bool
	}{{1, 148, true}, {2, 92, true}, {3, 64, true}, {4, 32, true}, {4, 128, true}, {4, 1000, true}, {1, 147, false}, {1, 149, false}, {2, 148, false}, {3, 63, false}, {4, 31, false}, {5, 128, false}, {0, 0, false}} {
		gate, io := activePolicyGate(t)
		trips := 0
		if err := gate.ArmActivePolicy(ActiveSessionPolicy{Ceiling: time.Minute, Permit: func() error { return nil }, Elapsed: func() time.Duration { return 0 }, Report: func(SessionViolation) error { trips++; return nil }}); err != nil {
			t.Fatal(err)
		}
		err := gate.WritePacket(context.Background(), activePacket(c.typ, c.size))
		if (err == nil) != c.valid {
			t.Fatalf("type=%d size=%d accepted=%v", c.typ, c.size, err == nil)
		}
		if !c.valid && (io.writeCount() != 0 || trips != 1) {
			t.Fatal("invalid packet reached transport")
		}
		if c.valid && c.typ == 4 && c.size > 32 {
			for i := 0; i < 10; i++ {
				if err := gate.WritePacket(context.Background(), activePacket(4, c.size)); err != nil {
					t.Fatal(err)
				}
			}
			if gate.Witness().ActivePolicy.ControlAdmitted != 0 {
				t.Fatal("business data charged as automatic control")
			}
		}
	}
}

func TestActiveSessionPolicyWriterFailureReportsAndCloses(t *testing.T) {
	gate, io := activePolicyGate(t)
	trips := 0
	if err := gate.ArmActivePolicy(ActiveSessionPolicy{Ceiling: time.Minute, Permit: func() error { return nil }, Elapsed: func() time.Duration { return 0 }, Report: func(v SessionViolation) error {
		if v != SessionWriterFailure {
			t.Fatal("wrong writer violation")
		}
		trips++
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	_ = io.Close()
	if gate.WritePacket(context.Background(), activePacket(4, 128)) == nil || trips != 1 || gate.Witness().ActivePolicy.WriterFailures != 1 {
		t.Fatal("writer failure not reported")
	}
}

func TestActiveSessionPolicyRequiresFinishDetachAndOneOwner(t *testing.T) {
	p := ActiveSessionPolicy{Ceiling: time.Minute, Permit: func() error { return nil }, Elapsed: func() time.Duration { return 0 }, Report: func(SessionViolation) error { return nil }}
	for _, state := range []WireGuardGateState{WireGuardGateStandby, WireGuardGateChallengeCapped, WireGuardGateChallengePassed, WireGuardGateFinishDetached, WireGuardGateClosed} {
		gate, _ := activePolicyGate(t)
		gate.state = state
		if gate.ArmActivePolicy(p) == nil {
			t.Fatal("early/closed policy arm")
		}
	}
	gate, _ := activePolicyGate(t)
	gate.finishRecorded = false
	if gate.ArmActivePolicy(p) == nil {
		t.Fatal("no FINISH accepted")
	}
	gate.finishRecorded = true
	gate.detached = false
	if gate.ArmActivePolicy(p) == nil {
		t.Fatal("no detach accepted")
	}
	gate.detached = true
	if gate.ArmActivePolicy(p) != nil || gate.ArmActivePolicy(p) == nil {
		t.Fatal("policy ownership is not single-use")
	}
	legacy, _ := activePolicyGate(t)
	if err := legacy.WritePacket(context.Background(), []byte("legacy unchanged")); err != nil {
		t.Fatal(err)
	}
	if legacy.Witness().ActivePolicy != nil {
		t.Fatal("nil policy changed legacy witness")
	}
}

// The orchestrator separately mutation-proves that Elapsed supplies the
// validated monotonic coordinate. This exercises the real per-write gate with
// that contract, including an RTC adjustment that used to look like a cap.
func TestActiveSessionMonotonicAccountingIsIndependentOfRTC(t *testing.T) {
	gate, transport := activePolicyGate(t)
	mono, utc := 20*time.Second, 22*time.Second
	reports := 0
	policy := ActiveSessionPolicy{Ceiling: time.Minute,
		Permit: func() error {
			if utc < mono-2*time.Second || utc > mono+2*time.Second {
				return errors.New("synthetic clock invalid")
			}
			return nil
		},
		Elapsed: func() time.Duration { return mono },
		Report:  func(SessionViolation) error { reports++; return nil },
	}
	if err := gate.ArmActivePolicy(policy); err != nil {
		t.Fatal(err)
	}
	for i, rtc := range []time.Duration{22 * time.Second, 20 * time.Second, 19 * time.Second, 22 * time.Second} {
		utc = rtc
		if err := gate.WritePacket(context.Background(), activePacket(4, 32)); err != nil {
			t.Fatalf("legal control %d after RTC adjustment: %v", i+1, err)
		}
	}
	if reports != 0 || transport.writeCount() != 4 {
		t.Fatal("RTC rollback caused a false hard report")
	}
	// UTC has advanced two seconds, but monotonic rolling 1s has NOT elapsed.
	if err := gate.WritePacket(context.Background(), activePacket(4, 32)); !errors.Is(err, ErrSessionControlLimit) {
		t.Fatal("RTC forward shift refreshed the one-second ledger")
	}
	w := gate.Witness().ActivePolicy
	if reports != 1 || transport.writeCount() != 4 || w.ControlAdmitted != 4 || w.ControlRejected != 1 || !transport.isClosed() {
		t.Fatal("true fifth control was not stopped and reported before write")
	}
}
