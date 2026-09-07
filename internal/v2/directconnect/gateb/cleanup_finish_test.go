package gateb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

// This is the cleanup authority truth table, not evidence of a durable write.
// The c1bproof composition separately exercises the real journal callback.
func TestCleanupHonorsPreviouslyDurableFinish(t *testing.T) {
	for _, controlled := range []bool{false, true} {
		for _, test := range []struct {
			name                   string
			burned, finished       bool
			badAuthorization       bool
			wantRelease, wantError bool
		}{
			{name: "preflight", wantRelease: true},
			{name: "durable_finish", burned: true, finished: true, wantRelease: true},
			{name: "missing_finish", burned: true},
			{name: "failed_finish", burned: true, badAuthorization: true, wantError: true},
		} {
			name := "attempt/" + test.name
			if controlled {
				name = "controller/" + test.name
			}
			t.Run(name, func(t *testing.T) {
				machine, peer, attempt := newCleanupFinishGovernor(t)
				r := &runtime{peer: peer, attempt: attempt, burned: test.burned, finishRecorded: test.finished}
				if test.badAuthorization {
					r.authorization = &governor.CommittedCarrierAuthorization{} // carries no authority
				}
				factory := &cleanupNoIOFactory{}
				if controlled {
					var err error
					r.controller, err = probeio.New(probeio.Config{Lease: attempt,
						Generation: probeio.NewGeneration(1), ExpectedGeneration: 1,
						Factory: factory, BuildVersion: "cleanup-finish-test"})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = r.controller.Close() })
				}
				err := r.cleanup(governor.PairingTerminalProtocolError)
				if (err != nil) != test.wantError {
					t.Fatalf("cleanup error presence=%t want=%t", err != nil, test.wantError)
				}
				// Repeated cleanup cannot turn missing/failed FINISH into release.
				if err := r.cleanup(governor.PairingTerminalProtocolError); err != nil {
					t.Fatalf("repeated cleanup failed: %v", err)
				}
				got := machine.Snapshot()
				want := 1
				if test.wantRelease {
					want = 0
				}
				if got.ActiveAttempts != want || got.ActivePeers != want || got.HeavyweightAttempts != want ||
					(got.Reserved == (governor.Resources{})) != test.wantRelease || got.SafetyTrip.BlocksActiveWork ||
					(r.attempt == nil && r.peer == nil) != test.wantRelease || r.finishRecorded != test.finished || factory.calls != 0 {
					t.Fatalf("cleanup authority mismatch: finished=%t release_expected=%t peers=%d attempts=%d heavy=%d reserved=%+v trip=%t opens=%d",
						r.finishRecorded, test.wantRelease, got.ActivePeers, got.ActiveAttempts, got.HeavyweightAttempts,
						got.Reserved, got.SafetyTrip.BlocksActiveWork, factory.calls)
				}
			})
		}
	}
}

func newCleanupFinishGovernor(t *testing.T) (*governor.Governor, *governor.PeerLease, *governor.AttemptLease) {
	t.Helper()
	namespace := t.TempDir()
	// Same synthetic clear-state format used by probeio's real-governor tests;
	// no canonical namespace or actual machine safety state is touched.
	record := governor.SafetyTripRecord{SchemaVersion: 1, State: governor.SafetyTripClear,
		UpdatedAt: time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(payload)
	envelope, err := json.Marshal(struct {
		Record   governor.SafetyTripRecord `json:"record"`
		Checksum string                    `json:"checksum"`
	}{record, hex.EncodeToString(checksum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(namespace, "safety-trip.json"), append(append([]byte{'C'}, envelope...), '\n'), 0o600); err != nil {
		t.Fatal("initialize private test safety state")
	}
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "cleanup-finish-test")
	if err != nil {
		t.Fatal("acquire private test owner")
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = machine.Close() })
	peer, err := machine.AcquirePeer("cleanup-peer")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), governor.AttemptRequest{
		ID: "cleanup-attempt", Operation: governor.OperationConnectTest,
		Cost: governor.AttemptCost{Duration: 10 * time.Second, Heavyweight: true,
			Resources: governor.Resources{Sockets: 1, Targets: 1, FiveTuples: 1, Packets: 3, PacketsPerSecond: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return machine, peer, attempt
}

type cleanupNoIOFactory struct{ calls int }

func (f *cleanupNoIOFactory) Open(context.Context) (probeio.Datagram, error) {
	f.calls++
	return nil, errors.New("cleanup proof must not open a socket")
}
