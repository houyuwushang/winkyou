package client

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/config"
	coordclient "winkyou/pkg/coordinator/client"
	"winkyou/pkg/logger"
	sesspkg "winkyou/pkg/session"
)

// RED witness for the old synchronous persistState: ordinary snapshot I/O
// must not hold any control callback hostage. The fixed one-second test guard
// is not a change to selection, heartbeat, transport or governor deadlines.
func TestRuntimeSnapshotIOCannotBlockControlCallbacks(t *testing.T) {
	callbacks := []struct {
		name string
		run  func(*engine)
	}{
		{"signal", func(e *engine) {
			e.handleSignal(&coordclient.SignalNotification{FromNode: "synthetic-peer", Type: coordclient.SignalType(99)})
		}},
		{"heartbeat_peer_update", func(e *engine) {
			e.handlePeerUpdate(&coordclient.PeerInfo{NodeID: "synthetic-peer", Online: false}, coordclient.PeerEventUpsert)
		}},
		{"selection_state", func(e *engine) {
			e.handlePeerSessionState("synthetic-peer", &peerSession{}, sesspkg.StateSelecting)
		}},
	}
	for _, test := range callbacks {
		t.Run(test.name, func(t *testing.T) {
			e := &engine{cfg: config.Default(), log: logger.Nop(), started: true, statePath: filepath.Join(t.TempDir(), "snapshot.yaml"), status: EngineStatus{NodeID: "synthetic-local"}, peers: map[string]*PeerStatus{"synthetic-peer": {NodeID: "synthetic-peer"}}}
			release, err := lockRuntimeFile(e.statePath, false)
			if err != nil {
				t.Fatal(err)
			}
			var unlockOnce sync.Once
			unlock := func() { unlockOnce.Do(release) }
			done := make(chan struct{})
			t.Cleanup(func() {
				unlock()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("control callback did not drain after releasing the test lock")
				}
				if err := e.Stop(); err != nil {
					t.Errorf("Stop: %v", err)
				}
			})
			go func() { defer close(done); test.run(e) }()
			select {
			case <-done:
				t.Log("snapshot_io_blocked=true control_callback_returned=true")
			case <-time.After(time.Second):
				t.Fatal("ordinary snapshot I/O blocked the control callback")
			}
		})
	}
}
