//go:build linux && fieldc1c

package tunnel

import (
	"testing"
	"winkyou/pkg/netif"
)

func TestFieldWireGuardRejectsUnownedInterfaceAndNativeBind(t *testing.T) {
	for _, config := range []Config{{}, {Interface: &netif.FieldInterface{}}, {Interface: &netif.FieldInterface{}, ListenPort: 51820}} {
		if _, err := NewFieldWireGuard(config); err == nil {
			t.Fatal("unowned or native-bind field tunnel accepted")
		}
	}
}

func TestFieldWireGuardEvidenceDoesNotChangeErrorsOrInterfaces(t *testing.T) {
	field := &fieldWGGoTunnel{wggoTunnel: newWGGoTunnel(Config{})}
	if field.Start() == nil || field.AddPeer(nil) == nil {
		t.Fatal("diagnostic wrapper suppressed rejection")
	}
	witness := FieldWireGuardSnapshot(field)
	if !witness.StartCalled || witness.StartSucceeded || !witness.PeerCalled || witness.PeerSucceeded {
		t.Fatal("diagnostic outcomes changed")
	}
	if FieldWireGuardSnapshot(nil) != (FieldWireGuardWitness{}) {
		t.Fatal("missing owner invented evidence")
	}
	if _, ok := any(field).(OneShotHandshakeInitiator); !ok {
		t.Fatal("field wrapper lost the existing one-shot handshake interface")
	}
}
