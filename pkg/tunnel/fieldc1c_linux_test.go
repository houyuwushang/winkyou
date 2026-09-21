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
