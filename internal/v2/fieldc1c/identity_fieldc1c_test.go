//go:build fieldc1c

package fieldc1c

import (
	"errors"
	"testing"
	"time"
)

func TestFieldWintunIdentityGolden(t *testing.T) {
	// Independent SHA-256 vectors: decoded instance ID is bytes 1 through 16.
	for _, tc := range []struct{ role, name, guid string }{
		{"initiator", "wcf07a50348ce89", "bc505672-37a8-d965-6a5c-73f9efa00256"},
		{"responder", "wcff4efcb41bf48", "653a9f1e-ed90-6e75-c74a-4d2b9780fa31"},
	} {
		t.Run(tc.role, func(t *testing.T) {
			name, guid, err := deriveWintunIdentity("AQIDBAUGBwgJCgsMDQ4PEA", tc.role)
			if err != nil || name != tc.name || guid != tc.guid || len(name) != 15 {
				t.Fatal("role-separated identity golden mismatch")
			}
			now := time.Now()
			instance := Instance{value: &validated{doc: document{InstanceID: "AQIDBAUGBwgJCgsMDQ4PEA"}, role: tc.role,
				notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Minute)}}
			actualName, actualGUID, err := instance.WintunIdentity()
			if err != nil || actualName != name || actualGUID != guid {
				t.Fatal("valid instance projection differs from golden")
			}
			instance.value.notAfter = now.Add(-time.Second)
			if n, g, err := instance.WintunIdentity(); !errors.Is(err, ErrInvalid) || n != "" || g != "" {
				t.Fatal("expired instance exposed derived identity")
			}
		})
	}
}

func TestFieldWintunIdentityRejectsMalformedAndZero(t *testing.T) {
	for _, tc := range [][2]string{
		{"", "initiator"}, {"AQIDBAUGBwgJCgsMDQ4PEA==", "initiator"},
		{"AQIDBAUGBwgJCgsMDQ4PEB", "initiator"}, {"AQID", "initiator"},
		{"AQIDBAUGBwgJCgsMDQ4PEA", ""}, {"AQIDBAUGBwgJCgsMDQ4PEA", "router"},
	} {
		if n, g, err := deriveWintunIdentity(tc[0], tc[1]); !errors.Is(err, ErrInvalid) || n != "" || g != "" {
			t.Fatal("invalid identity input accepted")
		}
	}
	if n, g, err := (Instance{}).WintunIdentity(); !errors.Is(err, ErrInvalid) || n != "" || g != "" {
		t.Fatal("zero instance issued identity")
	}
}
