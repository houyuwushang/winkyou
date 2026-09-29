//go:build fieldc1c

package fieldc1c

import (
	"runtime/debug"
	"testing"
)

func TestFieldToolsDependencyDigestUsesInstanceImplementation(t *testing.T) {
	doc, build, now := fixtureDocument(t)
	info := &debug.BuildInfo{Deps: []*debug.Module{{Path: "synthetic-module", Version: "v1", Sum: "synthetic-sum"}}}
	digest, err := DependencyConfigurationDigest(info, [2]string{doc.Devices[0].ConfigurationSHA256, doc.Devices[1].ConfigurationSHA256})
	if err != nil || digest != doc.DependencyAndConfigurationSHA256 {
		t.Fatal("tool and instance dependency digests differ")
	}
	doc.DependencyAndConfigurationSHA256 = digest
	if _, err := validate(encodeFixture(t, doc), "initiator", now, build); err != nil {
		t.Fatal("derived digest rejected by the Load validation core")
	}
	// Deliberately wrong role ordering must not match or pass Load's validator.
	wrong, err := DependencyConfigurationDigest(info, [2]string{doc.Devices[1].ConfigurationSHA256, doc.Devices[0].ConfigurationSHA256})
	if err != nil || wrong == digest {
		t.Fatal("role order lost")
	}
	doc.DependencyAndConfigurationSHA256 = wrong
	if _, err := validate(encodeFixture(t, doc), "initiator", now, build); err == nil {
		t.Fatal("different implementation's digest accepted")
	}
}
