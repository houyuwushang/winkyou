//go:build fieldc1c

package fieldc1c

import (
	"runtime/debug"
	"strings"
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

func TestFieldToolsDigestRejectsAmbiguousDependencies(t *testing.T) {
	hashes := [2]string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	for _, info := range []*debug.BuildInfo{nil,
		{Deps: []*debug.Module{nil}},
		{Deps: []*debug.Module{{Path: "synthetic", Replace: &debug.Module{Path: "other"}}}},
		{Deps: []*debug.Module{{Path: "same"}, {Path: "same"}}},
		{Deps: []*debug.Module{{Path: "synthetic\x00other"}}},
	} {
		if _, err := DependencyConfigurationDigest(info, hashes); err == nil {
			t.Fatal("ambiguous dependency accepted")
		}
	}
	left := &debug.BuildInfo{Deps: []*debug.Module{{Path: "z"}, {Path: "a"}}}
	right := &debug.BuildInfo{Deps: []*debug.Module{{Path: "a"}, {Path: "z"}}}
	a, err1 := DependencyConfigurationDigest(left, hashes)
	b, err2 := DependencyConfigurationDigest(right, hashes)
	if err1 != nil || err2 != nil || a != b {
		t.Fatal("module order changed digest")
	}
	hashes[0] = "invalid"
	if _, err := DependencyConfigurationDigest(left, hashes); err == nil {
		t.Fatal("invalid config hash accepted")
	}
}
