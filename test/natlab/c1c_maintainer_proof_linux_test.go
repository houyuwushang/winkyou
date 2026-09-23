//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Only the two C1c proof roots use this adapter. CI retains the original
// guard, including its original cleanup. Required flags remain independent.
func requireC1cProofEnvironment(t *testing.T) func(func(*testing.T)) func(*testing.T) {
	t.Helper()
	if _, present := os.LookupEnv(c1cMaintainerProofEnv); present {
		// Must run before requireGateB3Environment: its namespace capability
		// probe itself touches the named namespace registry.
		guard := requireC1cMaintainerHostProof(t)
		requireGateB3Environment(t)
		return guard
	}
	if mode, err := c1cHostProofMode(c1cProofInput{Env: c1cProofEnvironment()}); err != nil || mode != "ci" {
		t.Fatal("c1c_proof_attestation")
	}
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	return func(test func(*testing.T)) func(*testing.T) { return test }
}

func c1cProofEnvironment() map[string]string {
	env := make(map[string]string)
	for _, entry := range os.Environ() {
		if key, value, ok := strings.Cut(entry, "="); ok {
			env[key] = value
		}
	}
	return env
}

func requireC1cMaintainerHostProof(t *testing.T) func(func(*testing.T)) func(*testing.T) {
	t.Helper()
	in := c1cProofInput{Env: c1cProofEnvironment(), EUID: os.Geteuid()}
	// Reject mixed/invalid declarations even when subsequent read-only probes
	// cannot complete. Error strings never include paths or environment values.
	for key := range c1cCIAttestations {
		if _, present := in.Env[key]; present {
			t.Fatal("c1c_proof_mixed_attestation")
		}
	}
	if in.Env[c1cMaintainerProofEnv] != "1" || in.EUID != 0 {
		t.Fatal("c1c_proof_attestation_or_root")
	}
	for _, item := range []struct {
		path  string
		inode *uint64
	}{
		{"/proc/self/ns/net", &in.SelfNet}, {"/proc/1/ns/net", &in.InitNet},
		{"/proc/self/ns/mnt", &in.SelfMount}, {"/proc/1/ns/mnt", &in.InitMount},
	} {
		var stat unix.Stat_t
		if unix.Stat(item.path, &stat) != nil {
			t.Fatal("c1c_proof_namespace_read")
		}
		*item.inode = stat.Ino
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal("c1c_proof_mountinfo_read")
	}
	in.MountInfo = string(mounts)
	in.Registry, err = filepath.EvalSymlinks("/var/run/netns")
	if err != nil {
		t.Fatal("c1c_proof_registry_read")
	}
	if info, err := os.Lstat(in.Env["TMPDIR"]); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			in.Temp = c1cProofTempStat{Exists: true, Directory: info.IsDir(), UID: stat.Uid, Mode: info.Mode()}
		}
	}
	if mode, err := c1cHostProofMode(in); err != nil || mode != "maintainer" {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("c1c_proof_attestation")
	}
	original, err := readGateB3ConntrackMax("")
	if err != nil || original <= 0 {
		t.Fatal("c1c_proof_ceiling_read")
	}
	check := func(t *testing.T) {
		t.Helper()
		current, err := readGateB3ConntrackMax("")
		if err != nil || current != original {
			t.Error("c1c_proof_ceiling_changed")
		}
	}
	t.Cleanup(func() { check(t) })
	return func(test func(*testing.T)) func(*testing.T) {
		return func(t *testing.T) {
			// First registration runs last, after all child-owned drains.
			t.Cleanup(func() { check(t) })
			test(t)
		}
	}
}
