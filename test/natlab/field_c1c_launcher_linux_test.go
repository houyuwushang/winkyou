//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/pairgen"
)

// The existing C role-view probe and the real field proof cover separate
// interfaces. This fixture joins the unchanged full launcher to the real,
// exact-build field ELF, including its parent's pin and the child's /root bind.
// Material is synthetic and remains below the existing disposable CI fixture.
func fieldC1cLauncherFixture(t *testing.T, cfg fieldC1cHostConfig, binary, mode string) fieldC1cHostConfig {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.LauncherRoot, cfg.LauncherMode = root, mode
	attempt := strings.TrimSuffix(filepath.Base(cfg.Instance), ".json")
	base := filepath.Join(root, "c1c")
	role := filepath.Join(base, "endpoints", "initiator")
	evidence := filepath.Join(base, "evidence", attempt, "endpoint-initiator")
	for _, path := range []string{
		role + "/var-lib", role + "/install/winkyou", role + "/home", role + "/run/netns",
		filepath.Join(cfg.Host.HomeDirectory, ".winkyou-field/c1c/material"),
		filepath.Join(cfg.Host.HomeDirectory, ".winkyou-field/c1c/evidence"),
		filepath.Join(base, "material", attempt, "initiator"), evidence, root + "/registry",
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"wink", "gate-c-child-wrapper"} {
		copyGateC1bBinary(t, binary, filepath.Join(role, "install/winkyou", name))
	}
	for name, source := range map[string]string{"machine-id": cfg.MachineIDFile, "shadow": cfg.Host.ShadowFile} {
		raw, err := os.ReadFile(source)
		if err != nil || pairgen.WritePrivateFileExclusive(filepath.Join(role, name), raw) != nil {
			t.Fatal("launcher role identity copy failed")
		}
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Host.HomeDirectory, ".winkyou-field/c1c", attempt+".json"))
	if err != nil {
		t.Fatal("launcher instance read failed")
	}
	if mode == "bad_hash" {
		var document map[string]any
		if json.Unmarshal(raw, &document) != nil {
			t.Fatal("launcher instance decode failed")
		}
		document["initiator_binary_sha256"] = strings.Repeat("0", 64)
		raw, err = json.Marshal(document)
		if err != nil || os.WriteFile(filepath.Join(cfg.Host.HomeDirectory, ".winkyou-field/c1c", attempt+".json"), raw, 0o600) != nil {
			t.Fatal("synthetic hash mutation failed")
		}
	}
	if pairgen.WritePrivateFileExclusive(filepath.Join(base, attempt+".json"), raw) != nil {
		t.Fatal("launcher instance copy failed")
	}
	marker, _ := json.Marshal(map[string]string{"schema": "winkyou-c1c-role-init/1", "role": "initiator", "image_sha256": fieldC1cFileDigest(t, binary)})
	if pairgen.WritePrivateFileExclusive(filepath.Join(role, "initialized.json"), marker) != nil {
		t.Fatal("launcher role marker failed")
	}
	if mode == "replaced" {
		// In the child this file occupies the pathname of the original pin.
		// Its bytes must never be used as the running ELF's build witness.
		replacement := filepath.Join(cfg.Host.HomeDirectory, ".winkyou-field/c1c/endpoints/initiator/install/winkyou/wink")
		if os.MkdirAll(filepath.Dir(replacement), 0o700) != nil ||
			pairgen.WritePrivateFileExclusive(replacement, []byte("different image at the original pathname\n")) != nil {
			t.Fatal("launcher replacement fixture failed")
		}
	}
	cfg.Evidence = filepath.Join(evidence, attempt, "endpoint.jsonl")
	return cfg
}

func fieldC1cLauncherAnchor(cfg fieldC1cHostConfig) string {
	attempt := strings.TrimSuffix(filepath.Base(cfg.Instance), ".json")
	sum := sha256.Sum256([]byte("winkyou-c1c-anchor/1\n" + attempt))
	return fmt.Sprintf("wyc1c%x-i", sum[:4])
}

func prepareFieldC1cLauncherMounts(cfg fieldC1cHostConfig) error {
	if !gateC1bIsolatedMount(cfg.Host.ParentMount) || !gateC1bCurrentNamespace(cfg.Host.HostNamespace) {
		return errors.New("launcher fixture isolation missing")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/root", "tmpfs", 0, "mode=0700"); err != nil {
		return err
	}
	if err := os.Mkdir("/root/.winkyou-field", 0o700); err != nil {
		return err
	}
	if err := unix.Mount(cfg.LauncherRoot, "/root/.winkyou-field", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	role := "/root/.winkyou-field/c1c/endpoints/initiator"
	for _, mount := range [][2]string{
		{cfg.Host.MachineBase, role + "/var-lib"},
		{cfg.Host.HomeDirectory, role + "/home"},
		{cfg.Host.MachineBase, "/var/lib"},
		{cfg.LauncherRoot + "/registry", "/run/netns"},
	} {
		if err := unix.Mount(mount[0], mount[1], "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	// The existing TEST-NET client namespace is the anchor. The registry is
	// private to this host helper; no host registry entry is changed.
	anchor := filepath.Join("/run/netns", fieldC1cLauncherAnchor(cfg))
	f, err := os.OpenFile(anchor, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Mount("/proc/self/ns/net", anchor, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return os.Chdir("/root")
}

func fieldC1cLauncherCommand(t *testing.T, cfg fieldC1cHostConfig) *exec.Cmd {
	t.Helper()
	attempt := strings.TrimSuffix(filepath.Base(cfg.Instance), ".json")
	trace, err := os.OpenFile(cfg.Host.ResultFile+".image-trace", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("private image trace claim failed")
	}
	if err := trace.Close(); err != nil {
		t.Fatal("private image trace close failed")
	}
	// Syscall diagnostics stay in a private test file. Only fixed operation
	// classes and errno are projected into the test log, never private paths.
	return exec.Command("/usr/bin/strace", "-f", "-qq", "-e", "trace=openat,readlink,readlinkat",
		"-o", cfg.Host.ResultFile+".image-trace",
		"/bin/bash", filepath.Join(fieldC1cRepositoryRoot(t), "scripts/c1c-endpoint-launch.sh"),
		"initiator", attempt, fieldC1cLauncherAnchor(cfg))
}

func fieldC1cLauncherObservation(t *testing.T, cfg fieldC1cHostConfig, terminal fieldC1cTerminal) bool {
	t.Helper()
	output, err := os.ReadFile(cfg.Host.ResultFile)
	if err != nil {
		t.Fatal("launcher output unavailable")
	}
	trace, err := os.ReadFile(cfg.Host.ResultFile + ".image-trace")
	if err != nil {
		t.Fatal("launcher image trace unavailable")
	}
	const original = `"/root/.winkyou-field/c1c/endpoints/initiator/install/winkyou/wink"`
	var pid int
	if _, err := fmt.Sscanf(string(output), "C1C_LAUNCH role=initiator pid=%d", &pid); err != nil || pid <= 0 {
		t.Fatal("field image PID witness unavailable")
	}
	pathnameENOENT, procOpened := false, false
	for _, line := range strings.Split(string(trace), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != fmt.Sprint(pid) {
			continue
		}
		if strings.Contains(line, "openat(") && strings.Contains(line, original) && strings.Contains(line, "= -1 ENOENT") {
			pathnameENOENT = true
		}
		if strings.Contains(line, `openat(AT_FDCWD, "/proc/self/exe", O_RDONLY|O_CLOEXEC)`) && !strings.Contains(line, "= -1") {
			procOpened = true
		}
	}
	// stdout contains only the public summary and the launch/exit witnesses.
	// The endpoint terminal and strace bytes are never exported.
	t.Logf("C1C_LAUNCHER_IMAGE mode=%s terminal_present=%t pathname_reopen_ENOENT=%t proc_image_opened=%t trace_sha256=%x stdout_sha256=%x",
		cfg.LauncherMode, terminal.Class != "", pathnameENOENT, procOpened, sha256.Sum256(trace), sha256.Sum256(output))
	t.Logf("C1C_LAUNCHER_STDOUT\n%s", output)
	if cfg.LauncherMode == "old_path" || cfg.LauncherMode == "bad_hash" {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		var summary struct{ Class, Stage string }
		if len(lines) != 3 || !strings.HasPrefix(lines[0], "C1C_LAUNCH role=initiator ") ||
			json.Unmarshal([]byte(lines[1]), &summary) != nil || summary.Class != "gate_c_request_invalid" ||
			summary.Stage != "preflight" || lines[2] != "C1C_EXIT role=initiator code=1" || terminal.Class != "" {
			t.Fatal("mutation did not fail at the exact preflight boundary")
		}
		if cfg.LauncherMode == "old_path" {
			if !pathnameENOENT || procOpened {
				t.Fatal("old pathname mutation did not reproduce the original image-open failure")
			}
		} else if !procOpened || pathnameENOENT {
			t.Fatal("hash rejection did not read the running image")
		}
		return true
	}
	if terminal.Class == "" {
		t.Fatal("real field ELF failed before the private terminal; full-launcher proof is RED")
	}
	if !procOpened || pathnameENOENT {
		t.Fatal("running image was not read through the kernel image reference")
	}
	return false
}
