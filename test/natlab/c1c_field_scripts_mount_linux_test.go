//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	c1cScriptsMountRequired = "WINKYOU_C1C_SCRIPTS_MOUNT_REQUIRED"
	c1cScriptsMountHelper   = "WINKYOU_C1C_SCRIPTS_MOUNT_HELPER"
)

type c1cRoleViewResult struct {
	InitExit       int            `json:"init_exit"`
	InitObserved   bool           `json:"init_observed"`
	LaunchExit     int            `json:"launch_exit"`
	LaunchObserved bool           `json:"launch_observed"`
	Setup          map[string]any `json:"setup,omitempty"`
	Launch         map[string]any `json:"launch,omitempty"`
}

func TestLinuxC1cFieldScriptRoleViewProof(t *testing.T) {
	if os.Getenv(c1cScriptsMountRequired) != "1" {
		t.Skip("WINKYOU_C1C_SCRIPTS_MOUNT_REQUIRED is not 1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real role-view proof requires root")
	}
	if os.Getenv(c1cScriptsMountHelper) == "1" {
		if err := c1cRunRoleViewProofHelper(); err != nil {
			t.Fatal(err)
		}
		return
	}

	root, err := os.MkdirTemp("/root", "winkyou-c1c-role-view-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	attempt := "AAAAAAAAAAAAAAAAAAAAAA"
	role := filepath.Join(root, "initiator")
	registry := filepath.Join(root, "registry")
	evidence := filepath.Join(root, "evidence", attempt, "endpoint-initiator")
	material := filepath.Join(root, "material", attempt, "initiator")
	instance := filepath.Join(root, attempt+".json")
	if err := c1cCreateRoleViewFixture(role, registry, evidence, material, instance, attempt); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestLinuxC1cFieldScriptRoleViewProof$")
	cmd.Env = append(os.Environ(),
		c1cScriptsMountRequired+"=1",
		c1cScriptsMountHelper+"=1",
		"WINKYOU_C1C_ROLE_ROOT="+role,
		"WINKYOU_C1C_REGISTRY_ROOT="+registry,
		"WINKYOU_C1C_EVIDENCE_ROOT="+evidence,
		"WINKYOU_C1C_MATERIAL_ROOT="+material,
		"WINKYOU_C1C_INSTANCE="+instance,
		"WINKYOU_C1C_ATTEMPT="+attempt,
	)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := c1cRunOuterUnshare(cmd); err != nil {
		t.Fatalf("outer isolated helper failed: %v output=%s", err, output.String())
	}
	var result c1cRoleViewResult
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result); err != nil {
		t.Fatalf("role-view result invalid: %v output=%s", err, output.String())
	}
	if result.InitExit == 0 || result.InitObserved {
		t.Fatalf("current init script unexpectedly passed RED proof: %+v", result)
	}
	if result.LaunchExit == 0 || result.LaunchObserved {
		t.Fatalf("current launch script unexpectedly passed RED proof: %+v", result)
	}
}

func c1cRunOuterUnshare(cmd *exec.Cmd) error {
	args := append([]string{"--net", "--mount", "--fork"}, cmd.Args...)
	outer := exec.Command("/usr/bin/unshare", args...)
	outer.Env, outer.Stdout, outer.Stderr = cmd.Env, cmd.Stdout, cmd.Stderr
	return outer.Run()
}

func c1cCreateRoleViewFixture(role, registry, evidence, material, instance, attempt string) error {
	for _, path := range []string{
		role + "/var-lib", role + "/home/.ssh", role + "/home/.winkyou-field/c1c/evidence",
		role + "/home/.winkyou-field/c1c/material", role + "/run/netns", role + "/install/winkyou",
		registry, filepath.Dir(evidence), evidence, filepath.Dir(material), material,
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(role+"/machine-id", []byte(strings.Repeat("7", 32)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(role+"/shadow", []byte("root:x:19000:0:99999:7:::\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(instance, []byte("{\"synthetic\":true}\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(role, "home/.winkyou-field/c1c", attempt+".json"), []byte("{\"synthetic\":true}\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(material, "probe"), []byte("probe\n"), 0o600); err != nil {
		return err
	}
	wink := filepath.Join(role, "install/winkyou/wink")
	fake := fmt.Sprintf(`#!/bin/sh
exec /usr/bin/python3 - "$@" <<'PY'
import errno, json, os, subprocess
attempt = %s
def mountpoint(path):
    return subprocess.run(["/usr/bin/mountpoint", "-q", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
def stat_pair(path):
    value = os.stat(path)
    return [value.st_dev, value.st_ino]
def write_errno(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        os.close(fd)
        return 0
    except OSError as error:
        return error.errno
result = {
    "state": "ready", "ready": True,
    "machine_id": open("/etc/machine-id", encoding="ascii").read().strip(),
    "netns": sorted(os.listdir("/run/netns")),
    "mounts": {path: mountpoint(path) for path in ["/var/lib", "/usr/libexec/winkyou/wink", "/run", "/run/netns", "/root", "/root/.winkyou-field/c1c/evidence"]},
    "stats": {path: stat_pair(path) for path in ["/var/lib", "/usr/libexec/winkyou/wink", "/run/netns", "/root/.winkyou-field/c1c/evidence"]},
    "material_write_errno": write_errno("/root/.winkyou-field/c1c/material/" + attempt + "/probe"),
    "instance_write_errno": write_errno("/root/.winkyou-field/c1c/" + attempt + ".json"),
}
print(json.dumps(result, sort_keys=True), flush=True)
PY
`, strconv.Quote(attempt))
	if err := os.WriteFile(wink, []byte(fake), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(role, "install/winkyou/gate-c-child-wrapper"), []byte("#!/bin/sh\nexit 0\n"), 0o700)
}

func c1cRunRoleViewProofHelper() error {
	if os.Geteuid() != 0 {
		return errors.New("role-view helper is not root")
	}
	var self, init unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &self); err != nil {
		return err
	}
	if err := unix.Stat("/proc/1/ns/net", &init); err != nil {
		return err
	}
	if self.Ino == init.Ino {
		return errors.New("role-view helper is still in init netns")
	}
	role := os.Getenv("WINKYOU_C1C_ROLE_ROOT")
	registry := os.Getenv("WINKYOU_C1C_REGISTRY_ROOT")
	evidence := os.Getenv("WINKYOU_C1C_EVIDENCE_ROOT")
	material := os.Getenv("WINKYOU_C1C_MATERIAL_ROOT")
	instance := os.Getenv("WINKYOU_C1C_INSTANCE")
	attempt := os.Getenv("WINKYOU_C1C_ATTEMPT")
	if role == "" || registry == "" || evidence == "" || material == "" || instance == "" || attempt == "" {
		return errors.New("role-view fixture environment missing")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mount private: %w", err)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=755"); err != nil {
		return fmt.Errorf("private run tmpfs: %w", err)
	}
	if err := os.MkdirAll("/run/netns", 0o700); err != nil {
		return err
	}
	if err := unix.Mount(registry, "/run/netns", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("registry bind: %w", err)
	}
	names := []string{"wyc1cproof-i", "wyc1cproof-t", "wyc1cproof-r"}
	for _, name := range names {
		if output, err := exec.Command("/usr/sbin/ip", "netns", "add", name).CombinedOutput(); err != nil {
			return fmt.Errorf("anchor add %s: %v %s", name, err, output)
		}
	}
	defer func() {
		for _, name := range names {
			_ = exec.Command("/usr/sbin/ip", "netns", "del", name).Run()
		}
	}()

	_, file, _, _ := runtime.Caller(0)
	repository := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	initSource, err := os.ReadFile(filepath.Join(repository, "scripts", "c1c-endpoint-init.sh"))
	if err != nil {
		return err
	}
	launchSource, err := os.ReadFile(filepath.Join(repository, "scripts", "c1c-endpoint-launch.sh"))
	if err != nil {
		return err
	}
	setup, err := c1cExtractEmbedded(string(initSource), "SETUP")
	if err != nil {
		return err
	}
	child, err := c1cExtractEmbedded(string(launchSource), "CHILD")
	if err != nil {
		return err
	}
	initOut, initErr := c1cRunSetupSnippet(setup, role)
	launchOut, launchErr := c1cRunChildSnippet(child, role, evidence, material, instance, attempt, names[0]+"-i", strings.Contains(string(launchSource), "role_path"))
	result := c1cRoleViewResult{
		InitExit: c1cExitCode(initErr), InitObserved: bytes.Contains(initOut, []byte("\"state\":\"ready\"")),
		LaunchExit: c1cExitCode(launchErr), LaunchObserved: bytes.Contains(launchOut, []byte("\"state\":\"ready\"")),
	}
	if result.InitExit == 0 && result.InitObserved {
		if err := json.Unmarshal(initOut, &result.Setup); err != nil {
			return err
		}
	}
	if result.LaunchExit == 0 && result.LaunchObserved {
		if err := json.Unmarshal(launchOut, &result.Launch); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

func c1cExtractEmbedded(source, name string) (string, error) {
	marker := name + " = r'''"
	start := strings.Index(source, marker)
	if start < 0 {
		return "", fmt.Errorf("embedded %s missing", name)
	}
	start += len(marker)
	end := strings.Index(source[start:], "'''")
	if end < 0 {
		return "", fmt.Errorf("embedded %s terminator missing", name)
	}
	return source[start : start+end], nil
}

func c1cRunSetupSnippet(snippet, role string) ([]byte, error) {
	roleFD, err := os.Open(role)
	if err != nil {
		return nil, err
	}
	defer roleFD.Close()
	registryFD, err := os.Open("/run/netns")
	if err != nil {
		return nil, err
	}
	defer registryFD.Close()
	args := []string{"3", "4"}
	files := []*os.File{roleFD, registryFD}
	if !strings.Contains(snippet, "/proc/self/fd/") {
		args = []string{"3", "4", "5", "6", "7", "8", "9", "10", role, "/run/netns"}
		files, err = c1cOpenSetupSources(role, registryFD)
		if err != nil {
			return nil, err
		}
		defer c1cCloseFiles(files)
	}
	return c1cRunPythonMountSnippet(snippet, args, files)
}

func c1cOpenSetupSources(role string, registryFD *os.File) ([]*os.File, error) {
	paths := []string{role, role + "/var-lib", role + "/install", role + "/shadow", role + "/machine-id"}
	files := make([]*os.File, 0, 8)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			c1cCloseFiles(files)
			return nil, err
		}
		files = append(files, file)
	}
	files = append(files, registryFD)
	for _, path := range []string{role + "/run", role + "/home"} {
		file, err := os.Open(path)
		if err != nil {
			c1cCloseFiles(files[:len(files)-1])
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func c1cRunChildSnippet(snippet, role, evidence, material, instance, attempt, anchor string, fixed bool) ([]byte, error) {
	var paths []string
	if fixed {
		paths = []string{role, role + "/var-lib", role + "/install", role + "/shadow", role + "/machine-id", "/run/netns", role + "/run", role + "/home", evidence, material, instance}
	} else {
		paths = []string{role, "/run/netns", evidence, material, instance}
	}
	files := make([]*os.File, 0, len(paths)+1)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			c1cCloseFiles(files)
			return nil, err
		}
		files = append(files, file)
	}
	readBarrier, writeBarrier, err := os.Pipe()
	if err != nil {
		c1cCloseFiles(files)
		return nil, err
	}
	defer readBarrier.Close()
	defer writeBarrier.Close()
	files = append(files, readBarrier)
	args := []string{"3", "4", "5", "6", "7", "8", attempt, anchor, "run"}
	if fixed {
		args = []string{"3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", attempt, anchor, "run", role, "/run/netns", evidence, material, instance}
	}
	cmd := exec.Command("/usr/bin/unshare", "-m", "--propagation", "private", "/usr/bin/python3", "-I", "-B", "-c", snippet)
	cmd.Args = append(cmd.Args, args...)
	cmd.ExtraFiles = files
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if _, err := writeBarrier.Write([]byte("1")); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	_ = writeBarrier.Close()
	err = cmd.Wait()
	return stdout.Bytes(), err
}

func c1cRunPythonMountSnippet(snippet string, args []string, files []*os.File) ([]byte, error) {
	cmd := exec.Command("/usr/bin/unshare", "-m", "--propagation", "private", "/usr/bin/python3", "-I", "-B", "-c", snippet)
	cmd.Args = append(cmd.Args, args...)
	cmd.ExtraFiles = files
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

func c1cCloseFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func c1cExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return -1
}
