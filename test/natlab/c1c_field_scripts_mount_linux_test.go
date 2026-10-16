//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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
	InitExit       int                      `json:"init_exit"`
	InitObserved   bool                     `json:"init_observed"`
	LaunchExit     int                      `json:"launch_exit"`
	LaunchObserved bool                     `json:"launch_observed"`
	Setup          map[string]any           `json:"setup,omitempty"`
	Launch         map[string]any           `json:"launch,omitempty"`
	RegistrySame   bool                     `json:"registry_same"`
	RootClear      bool                     `json:"root_clear"`
	EndToEnd       *c1cLaunchEndToEndResult `json:"launcher_end_to_end,omitempty"`
	LateNet        *c1cLaunchEndToEndResult `json:"late_net_mutation,omitempty"`
}

type c1cLaunchEndToEndResult struct {
	Exit        int            `json:"exit"`
	Stdout      string         `json:"stdout"`
	Stderr      string         `json:"stderr"`
	Payload     map[string]any `json:"payload"`
	Anchor      uint64         `json:"anchor"`
	ParentMount uint64         `json:"parent_mount"`
	ImageSHA256 string         `json:"image_sha256"`
	ImageInode  uint64         `json:"image_inode"`
	Launch      string         `json:"launch"`
	ReplayExit  int            `json:"replay_exit"`
	Replay      string         `json:"replay"`
	ObservedNet uint64         `json:"observed_net"`
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
	if err := c1cDecodeRoleViewResult(output.Bytes(), &result); err != nil {
		t.Fatalf("role-view result invalid: %v output=%s", err, output.String())
	}
	if result.InitExit != 0 || !result.InitObserved {
		t.Fatalf("init role-view proof failed: %+v", result)
	}
	if result.LaunchExit != 0 || !result.LaunchObserved {
		t.Fatalf("launch role-view proof failed: %+v", result)
	}
	if !result.RegistrySame || !result.RootClear {
		t.Fatalf("outer mount namespace changed: %+v", result)
	}
	c1cAssertRoleViewObservation(t, result.Setup, role, registry, evidence, false)
	c1cAssertRoleViewObservation(t, result.Launch, role, registry, evidence, true)
	if errno, ok := c1cNumber(result.Launch, "material_write_errno"); !ok || int(errno) != int(syscall.EROFS) {
		t.Fatalf("material bind is not read-only: %+v", result.Launch)
	}
	if errno, ok := c1cNumber(result.Launch, "instance_write_errno"); !ok || int(errno) != int(syscall.EROFS) {
		t.Fatalf("instance bind is not read-only: %+v", result.Launch)
	}
	t.Run("launcher_end_to_end", func(t *testing.T) {
		actual := result.EndToEnd
		if err := c1cCheckLaunchWitness(actual); err != nil {
			t.Fatalf("short-payload witness failed: %v result=%+v", err, actual)
		}
		if actual.Payload["ns_net"] != float64(actual.Anchor) || actual.Payload["machine_id"] != strings.Repeat("7", 32) {
			t.Fatalf("short payload did not complete in the role view: %+v", actual)
		}
		if actual.ReplayExit != 1 || actual.Replay != "C1C_LAUNCH class=evidence_already_claimed\n" {
			t.Fatalf("same attempt was not rejected: %+v", actual)
		}
		fmt.Printf("launcher_end_to_end GREEN (witness precedes short payload):\n%s", actual.Stdout)
	})
	t.Run("launcher_late_net_mutation", func(t *testing.T) {
		actual := result.LateNet
		if actual == nil || actual.ObservedNet == 0 || actual.ObservedNet == actual.Anchor || actual.Exit != 1 ||
			actual.Stdout != "C1C_EXIT role=initiator code=70\nC1C_LAUNCH class=exec_witness_unavailable\n" || actual.Launch != "" || len(actual.Payload) != 0 {
			t.Fatalf("late netns entry mutation escaped: %+v", actual)
		}
		if c1cCheckLaunchWitness(actual) == nil {
			t.Fatal("end-to-end checker accepted late netns entry")
		}
		fmt.Printf("launcher_late_net_mutation RED net_ns=%d anchor=%d; 50ms payload withheld by gate\n", actual.ObservedNet, actual.Anchor)
	})
}

func c1cCheckLaunchWitness(actual *c1cLaunchEndToEndResult) error {
	if actual == nil || actual.Exit != 0 || actual.Stderr != "" {
		return errors.New("launcher did not exit cleanly")
	}
	lines := strings.Split(strings.TrimSuffix(actual.Stdout, "\n"), "\n")
	if len(lines) != 2 || lines[1] != "C1C_EXIT role=initiator code=0" || actual.Launch != lines[0]+"\n" {
		return errors.New("persistent witness and stdout order differ")
	}
	var pid, ticks, netNS, mountNS, inode uint64
	var digest string
	n, err := fmt.Sscanf(lines[0], "C1C_LAUNCH role=initiator pid=%d starttime=%d net_ns=%d mnt_ns=%d exe_sha256=%s exe_ino=%d", &pid, &ticks, &netNS, &mountNS, &digest, &inode)
	if err != nil || n != 6 || pid < 2 || ticks == 0 || mountNS == 0 || mountNS == actual.ParentMount || digest != actual.ImageSHA256 || inode != actual.ImageInode {
		return errors.New("pinned image or process witness differs")
	}
	if netNS != actual.Anchor {
		return fmt.Errorf("net_ns=%d differs from anchor=%d", netNS, actual.Anchor)
	}
	if actual.Payload["pid"] != float64(pid) {
		return errors.New("payload pid differs from witnessed child pid")
	}
	return nil
}

func c1cDecodeRoleViewResult(output []byte, result *c1cRoleViewResult) error {
	var lastErr error
	for index, value := range output {
		if value != '{' {
			continue
		}
		var candidate c1cRoleViewResult
		// The nested test binary writes PASS after the helper's JSON witness,
		// sometimes without a line break. Decode the first complete object and
		// deliberately leave any test-runner suffix unread.
		if err := json.NewDecoder(bytes.NewReader(output[index:])).Decode(&candidate); err == nil {
			*result = candidate
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no JSON result line")
	}
	return lastErr
}

func c1cNumber(value map[string]any, key string) (float64, bool) {
	number, ok := value[key].(float64)
	return number, ok
}

func c1cAssertRoleViewObservation(t *testing.T, value map[string]any, role, registry, evidence string, launcher bool) {
	t.Helper()
	if value == nil || value["state"] != "ready" || value["ready"] != true {
		t.Fatalf("fake target did not run: %+v", value)
	}
	if value["machine_id"] != strings.Repeat("7", 32) {
		t.Fatalf("machine-id was not role-bound: %+v", value)
	}
	netns, ok := value["netns"].([]any)
	if !ok || len(netns) != 3 {
		t.Fatalf("anchor listing missing: %+v", value)
	}
	seen := make([]string, 0, len(netns))
	for _, item := range netns {
		name, ok := item.(string)
		if !ok {
			t.Fatalf("anchor listing is not textual: %+v", value)
		}
		seen = append(seen, name)
	}
	expected := []string{"wyc1cproof-i", "wyc1cproof-r", "wyc1cproof-t"}
	if strings.Join(seen, "\x00") != strings.Join(expected, "\x00") {
		t.Fatalf("anchor listing changed: %+v", value)
	}
	anchorMounts, ok := value["anchor_mounts"].(map[string]any)
	if !ok {
		t.Fatalf("anchor mount observations missing: %+v", value)
	}
	for _, name := range expected {
		if anchorMounts[name] != true {
			t.Fatalf("anchor %s is not a mountpoint: %+v", name, anchorMounts)
		}
	}
	mounts, ok := value["mounts"].(map[string]any)
	if !ok {
		t.Fatalf("mountpoint observations missing: %+v", value)
	}
	for _, path := range []string{"/var/lib", "/usr/libexec", "/run", "/run/netns", "/root"} {
		if mounts[path] != true {
			t.Fatalf("%s is not a mountpoint: %+v", path, mounts)
		}
	}
	if launcher && mounts["/root/.winkyou-field/c1c/evidence"] != true {
		t.Fatalf("launcher evidence is not a mountpoint: %+v", mounts)
	}
	stats, ok := value["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stat observations missing: %+v", value)
	}
	if !c1cSameStat(stats["/var/lib"], role+"/var-lib") ||
		!c1cSameStat(stats["/usr/libexec/winkyou/wink"], role+"/install/winkyou/wink") ||
		!c1cSameStat(stats["/run/netns"], registry) {
		t.Fatalf("role view identity mismatch: %+v", stats)
	}
	if launcher && !c1cSameStat(stats["/root/.winkyou-field/c1c/evidence"], evidence) {
		t.Fatalf("evidence identity mismatch: %+v", stats)
	}
	if !launcher && !c1cSameStat(stats["/root/.winkyou-field/c1c/evidence"], filepath.Join(role, "home/.winkyou-field/c1c/evidence")) {
		t.Fatalf("home evidence identity mismatch: %+v", stats)
	}
}

func c1cSameStat(value any, source string) bool {
	actual, ok := value.([]any)
	if !ok || len(actual) != 2 {
		return false
	}
	info, err := os.Stat(source)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return actual[0] == float64(stat.Dev) && actual[1] == float64(stat.Ino)
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
		role + "/home/.winkyou-field/c1c/material", role + "/home/.winkyou-field/c1c/material/" + attempt,
		role + "/run/netns", role + "/install/winkyou",
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
anchors = ["wyc1cproof-i", "wyc1cproof-t", "wyc1cproof-r"]
result = {
    "state": "ready", "ready": True,
    "machine_id": open("/etc/machine-id", encoding="ascii").read().strip(),
    "netns": sorted(os.listdir("/run/netns")),
    "anchor_mounts": {name: mountpoint("/run/netns/" + name) for name in anchors},
    "mounts": {path: mountpoint(path) for path in ["/var/lib", "/usr/libexec", "/run", "/run/netns", "/root", "/root/.winkyou-field/c1c/evidence"]},
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
	registryBefore, err := c1cDirectoryEntries("/run/netns")
	if err != nil {
		return err
	}

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
	launchOut, launchErr := c1cRunChildSnippet(child, role, evidence, material, instance, attempt, names[0], strings.Contains(string(launchSource), "role_path"))
	registryAfter, err := c1cDirectoryEntries("/run/netns")
	if err != nil {
		return err
	}
	result := c1cRoleViewResult{
		InitExit: c1cExitCode(initErr), InitObserved: bytes.Contains(initOut, []byte("\"state\": \"ready\"")),
		LaunchExit: c1cExitCode(launchErr), LaunchObserved: bytes.Contains(launchOut, []byte("\"state\": \"ready\"")),
		RegistrySame: strings.Join(registryBefore, "\x00") == strings.Join(registryAfter, "\x00"),
		RootClear:    exec.Command("/usr/bin/mountpoint", "-q", "/root").Run() != nil,
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
	result.EndToEnd, err = c1cRunLauncherEndToEnd(repository, attempt, false)
	if err != nil {
		return err
	}
	result.LateNet, err = c1cRunLauncherEndToEnd(repository, attempt, true)
	if err != nil {
		return err
	}
	registryAfter, err = c1cDirectoryEntries("/run/netns")
	if err != nil {
		return err
	}
	result.RegistrySame = strings.Join(registryBefore, "\x00") == strings.Join(registryAfter, "\x00")
	result.RootClear = exec.Command("/usr/bin/mountpoint", "-q", "/root").Run() != nil
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

// Run the unchanged, complete launcher below the same outer net/mount fixture.
// The extra mount view supplies its fixed root without touching a host role tree.
func c1cRunLauncherEndToEnd(repository, attempt string, lateNet bool) (*c1cLaunchEndToEndResult, error) {
	root, err := os.MkdirTemp("/tmp", "winkyou-c1c-full-launch-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	role := filepath.Join(root, "c1c/endpoints/initiator")
	evidence := filepath.Join(root, "c1c/evidence", attempt, "endpoint-initiator")
	for _, path := range []string{
		role + "/var-lib", role + "/install/winkyou", role + "/run/netns",
		role + "/home/.winkyou-field/c1c/evidence", evidence,
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(role+"/machine-id", []byte(strings.Repeat("7", 32)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(role+"/shadow", []byte("root:x:19000:0:99999:7:::\n"), 0o600); err != nil {
		return nil, err
	}
	// A native ELF avoids observing an interpreter in place of the pinned image.
	// Padding matches the measured field image; it changes neither instructions
	// nor payload lifetime, but retains the original observer's full-hash cost.
	image := role + "/install/winkyou/wink"
	program := fmt.Sprintf(`#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    struct timespec a, b;
    struct stat ns;
    char machine[34] = {0}, payload[256];
    if (argc != 2 || strcmp(argv[1], "version")) return 70;
    if (clock_gettime(CLOCK_MONOTONIC, &a) || stat("/proc/self/ns/net", &ns)) return 71;
    int in = open("/etc/machine-id", O_RDONLY);
    if (in < 0 || read(in, machine, 33) != 33 || close(in)) return 72;
    machine[32] = 0;
    const char *base = "/root/.winkyou-field/c1c/evidence/";
    char directory[256], file[256];
    snprintf(directory, sizeof directory, "%%s%s", base);
    if (mkdir(directory, 0700)) return 73;
    snprintf(directory, sizeof directory, "%%s%s/endpoint-initiator", base);
    if (mkdir(directory, 0700)) return 73;
    snprintf(file, sizeof file, "%%s/payload.json", directory);
    int out = open(file, O_WRONLY|O_CREAT|O_EXCL, 0600);
    int size = snprintf(payload, sizeof payload, "{\"pid\":%%ld,\"ns_net\":%%llu,\"machine_id\":\"%%s\"}\n", (long)getpid(), (unsigned long long)ns.st_ino, machine);
    if (out < 0 || write(out, payload, size) != size || close(out)) return 74;
    if (clock_gettime(CLOCK_MONOTONIC, &b)) return 75;
    int64_t elapsed = (b.tv_sec-a.tv_sec)*1000000000LL+b.tv_nsec-a.tv_nsec;
    return elapsed <= 5000000 ? 0 : 76;
}
`, attempt, attempt)
	if lateNet {
		program = strings.Replace(program, "    int in = open", "    struct timespec pause = {0, 50000000};\n    if (nanosleep(&pause, 0)) return 77;\n    int in = open", 1)
		program = strings.Replace(program, "elapsed <= 5000000", "elapsed <= 100000000", 1)
	}
	compiler := exec.Command("gcc", "-x", "c", "-O2", "-o", image, "-")
	compiler.Stdin = strings.NewReader(program)
	if output, err := compiler.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("short ELF build: %w %s", err, output)
	}
	if err := os.Chmod(image, 0o700); err != nil {
		return nil, err
	}
	if err := os.Truncate(image, 31403149); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(image)
	if err != nil {
		return nil, err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if err := os.WriteFile(role+"/install/winkyou/gate-c-child-wrapper", data, 0o700); err != nil {
		return nil, err
	}
	marker, _ := json.Marshal(map[string]string{"schema": "winkyou-c1c-role-init/1", "role": "initiator", "image_sha256": digest})
	if err := os.WriteFile(role+"/initialized.json", marker, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte("winkyou-c1c-anchor/1\n" + attempt))
	anchor := fmt.Sprintf("wyc1c%x-i", sum[:4])
	if output, err := exec.Command("/usr/sbin/ip", "netns", "add", anchor).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("full launcher anchor: %w %s", err, output)
	}
	defer exec.Command("/usr/sbin/ip", "netns", "del", anchor).Run()
	script := filepath.Join(repository, "scripts/c1c-endpoint-launch.sh")
	observation := filepath.Join(root, "observed-net.json")
	if lateNet {
		original, err := os.ReadFile(script)
		if err != nil {
			return nil, err
		}
		mutant := string(original)
		changes := [][2]string{
			{`argv = ["/usr/sbin/ip", "netns", "exec", anchor, "/usr/bin/unshare"`, `argv = ["/usr/bin/unshare"`},
			{`os.execve(wink_fd, args, ENV)`, `os.execve("/usr/sbin/ip", ["/usr/sbin/ip", "netns", "exec", anchor, "/proc/self/fd/" + str(wink_fd)] + args[1:], ENV)`},
			{`    return {"pid": pid, "starttime": ticks, "net_ns": net, "mnt_ns": mount}`, "    with open(" + strconv.Quote(observation) + ", \"w\") as observed:\n        json.dump(net, observed)\n" + `    return {"pid": pid, "starttime": ticks, "net_ns": net, "mnt_ns": mount}`},
		}
		for _, change := range changes {
			if strings.Count(mutant, change[0]) != 1 {
				return nil, errors.New("late-net mutation target is not unique")
			}
			mutant = strings.Replace(mutant, change[0], change[1], 1)
		}
		script = filepath.Join(root, "late-net-launch.sh")
		if err := os.WriteFile(script, []byte(mutant), 0o700); err != nil {
			return nil, err
		}
	}
	const driver = `import json, os, subprocess, sys
root, source, attempt, anchor, digest, observation = sys.argv[1:]
subprocess.run(["/usr/bin/mount","--make-rprivate","/"],check=True)
subprocess.run(["/usr/bin/mount","-t","tmpfs","-o","mode=700","tmpfs","/root"],check=True)
os.mkdir("/root/.winkyou-field",0o700)
subprocess.run(["/usr/bin/mount","--bind",root,"/root/.winkyou-field"],check=True)
base="/root/.winkyou-field/c1c"
role=base+"/endpoints/initiator"
evidence=base+"/evidence/"+attempt+"/endpoint-initiator"
result=subprocess.run(["bash",source,"initiator",attempt,anchor,"--payload","version"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
payload_path=evidence+"/"+attempt+"/endpoint-initiator/payload.json"
payload=json.load(open(payload_path)) if os.path.exists(payload_path) else {}
observed=json.load(open(observation)) if os.path.exists(observation) else 0
replay=subprocess.run(["bash",source,"initiator",attempt,anchor,"--payload","version"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
print(json.dumps({"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr,"payload":payload,"anchor":os.stat("/run/netns/"+anchor).st_ino,"parent_mount":os.stat("/proc/self/ns/mnt").st_ino,"image_sha256":digest,"image_inode":os.stat(role+"/install/winkyou/wink").st_ino,"launch":open(evidence+"/launch.json").read(),"replay_exit":replay.returncode,"replay":replay.stdout,"observed_net":observed}))
`
	command := exec.Command("/usr/bin/unshare", "-m", "--propagation", "private", "/usr/bin/python3", "-I", "-B", "-c", driver, root, script, attempt, anchor, digest, observation)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("full launcher driver: %w %s", err, output)
	}
	var result c1cLaunchEndToEndResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("full launcher result: %w %s", err, output)
	}
	return &result, nil
}

func c1cDirectoryEntries(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
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
	deterministic := strings.Contains(snippet, "ready_write")
	var readyRead, readyWrite *os.File
	var imageInfo *syscall.Stat_t
	if deterministic {
		image, err := os.Open(role + "/install/winkyou/wink")
		if err != nil {
			c1cCloseFiles(files)
			return nil, err
		}
		files = append(files, image)
		info, err := image.Stat()
		if err != nil {
			c1cCloseFiles(files)
			return nil, err
		}
		imageInfo = info.Sys().(*syscall.Stat_t)
		readyRead, readyWrite, err = os.Pipe()
		if err != nil {
			c1cCloseFiles(files)
			return nil, err
		}
		defer readyRead.Close()
		files = append(files, readyWrite)
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
	if deterministic {
		args = []string{"3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", strconv.FormatUint(uint64(imageInfo.Dev), 10), strconv.FormatUint(imageInfo.Ino, 10), attempt, anchor, "run", role, "/run/netns", evidence, material, instance}
	}
	cmd := exec.Command("/usr/bin/unshare", "-m", "--propagation", "private", "/usr/bin/python3", "-I", "-B", "-c", snippet)
	if deterministic {
		cmd = exec.Command("/usr/sbin/ip", append([]string{"netns", "exec", anchor}, cmd.Args...)...)
	}
	cmd.Args = append(cmd.Args, args...)
	cmd.ExtraFiles = files
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// ExtraFiles are duplicated by Start; release the parent pins while the
	// child still owns its copies and keep only the barrier writer below.
	c1cCloseFiles(files[:len(files)-1])
	if deterministic {
		var ready [1]byte
		if n, err := readyRead.Read(ready[:]); err != nil || n != 1 || ready[0] != 'R' {
			_ = writeBarrier.Close()
			_ = cmd.Wait()
			return nil, fmt.Errorf("child readiness missing: n=%d err=%v", n, err)
		}
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
