package architecture

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var c1cFieldScriptContracts = map[string][]string{
	"endpoint-init":   {`ROOT = "/root/.winkyou-field/c1c"`, `ROLES = ("initiator", "responder")`, `os.umask(0o077)`, `os.O_EXCL`, `os.O_RDWR`, `already_initialized`, `image_changed`, `identity_unsafe`, `install_hash_mismatch`, `root:x:19000:0:99999:7:::`, `setup-machine-scope`, `stderr=subprocess.STDOUT`, `setup-`, `"initialized.json"`, `resumed=`, `"var-lib"`, `C1C_INIT`},
	"endpoint-launch": {`ROOT = "/root/.winkyou-field/c1c"`, `ROLES = ("initiator", "responder")`, `os.umask(0o077)`, `os.O_EXCL`, `"/proc/self/ns/net"`, `"/proc/1/ns/net"`, `"/run/netns"`, `"--propagation", "private"`, `"/var/lib"`, `"/usr/libexec"`, `"/etc/shadow"`, `"/etc/machine-id"`, `"wyc1c"`, `C1C_LAUNCH`, `C1C_EXIT`, `exec_witness`, `evidence_parent`, `"/usr/libexec/winkyou/wink"`},
	"owned-stop":      {`ROLES`, `os.umask(0o077)`, `identity_mismatch`, `signal.SIGTERM`, `DRAIN_SECONDS = 2.0`, `POLL_SECONDS = 0.1`, `os.pidfd_open`, `signal.pidfd_send_signal`, `rfind(")")`, `C1C_STOP`},
	"me-correlate":    {`ROOT = "/root/.winkyou-field/c1c/evidence"`, `ROLES = ("initiator", "responder")`, `os.umask(0o077)`, `os.O_NOFOLLOW`, `MAX_BYTES = 4 * 1024 * 1024`, `endpoint_tuple_not_recorded`, `clock_not_comparable`, `C1C_ME`, `mapping_age_at_hit_ns`, `stop_to_verify_ns`},
}

func c1cFieldScriptValid(name, source string) bool {
	if !strings.HasPrefix(source, "#!/bin/sh\n") || !strings.Contains(source, `exec /usr/bin/python3 -I -B - "$@" <<'PY'`) {
		return false
	}
	for _, literal := range c1cFieldScriptContracts[name] {
		if !strings.Contains(source, literal) {
			return false
		}
	}
	for _, bad := range []string{"rm -rf", "flush", "pkill", "killall", "--force", "shell=True", "os.system", "os.environ", "USERPROFILE", "socket.", "urllib", "requests.", "ip netns del"} {
		if strings.Contains(source, bad) {
			return false
		}
	}
	if name == "endpoint-launch" && (strings.Contains(source, "os.kill(") || strings.Contains(source, "os.unlink(") || strings.Contains(source, "os.rmdir(")) {
		return false
	}
	if name == "endpoint-init" && (strings.Contains(source, "remove_failed_copies") || strings.Contains(source, "os.unlink(") || strings.Contains(source, "os.rmdir(") || strings.Contains(source, "os.remove(") || strings.Contains(source, "shutil")) {
		return false
	}
	if name == "me-correlate" && (strings.Contains(source, "subprocess") || strings.Contains(source, "os.write(") || strings.Contains(source, "O_CREAT")) {
		return false
	}
	return true
}

func c1cEmbeddedScript(source, name string) (string, bool) {
	marker := name + " = r'''"
	start := strings.Index(source, marker)
	if start < 0 {
		return "", false
	}
	start += len(marker)
	end := strings.Index(source[start:], "'''")
	if end < 0 {
		return "", false
	}
	return source[start : start+end], true
}

func c1cRoleViewLineHas(source, fragment, required string) bool {
	start := strings.Index(source, fragment)
	if start < 0 {
		return false
	}
	end := strings.IndexByte(source[start:], '\n')
	if end < 0 {
		end = len(source) - start
	}
	return strings.Contains(source[start:start+end], required)
}

func c1cRoleViewScriptValid(name, source string) bool {
	snippetName := map[string]string{"endpoint-init": "SETUP", "endpoint-launch": "CHILD"}[name]
	if snippetName == "" {
		return true
	}
	snippet, ok := c1cEmbeddedScript(source, snippetName)
	if !ok || strings.Contains(snippet, "/proc/self/fd/") ||
		!strings.Contains(snippet, "def identity(pin, target):") ||
		!strings.Contains(snippet, "os.fstat(pin)") ||
		!strings.Contains(snippet, "os.stat(target)") ||
		!strings.Contains(snippet, `raise RuntimeError("mount_identity_mismatch")`) {
		return false
	}
	fragments := []string{
		`bind(role_path + "/var-lib"`, `bind(role_path + "/install"`,
		`bind(role_path + "/shadow"`, `bind(role_path + "/machine-id"`,
		`bind(registry_path, role_path + "/run/netns"`, `bind(role_path + "/run", "/run"`,
	}
	if name == "endpoint-init" {
		fragments = append(fragments, `bind(role_path + "/home", "/root"`)
	} else {
		fragments = append(fragments,
			`bind(evidence_path, evidence_parent`,
			`bind(material_path, role_state + "/material/" + attempt`,
			`bind(instance_path, role_state + "/" + attempt`,
			`bind(role_home, "/root"`)
	}
	last := -1
	for _, fragment := range fragments {
		position := strings.Index(snippet, fragment)
		if position < 0 || position < last {
			return false
		}
		last = position
	}
	for _, fragment := range []string{
		fragments[4], fragments[5], fragments[len(fragments)-1],
	} {
		if !c1cRoleViewLineHas(snippet, fragment, "recursive=True") {
			return false
		}
	}
	if name == "endpoint-launch" {
		if !c1cRoleViewLineHas(snippet, fragments[7], "readonly=True") ||
			!c1cRoleViewLineHas(snippet, fragments[8], "readonly=True") {
			return false
		}
		if strings.Count(snippet, "identity(pin, target)") < 3 {
			return false
		}
	} else if strings.Count(snippet, "identity(pin, target)") < 2 {
		return false
	}
	return true
}

func TestC1cFieldScriptContractsAndMutations(t *testing.T) {
	for name, literals := range c1cFieldScriptContracts {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "c1c-"+name+".sh"))
			if err != nil {
				t.Fatal("field script unavailable")
			}
			source := strings.ReplaceAll(string(data), "\r\n", "\n")
			if !c1cFieldScriptValid(name, source) {
				t.Fatal("field script contract rejected")
			}
			if !c1cRoleViewScriptValid(name, source) {
				t.Fatal("role-view bind contract rejected")
			}
			for _, literal := range literals {
				changed := strings.ReplaceAll(source, literal, "MUTATED")
				if changed == source || c1cFieldScriptValid(name, changed) {
					t.Fatal("contract mutation escaped")
				}
			}
			for _, bad := range []string{"rm -rf", "pkill", "killall", "--force", "shell=True", "os.system", "urllib", "os.environ"} {
				if c1cFieldScriptValid(name, source+"\n# "+bad) {
					t.Fatal("forbidden capability mutation escaped")
				}
			}
			if name == "endpoint-init" {
				for _, bad := range []string{"remove_failed_copies", "os.unlink(", "os.rmdir(", "os.remove(", "shutil"} {
					if c1cFieldScriptValid(name, source+"\n# "+bad) {
						t.Fatalf("init deletion mutation escaped: %s", bad)
					}
				}
			}
			t.Logf("literal_mutations=%d forbidden_mutations=8", len(literals))
		})
	}
}

func TestC1cFieldScriptRoleViewMutations(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "c1c-endpoint-launch.sh"))
	if err != nil {
		t.Fatal("field launch script unavailable")
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	mutations := []struct {
		name   string
		mutate func(string) string
	}{
		{"old_home_order", func(value string) string {
			return c1cSwapScriptLines(value, `bind(role_path + "/run", "/run"`, `bind(role_home, "/root"`)
		}},
		{"run_bind_instead_of_rbind", func(value string) string {
			return strings.Replace(value, `bind(role_path + "/run", "/run", run, recursive=True)`, `bind(role_path + "/run", "/run", run, recursive=False)`, 1)
		}},
		{"registry_after_run", func(value string) string {
			return c1cSwapScriptLines(value, `bind(registry_path, role_path + "/run/netns"`, `bind(role_path + "/run", "/run"`)
		}},
		{"identity_check_removed", func(value string) string {
			return strings.Replace(value, "        identity(pin, target)\n", "", 1)
		}},
		{"material_not_readonly", func(value string) string {
			return strings.Replace(value, `bind(material_path, role_state + "/material/" + attempt, material_fd, readonly=True)`, `bind(material_path, role_state + "/material/" + attempt, material_fd)`, 1)
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := mutation.mutate(source)
			if changed == source || c1cRoleViewScriptValid("endpoint-launch", changed) {
				t.Fatal("role-view mutation escaped")
			}
			t.Log("RED mutation rejected and source restored")
		})
	}
	t.Logf("role_view_mutations=%d", len(mutations))
}

func c1cSwapScriptLines(source, left, right string) string {
	lines := strings.Split(source, "\n")
	leftIndex, rightIndex := -1, -1
	for index, line := range lines {
		if leftIndex < 0 && strings.Contains(line, left) {
			leftIndex = index
		}
		if rightIndex < 0 && strings.Contains(line, right) {
			rightIndex = index
		}
	}
	if leftIndex < 0 || rightIndex < 0 {
		return source
	}
	lines[leftIndex], lines[rightIndex] = lines[rightIndex], lines[leftIndex]
	return strings.Join(lines, "\n")
}

func TestC1cFieldScriptsPureSemantics(t *testing.T) {
	pythonName := "python3"
	if runtime.GOOS == "windows" {
		pythonName = "python"
	}
	python, err := exec.LookPath(pythonName)
	if err != nil {
		t.Fatal("Python 3 required for pure script contracts")
	}
	for name := range c1cFieldScriptContracts {
		t.Run(name, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "c1c-"+name+".sh"))
			if err != nil {
				t.Fatal("field script unavailable")
			}
			request := map[string]string{"mode": name, "source": strings.ReplaceAll(string(source), "\r\n", "\n")}
			if name == "me-correlate" {
				golden, err := os.ReadFile(filepath.Join(repositoryRoot(t), "internal/architecture/testdata/c1c-me-correlate.golden.json"))
				if err != nil {
					t.Fatal("correlation golden unavailable")
				}
				request["golden"] = strings.ReplaceAll(string(golden), "\r\n", "\n")
			}
			payload, _ := json.Marshal(request)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join(repositoryRoot(t), "internal/architecture/testdata/c1c_field_scripts_test.py"))
			cmd.Stdin = strings.NewReader(string(payload))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("pure contract failed: %s", out)
			}
			t.Logf("%s", out)
		})
	}
}
