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
	"endpoint-init":   {`ROOT = "/root/.winkyou-field/c1c"`, `ROLES = ("initiator", "responder")`, `os.umask(0o077)`, `os.O_EXCL`, `already_initialized`, `install_hash_mismatch`, `root:x:19000:0:99999:7:::`, `setup-machine-scope`, `"var-lib"`, `C1C_INIT`},
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
	if name == "me-correlate" && (strings.Contains(source, "subprocess") || strings.Contains(source, "os.write(") || strings.Contains(source, "O_CREAT")) {
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
			for _, literal := range literals {
				changed := strings.Replace(source, literal, "MUTATED", 1)
				if changed == source || c1cFieldScriptValid(name, changed) {
					t.Fatal("contract mutation escaped")
				}
			}
			for _, bad := range []string{"rm -rf", "pkill", "killall", "--force", "shell=True", "os.system", "urllib", "os.environ"} {
				if c1cFieldScriptValid(name, source+"\n# "+bad) {
					t.Fatal("forbidden capability mutation escaped")
				}
			}
			t.Logf("literal_mutations=%d forbidden_mutations=8", len(literals))
		})
	}
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
			payload, _ := json.Marshal(map[string]string{"mode": name, "source": strings.ReplaceAll(string(source), "\r\n", "\n")})
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
