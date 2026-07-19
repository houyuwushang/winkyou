//go:build windows || linux

package processidentity

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestCurrentAndInspect(t *testing.T) {
	current, err := Current()
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if current == "" {
		t.Fatal("Current() returned an empty identity")
	}
	if _, err := strconv.ParseUint(current, 10, 64); err != nil {
		t.Fatalf("Current() identity %q is not an unsigned decimal: %v", current, err)
	}

	inspected, alive, err := Inspect(os.Getpid())
	if err != nil {
		t.Fatalf("Inspect(current pid) error = %v", err)
	}
	if !alive {
		t.Fatal("Inspect(current pid) reports the current process is not alive")
	}
	if inspected != current {
		t.Fatalf("Inspect(current pid) identity = %q, want %q", inspected, current)
	}

	matched, err := Matches(os.Getpid(), current)
	if err != nil {
		t.Fatalf("Matches(current pid, current identity) error = %v", err)
	}
	if !matched {
		t.Fatal("Matches(current pid, current identity) = false, want true")
	}

	matched, err = Matches(os.Getpid(), current+"0")
	if err != nil {
		t.Fatalf("Matches(current pid, different identity) error = %v", err)
	}
	if matched {
		t.Fatal("Matches(current pid, different identity) = true, want false")
	}
}

func TestValidation(t *testing.T) {
	if _, _, err := Inspect(0); err == nil {
		t.Fatal("Inspect(0) error = nil, want invalid PID error")
	}
	if _, err := Matches(os.Getpid(), ""); err == nil {
		t.Fatal("Matches(pid, empty identity) error = nil, want error")
	}
}

func TestShortLivedProcessIdentity(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessIdentityHelper$")
	cmd.Env = append(os.Environ(), "GO_WANT_PROCESSIDENTITY_HELPER=1")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error = %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read helper readiness: %v (stderr: %s)", err, stderr.String())
	}
	if strings.TrimSpace(ready) != "ready" {
		t.Fatalf("helper readiness = %q, want %q", ready, "ready")
	}

	pid := cmd.Process.Pid
	id, alive, err := Inspect(pid)
	if err != nil {
		t.Fatalf("Inspect(helper pid) error = %v", err)
	}
	if !alive || id == "" {
		t.Fatalf("Inspect(helper pid) = (%q, %t), want non-empty identity and alive", id, alive)
	}
	matched, err := Matches(pid, id)
	if err != nil {
		t.Fatalf("Matches(live helper) error = %v", err)
	}
	if !matched {
		t.Fatal("Matches(live helper) = false, want true")
	}

	if err := stdin.Close(); err != nil {
		t.Fatalf("close helper stdin: %v", err)
	}
	waitErr := cmd.Wait()
	waited = true
	if waitErr != nil {
		t.Fatalf("wait for helper: %v (stderr: %s)", waitErr, stderr.String())
	}

	matched, err = Matches(pid, id)
	if err != nil {
		t.Fatalf("Matches(exited helper) error = %v", err)
	}
	if matched {
		t.Fatal("Matches(exited helper) = true, want false")
	}
}

func TestProcessIdentityHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PROCESSIDENTITY_HELPER") != "1" {
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatalf("write readiness: %v", err)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatalf("wait for parent: %v", err)
	}
}
