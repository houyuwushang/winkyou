//go:build linux

package sshassembly

import (
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func processGoneForTest(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func TestOwnedProcessRunnerRequestExitLeavesNoProcess(t *testing.T) {
	environment, err := fixedEnvironment(PlatformLinux)
	if err != nil {
		t.Fatal("fixed helper environment unavailable")
	}
	environment = append(environment, processHelperRoleKey+"=child")
	process, err := (execProcessRunner{}).Start(processSpec{executable: os.Args[0],
		arguments: []string{"-test.run=^TestOwnedChildDiesWithParent$"}, environment: environment})
	if err != nil {
		t.Fatal("owned exit-request helper could not start")
	}
	owned := process.(*execOwnedProcess)
	defer killProcessForTest(owned.command.Process.Pid)
	defer process.Stdin().Close()
	defer process.Stdout().Close()
	defer process.Stderr().Close()
	if err := process.RequestExit(); err != nil {
		t.Fatal("owned exit request failed")
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case <-done:
	case <-time.After(DrainTimeout):
		_ = process.Kill()
		<-done
		t.Fatal("graceful request left an owned helper alive")
	}
	if !processGoneForTest(owned.command.Process.Pid) {
		t.Fatal("exit-request helper left process residue")
	}
	_, _ = io.Copy(io.Discard, process.Stderr())
}

func killProcessForTest(pid int) {
	if pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
