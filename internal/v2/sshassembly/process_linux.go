//go:build linux

package sshassembly

import (
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
)

type linuxProcessContainment struct {
	process *os.Process
	release chan struct{}
	once    sync.Once
}

// startOwnedCommand keeps the exact OS thread that created the child alive
// until Wait completes. Linux Pdeathsig is tied to that thread, not merely to
// the process, so unlocking it earlier could terminate a healthy child when
// the Go runtime retires the thread.
func startOwnedCommand(command *exec.Cmd) (processContainment, error) {
	type result struct {
		process *os.Process
		err     error
	}
	release := make(chan struct{})
	started := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		err := command.Start()
		started <- result{process: command.Process, err: err}
		if err == nil {
			<-release
		}
	}()
	value := <-started
	if value.err != nil || value.process == nil {
		return nil, value.err
	}
	return &linuxProcessContainment{process: value.process, release: release}, nil
}

func (containment *linuxProcessContainment) Kill() error {
	if containment == nil || containment.process == nil {
		return ErrChildTerminated
	}
	return containment.process.Kill()
}

func (containment *linuxProcessContainment) Close() error {
	if containment != nil {
		containment.once.Do(func() { close(containment.release) })
	}
	return nil
}
