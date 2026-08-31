package sshassembly

import (
	"io"
	"os"
	"os/exec"
)

type processContainment interface {
	Kill() error
	Close() error
}

type execProcessRunner struct{}

func (execProcessRunner) Start(spec processSpec) (ownedProcess, error) {
	command := exec.Command(spec.executable, spec.arguments...)
	command.Env = append([]string(nil), spec.environment...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	containment, err := startOwnedCommand(command)
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	return &execOwnedProcess{
		command: command, stdin: stdin, stdout: stdout, stderr: stderr, containment: containment,
	}, nil
}

type execOwnedProcess struct {
	command     *exec.Cmd
	stdin       io.WriteCloser
	stdout      io.ReadCloser
	stderr      io.ReadCloser
	containment processContainment
}

func (process *execOwnedProcess) Stdin() io.WriteCloser { return process.stdin }
func (process *execOwnedProcess) Stdout() io.ReadCloser { return process.stdout }
func (process *execOwnedProcess) Stderr() io.ReadCloser { return process.stderr }
func (process *execOwnedProcess) Wait() error {
	err := process.command.Wait()
	if process.containment != nil {
		_ = process.containment.Close()
	}
	return err
}
func (process *execOwnedProcess) Kill() error {
	if process == nil || process.containment == nil {
		return ErrChildTerminated
	}
	return process.containment.Kill()
}

func validateSystemExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrProfileInvalid
	}
	return nil
}
