//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
)

// Execute is consumed only by the sealed command. A caller cannot inject a
// document, factory, clock, command, namespace name, or permission boolean.
func Execute(ctx context.Context, args []string) Summary {
	invalid := Summary{Stage: "preflight", Class: "gate_c_request_invalid"}
	if len(args) != 3 || args[1] != "--instance" || args[2] == "" {
		return invalid
	}
	switch args[0] {
	case "run":
		return runGuardian(ctx, args[2])
	case "teardown":
		return teardown(ctx, args[2])
	case "owned-worker":
		return worker(ctx, args[2])
	default:
		return invalid
	}
}

func runGuardian(ctx context.Context, path string) (summary Summary) {
	start := time.Now()
	summary = Summary{Stage: "preflight", Class: "gate_c_request_invalid"}
	a, e := fieldc1c.LoadRouter(path)
	if e != nil {
		return summary
	}
	s, e := a.Snapshot()
	if e != nil {
		return summary
	}
	summary.Profile = s.Profile
	if a.Check(time.Now()) != nil {
		return summary
	}
	if e = preflightTopology(s); e != nil {
		summary.Class = errorClass(e)
		return summary
	}
	if ctx.Err() != nil || a.Check(time.Now()) != nil {
		return summary
	}
	j, e := newJournal(s)
	if e != nil {
		summary.Class = errorClass(e)
		return summary
	}
	defer j.close()
	guard, e := acquireCeiling(s, j)
	defer func() {
		if value, err := readOwnership(s); err == nil {
			j.value = value
		}
		if err := guard.restore(); err != nil {
			summary.Class = errorClass(err)
		}
		summary.DurationNS = time.Since(start).Nanoseconds()
	}()
	if e != nil {
		summary.Class = errorClass(e)
		return summary
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		summary.Class = errorClass(errIO)
		return summary
	}
	defer reader.Close()
	defer writer.Close()
	self, e := os.Executable()
	if e != nil {
		return summary
	}
	command := exec.Command(self, "owned-worker", "--instance", path)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{reader, j.lock}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	command.WaitDelay = 100 * time.Millisecond
	// Never inherit stdout/stderr: a child panic may contain private paths.
	privateOutput := &cappedOutput{maximum: 1024 * 1024}
	command.Stdout, command.Stderr = privateOutput, privateOutput
	done, startErr := startOwnedChild(command)
	if startErr != nil {
		summary.Class = errorClass(errIO)
		return summary
	}
	_ = reader.Close()
	childStart, e := processStart(command.Process.Pid)
	if e != nil {
		_ = command.Process.Kill()
		<-done
		summary.Class = errorClass(e)
		return summary
	}
	j.value.ChildPID, j.value.ChildStart = command.Process.Pid, childStart
	if j.save() != nil {
		_ = command.Process.Kill()
		<-done
		summary.Class = errorClass(errIO)
		return summary
	}
	if _, e = io.WriteString(writer, s.Digest); e != nil {
		_ = command.Process.Kill()
	}
	_ = writer.Close()
	active, cancel := context.WithDeadline(ctx, s.Deadline)
	defer cancel()
	var childErr error
	select {
	case childErr = <-done:
	case <-active.Done():
		_ = command.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(cleanupTimeout + 2*DrainTimeout)
		select {
		case childErr = <-done:
		case <-timer.C:
			_ = command.Process.Kill()
			childErr = <-done
		}
		timer.Stop()
	}
	// A separate guardian outlives a killed worker and still owns cleanup and
	// the ceiling lock. The private journal, not the child's exit code, is authority.
	value, e := readOwnership(s)
	if e != nil {
		summary.Class = errorClass(e)
		return summary
	}
	j.value = value
	reportedResult := false
	if data, e := readPrivateJSON(s.Directory, "summary.json", 64*1024); e == nil {
		var reported Summary
		if json.Unmarshal(data, &reported) == nil {
			if _, e = reported.Encode(); e == nil {
				summary = reported
				reportedResult = true
			}
		}
		clear(data)
	}
	if !reportedResult {
		summary.Class = "c1c_router_io_failed"
	}
	if !j.value.Clean {
		t := &topology{snapshot: s, journal: j}
		if e = t.cleanup(&summary.Counts); e != nil {
			summary.Class = errorClass(e)
		} else {
			summary.Class = "c1c_router_io_failed"
		}
	}
	if childErr != nil && oneOf(summary.Class, "cancelled", "expired", "success") {
		summary.Class = "c1c_router_io_failed"
	}
	summary.Stage = "terminal"
	summary.Counts.ProcessResidue = zero() // exact child Wait completed above
	if !residueZero(summary.Counts) {
		summary.Class = "c1c_router_drain_failed"
	}
	return summary
}

func worker(ctx context.Context, path string) Summary {
	summary := Summary{Stage: "preflight", Class: "gate_c_request_invalid"}
	a, e := fieldc1c.LoadRouter(path)
	if e != nil {
		return summary
	}
	s, e := a.Snapshot()
	if e != nil {
		return summary
	}
	// The hidden entry is unusable without both inherited descriptors and
	// this exact parent/child start identity in the one-shot private journal.
	lock := os.NewFile(4, "owned-lock")
	if lock == nil {
		return summary
	}
	defer lock.Close()
	if readAdoptionToken(3, s.Digest) != nil {
		return summary
	}
	value, e := readOwnership(s)
	start, e2 := processStart(os.Getpid())
	parent, e3 := processStart(os.Getppid())
	if e != nil || e2 != nil || e3 != nil || value.PID != os.Getppid() || value.Start != parent || value.ChildPID != os.Getpid() || value.ChildStart != start || value.Clean {
		return summary
	}
	var inherited, known unix.Stat_t
	if unix.Fstat(4, &inherited) != nil || unix.Lstat(filepath.Join(s.Directory, "owner.lock"), &known) != nil || inherited.Ino != known.Ino || inherited.Dev != known.Dev || inherited.Mode&unix.S_IFMT != unix.S_IFREG {
		return summary
	}
	j := &journal{dir: s.Directory, value: value, lock: lock}
	active, cancel := context.WithDeadline(ctx, s.Deadline)
	defer cancel()
	summary = runOwned(active, a, j)
	if e = writePrivateJSON(s.Directory, "summary.json", summary); e != nil {
		summary.Class = errorClass(e)
	}
	return summary
}

func readAdoptionToken(fd int, digest string) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return ErrOwnership
	}
	// ExtraFiles crosses exec as a blocking fd. NewFile only joins the Go
	// poller for an already nonblocking inherited descriptor; otherwise its
	// deadline is unsupported and the supposedly bounded adoption cannot run.
	if unix.SetNonblock(fd, true) != nil {
		return ErrOwnership
	}
	control := os.NewFile(uintptr(fd), "owned-control")
	if control == nil {
		return ErrOwnership
	}
	defer control.Close()
	if control.SetReadDeadline(time.Now().Add(DrainTimeout)) != nil {
		return ErrOwnership
	}
	token, e := io.ReadAll(io.LimitReader(control, 65))
	defer clear(token)
	if e != nil || len(digest) != 64 || string(token) != digest {
		return ErrOwnership
	}
	return nil
}

func readPrivateJSON(dir, name string, maximum int) ([]byte, error) {
	if privateDirectory(dir) != nil {
		return nil, ErrOwnership
	}
	fd, e := unix.Open(filepath.Join(dir, name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrOwnership
	}
	f := os.NewFile(uintptr(fd), "owned-result")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Size > int64(maximum) {
		return nil, ErrOwnership
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if e != nil || len(b) > maximum {
		return nil, errIO
	}
	return b, nil
}

func teardown(ctx context.Context, path string) (summary Summary) {
	start := time.Now()
	summary = Summary{Stage: "preflight", Class: "gate_c_request_invalid"}
	defer func() { summary.DurationNS = time.Since(start).Nanoseconds() }()
	a, e := fieldc1c.LoadRouterForTeardown(path)
	if e != nil {
		return summary
	}
	s, e := a.Snapshot()
	if e != nil {
		return summary
	}
	summary.Profile = s.Profile
	value, e := readOwnership(s)
	if e != nil {
		summary.Class = errorClass(e)
		return summary
	}
	fd, e := unix.Open(filepath.Join(s.Directory, "owner.lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		summary.Class = errorClass(ErrOwnership)
		return summary
	}
	lock := os.NewFile(uintptr(fd), "owned-lock")
	defer lock.Close()
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		if current, e := processStart(value.PID); e != nil || current != value.Start {
			summary.Class = errorClass(ErrOwnership)
			return summary
		}
		if signalOwnedPID(value.PID, value.Start, unix.SIGTERM) != nil {
			summary.Class = errorClass(ErrOwnership)
			return summary
		}
		limit := time.NewTimer(cleanupTimeout + 3*DrainTimeout)
		defer limit.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
			select {
			case <-ctx.Done():
				summary.Class = "cancelled"
				return summary
			case <-limit.C:
				summary.Class = errorClass(ErrDrain)
				return summary
			case <-ticker.C:
			}
		}
	}
	value, e = readOwnership(s)
	if e != nil {
		summary.Class = errorClass(e)
		return summary
	}
	// Never kill a recycled PID. A dead guardian's owned child must also have
	// exited (PDEATHSIG); a matching survivor is not silently ignored.
	if current, e := processStart(value.ChildPID); e == nil && current == value.ChildStart {
		summary.Class = errorClass(ErrDrain)
		return summary
	}
	j := &journal{dir: s.Directory, value: value, lock: lock}
	t := &topology{snapshot: s, journal: j}
	cleanErr := t.cleanup(&summary.Counts)
	restoreErr := restoreInterruptedCeiling(s, j)
	if e = errors.Join(cleanErr, restoreErr); e != nil {
		summary.Class = errorClass(e)
	} else if residueZero(summary.Counts) {
		summary.Class = "success"
	} else {
		summary.Class = errorClass(ErrDrain)
	}
	summary.Stage = "terminal"
	checklist := struct {
		Counts   Counts `json:"counts"`
		Operator string `json:"operator_review"`
		Reviewer string `json:"second_person_review"`
	}{Counts: summary.Counts}
	// One review artifact per teardown invocation; prior evidence is immutable.
	if e = writePrivateJSON(s.Directory, "teardown-checklist.json", checklist); e != nil {
		summary.Class = errorClass(e)
	}
	return summary
}

func startOwnedChild(command *exec.Cmd) (<-chan error, error) {
	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := command.Start()
		started <- err
		if err != nil {
			done <- err
			return
		}
		done <- command.Wait()
	}()
	return done, <-started
}

func signalOwnedPID(pid int, start string, signal unix.Signal) error {
	fd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		return ErrOwnership
	}
	defer unix.Close(fd)
	if current, e := processStart(pid); e != nil || current != start {
		return ErrOwnership
	}
	if unix.PidfdSendSignal(fd, signal, nil, 0) != nil {
		return ErrOwnership
	}
	return nil
}
