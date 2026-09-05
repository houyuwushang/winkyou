//go:build windows

package sshassembly

import (
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessContainment struct {
	mu  sync.Mutex
	job windows.Handle
}

// startOwnedCommand starts the child suspended, assigns it to a one-process
// kill-on-close Job Object, and only then resumes its sole primary thread.
// Therefore there is no executable interval in which a child can escape the
// parent-death containment boundary.
func startOwnedCommand(command *exec.Cmd) (processContainment, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	closeJob := true
	defer func() {
		if closeJob {
			_ = windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	limits.BasicLimitInformation.ActiveProcessLimit = 1
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, err
	}
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	if err := command.Start(); err != nil {
		return nil, err
	}
	failStarted := func(cause error) (processContainment, error) {
		if command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		return nil, cause
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(command.Process.Pid))
	if err != nil {
		return failStarted(err)
	}
	assignErr := windows.AssignProcessToJobObject(job, processHandle)
	_ = windows.CloseHandle(processHandle)
	if assignErr != nil {
		return failStarted(assignErr)
	}
	if err := resumeOnlyThread(uint32(command.Process.Pid)); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = command.Wait()
		return nil, err
	}
	closeJob = false
	return &windowsProcessContainment{job: job}, nil
}

func resumeOnlyThread(processID uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	var threads []uint32
	err = windows.Thread32First(snapshot, &entry)
	for err == nil {
		if entry.OwnerProcessID == processID {
			threads = append(threads, entry.ThreadID)
		}
		err = windows.Thread32Next(snapshot, &entry)
	}
	if !errors.Is(err, syscall.ERROR_NO_MORE_FILES) || len(threads) != 1 {
		return ErrTransport
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threads[0])
	if err != nil {
		return err
	}
	defer windows.CloseHandle(thread)
	previous, err := windows.ResumeThread(thread)
	if err != nil || previous != 1 {
		return ErrTransport
	}
	return nil
}

func (containment *windowsProcessContainment) Kill() error {
	if containment == nil {
		return ErrChildTerminated
	}
	containment.mu.Lock()
	defer containment.mu.Unlock()
	if containment.job == 0 {
		return ErrChildTerminated
	}
	return windows.TerminateJobObject(containment.job, 1)
}

// This no-console profile has no safe per-process graceful console signal.
// Pipe closure remains its cooperative request; the existing two-second
// owned Job Object kill bound is unchanged. No console/group signal is sent.
func (containment *windowsProcessContainment) RequestExit() error { return nil }

func (containment *windowsProcessContainment) Close() error {
	if containment == nil {
		return nil
	}
	containment.mu.Lock()
	defer containment.mu.Unlock()
	if containment.job == 0 {
		return nil
	}
	err := windows.CloseHandle(containment.job)
	containment.job = 0
	return err
}
