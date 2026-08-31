//go:build windows

package sshassembly

import (
	"errors"

	"golang.org/x/sys/windows"
)

func processGoneForTest(pid int) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return true
	}
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	status, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && status == windows.WAIT_OBJECT_0
}

func killProcessForTest(pid int) {
	if pid <= 0 {
		return
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
	}
	_ = windows.TerminateProcess(handle, 1)
	_, _ = windows.WaitForSingleObject(handle, 2_000)
	_ = windows.CloseHandle(handle)
}
