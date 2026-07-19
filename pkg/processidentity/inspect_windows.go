//go:build windows

package processidentity

import (
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/windows"
)

// Inspect returns the process creation FILETIME and whether the process is
// still alive. Keeping the process handle open makes the observation safe from
// PID reuse while the identity and liveness are read.
func Inspect(pid int) (id string, alive bool, err error) {
	if err := validatePID(pid); err != nil {
		return "", false, err
	}
	if uint64(pid) > uint64(^uint32(0)) {
		return "", false, fmt.Errorf("process identity: pid is outside the Windows PID range: %d", pid)
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("process identity: open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", false, fmt.Errorf("process identity: get creation time for pid %d: %w", pid, err)
	}
	rawCreationTime := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	id = strconv.FormatUint(rawCreationTime, 10)

	waitResult, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return "", false, fmt.Errorf("process identity: query liveness for pid %d: %w", pid, err)
	}
	switch waitResult {
	case uint32(windows.WAIT_TIMEOUT):
		return id, true, nil
	case uint32(windows.WAIT_OBJECT_0):
		return id, false, nil
	default:
		return "", false, fmt.Errorf("process identity: unexpected wait result %#x for pid %d", waitResult, pid)
	}
}
