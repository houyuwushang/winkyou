//go:build windows

package recoverycard

import (
	"golang.org/x/sys/windows"
)

func replaceFile(oldPath, newPath string) error {
	oldPtr, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		oldPtr,
		newPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

// MoveFileEx with MOVEFILE_WRITE_THROUGH flushes the copy/delete operation.
// Windows does not expose a portable directory fsync through os.File.
func syncParentDirectory(string) error { return nil }
