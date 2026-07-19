//go:build !windows

package recoverycard

import (
	"os"
)

func replaceFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func syncParentDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
