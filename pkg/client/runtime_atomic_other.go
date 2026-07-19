//go:build !windows

package client

import "os"

func replaceRuntimeStateFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func syncRuntimeStateDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
