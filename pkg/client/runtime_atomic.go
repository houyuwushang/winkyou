package client

import (
	"fmt"
	"os"
	"path/filepath"
)

func atomicWriteRuntimeFile(path string, data []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create runtime state directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary runtime state: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if retErr != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary runtime state mode: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary runtime state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary runtime state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary runtime state: %w", err)
	}
	if err := replaceRuntimeStateFile(tempPath, path); err != nil {
		return fmt.Errorf("replace runtime state: %w", err)
	}
	if err := syncRuntimeStateDirectory(dir); err != nil {
		return fmt.Errorf("sync runtime state directory: %w", err)
	}
	return nil
}
