//go:build linux

package sshchildwrapper

import (
	"os"
	"path/filepath"
	"syscall"
)

func validateFixedInstallation() error {
	return validateInstallationAt("/", FixedWrapperPath, FixedBinaryPath, 0)
}

func validateInstallationAt(boundary, wrapper, binary string, expectedUID uint32) error {
	if !filepath.IsAbs(boundary) || !filepath.IsAbs(wrapper) || !filepath.IsAbs(binary) {
		return ErrWrapperInvalid
	}
	boundary = filepath.Clean(boundary)
	for _, path := range []string{wrapper, binary} {
		clean := filepath.Clean(path)
		relative, err := filepath.Rel(boundary, clean)
		if err != nil || relative == "." || relative == ".." || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
			return ErrWrapperInvalid
		}
		info, err := os.Lstat(clean)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o100 == 0 {
			return ErrWrapperInvalid
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != expectedUID || stat.Nlink != 1 {
			return ErrWrapperInvalid
		}
		for directory := filepath.Dir(clean); ; directory = filepath.Dir(directory) {
			directoryInfo, err := os.Lstat(directory)
			if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o022 != 0 {
				return ErrWrapperInvalid
			}
			directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
			if !ok || directoryStat.Uid != expectedUID {
				return ErrWrapperInvalid
			}
			if directory == boundary {
				break
			}
			parent := filepath.Dir(directory)
			if parent == directory {
				return ErrWrapperInvalid
			}
		}
	}
	return nil
}
