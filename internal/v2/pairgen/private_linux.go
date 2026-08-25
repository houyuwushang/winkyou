//go:build linux

package pairgen

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func protectPrivatePath(path string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return validatePrivatePath(path, directory)
}

func validatePrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return ErrOutputUnavailable
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
		if !info.IsDir() {
			return ErrOutputUnavailable
		}
	} else if !info.Mode().IsRegular() {
		return ErrOutputUnavailable
	}
	if info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != want {
		return ErrOutputUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || (!directory && stat.Nlink != 1) {
		return ErrOutputUnavailable
	}
	_, err = unix.Getxattr(path, "system.posix_acl_access", nil)
	if err == nil {
		return ErrOutputUnavailable
	}
	if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
		return ErrOutputUnavailable
	}
	return nil
}

func syncPrivateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
