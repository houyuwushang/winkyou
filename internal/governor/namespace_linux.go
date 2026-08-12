//go:build linux

package governor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Keep the safety namespace outside /var/lib/wink and /var/lib/winkyou so
// runtime/config ownership cannot make the machine-wide authority replaceable.
const linuxMachineNamespace = "/var/lib/winkyou-safety-v2"

func platformMachineNamespacePath() (string, error) {
	return linuxMachineNamespace, nil
}

func inspectMachineNamespaceAt(path string) NamespaceStatus {
	return inspectLinuxMachineNamespaceAt(path, 0, 0)
}

func setupMachineNamespaceAt(path string) error {
	status := inspectMachineNamespaceAt(path)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: run wink setup-machine-scope as root", ErrElevationRequired)
	}
	return setupLinuxMachineNamespaceAt(path, 0, 0)
}

func inspectLinuxMachineNamespaceAt(path string, expectedUID, expectedGID int) NamespaceStatus {
	if !filepath.IsAbs(path) {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: namespace path is not absolute", ErrNamespaceUnsafe))
	}
	if err := validateLinuxNamespaceParent(filepath.Dir(path), expectedUID, expectedGID); err != nil {
		return unsafeNamespaceStatus(path, err)
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return missingNamespaceStatus(path, "machine namespace has not been installed")
	}
	if err != nil {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: inspect namespace: %v", ErrNamespaceUnsafe, err))
	}
	if err := validateLinuxPath(path, info, true, 0o755, expectedUID, expectedGID); err != nil {
		return unsafeNamespaceStatus(path, err)
	}

	for _, name := range []string{ownerLockFilename, ownerMetadataFilename} {
		filePath := filepath.Join(path, name)
		fileInfo, err := os.Lstat(filePath)
		if err != nil {
			return unsafeNamespaceStatus(path, fmt.Errorf("%w: inspect %s: %v", ErrNamespaceUnsafe, name, err))
		}
		if err := validateLinuxPath(filePath, fileInfo, false, 0o666, expectedUID, expectedGID); err != nil {
			return unsafeNamespaceStatus(path, err)
		}
	}

	return readyNamespaceStatus(path, "root-owned machine namespace and fixed owner files are ready")
}

func validateLinuxNamespaceParent(path string, expectedUID, expectedGID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect namespace parent %s: %v", ErrNamespaceUnsafe, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: namespace parent %s is not a real directory", ErrNamespaceUnsafe, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: namespace parent %s ownership is unavailable", ErrNamespaceUnsafe, path)
	}
	if int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID {
		return fmt.Errorf(
			"%w: namespace parent %s owner is %d:%d, want %d:%d",
			ErrNamespaceUnsafe,
			path,
			stat.Uid,
			stat.Gid,
			expectedUID,
			expectedGID,
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: namespace parent %s is group- or world-writable", ErrNamespaceUnsafe, path)
	}
	return rejectLinuxExtendedACL(path)
}

func setupLinuxMachineNamespaceAt(path string, expectedUID, expectedGID int) error {
	status := inspectLinuxMachineNamespaceAt(path, expectedUID, expectedGID)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}

	if err := os.Mkdir(path, 0o755); err != nil {
		return fmt.Errorf("create machine namespace: %w", err)
	}
	if err := os.Chown(path, expectedUID, expectedGID); err != nil {
		return fmt.Errorf("set machine namespace owner: %w", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("set machine namespace mode: %w", err)
	}

	for _, name := range []string{ownerLockFilename, ownerMetadataFilename} {
		filePath := filepath.Join(path, name)
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		closeErr := file.Close()
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", name, closeErr)
		}
		if err := os.Chown(filePath, expectedUID, expectedGID); err != nil {
			return fmt.Errorf("set %s owner: %w", name, err)
		}
		if err := os.Chmod(filePath, 0o666); err != nil {
			return fmt.Errorf("set %s mode: %w", name, err)
		}
	}

	status = inspectLinuxMachineNamespaceAt(path, expectedUID, expectedGID)
	if !status.Ready {
		return fmt.Errorf("%w: %s", ErrNamespaceNotReady, status.Detail)
	}
	return nil
}

func validateLinuxPath(path string, info os.FileInfo, directory bool, mode os.FileMode, expectedUID, expectedGID int) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symbolic link", ErrNamespaceUnsafe, path)
	}
	if directory {
		if !info.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrNamespaceUnsafe, path)
		}
	} else {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrNamespaceUnsafe, path)
		}
	}

	actualMode := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if actualMode != mode {
		return fmt.Errorf("%w: %s mode is %04o, want %04o", ErrNamespaceUnsafe, path, actualMode, mode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s ownership is unavailable", ErrNamespaceUnsafe, path)
	}
	if int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID {
		return fmt.Errorf(
			"%w: %s owner is %d:%d, want %d:%d",
			ErrNamespaceUnsafe,
			path,
			stat.Uid,
			stat.Gid,
			expectedUID,
			expectedGID,
		)
	}
	if !directory && stat.Nlink != 1 {
		return fmt.Errorf("%w: %s has %d hard links, want 1", ErrNamespaceUnsafe, path, stat.Nlink)
	}
	if err := rejectLinuxExtendedACL(path); err != nil {
		return err
	}
	return nil
}

func rejectLinuxExtendedACL(path string) error {
	_, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	if err == nil {
		return fmt.Errorf("%w: %s has an extended POSIX ACL", ErrNamespaceUnsafe, path)
	}
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return fmt.Errorf("%w: inspect %s POSIX ACL: %v", ErrNamespaceUnsafe, path, err)
}
