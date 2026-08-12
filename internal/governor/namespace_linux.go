//go:build linux

package governor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Keep the safety namespace outside /var/lib/wink and /var/lib/winkyou so
// runtime/config ownership cannot make the machine-wide authority replaceable.
const linuxMachineNamespace = "/var/lib/winkyou-safety-v2"

func platformMachineNamespacePath() (string, error) {
	return linuxMachineNamespace, nil
}

func platformUserAcknowledgedNamespacePath() (string, error) {
	return filepath.Join("/run/user", strconv.Itoa(os.Geteuid()), "winkyou-safety-v2"), nil
}

func inspectMachineNamespaceAt(path string) NamespaceStatus {
	return inspectLinuxMachineNamespaceAt(path, 0, 0)
}

func inspectUserAcknowledgedNamespaceAt(path string) NamespaceStatus {
	return inspectLinuxUserAcknowledgedNamespaceAt(path, os.Geteuid())
}

func setupMachineNamespaceAt(path string) error {
	status := inspectMachineNamespaceAt(path)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}
	elevated, err := machineScopeElevated()
	if err != nil {
		return fmt.Errorf("inspect process elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("%w: run wink setup-machine-scope as root", ErrElevationRequired)
	}
	return setupLinuxMachineNamespaceAt(path, 0, 0)
}

func machineScopeElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}

func inspectLinuxMachineNamespaceAt(path string, expectedUID, expectedGID int) NamespaceStatus {
	if !filepath.IsAbs(path) {
		return unsafeNamespaceStatus(ScopeMachine, path, fmt.Errorf("%w: namespace path is not absolute", ErrNamespaceUnsafe), true)
	}
	if err := validateLinuxNamespaceParent(filepath.Dir(path), expectedUID, expectedGID); err != nil {
		return unsafeNamespaceStatus(ScopeMachine, path, err, true)
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return missingNamespaceStatus(ScopeMachine, path, "machine namespace has not been installed", true)
	}
	if err != nil {
		return unsafeNamespaceStatus(ScopeMachine, path, fmt.Errorf("%w: inspect namespace: %v", ErrNamespaceUnsafe, err), true)
	}
	if err := validateLinuxPath(path, info, true, 0o755, expectedUID, expectedGID); err != nil {
		return unsafeNamespaceStatus(ScopeMachine, path, err, true)
	}

	for _, name := range namespaceFixedFilenames() {
		filePath := filepath.Join(path, name)
		fileInfo, err := os.Lstat(filePath)
		if err != nil {
			return unsafeNamespaceStatus(ScopeMachine, path, fmt.Errorf("%w: inspect %s: %v", ErrNamespaceUnsafe, name, err), true)
		}
		if err := validateLinuxPath(filePath, fileInfo, false, 0o666, expectedUID, expectedGID); err != nil {
			return unsafeNamespaceStatus(ScopeMachine, path, err, true)
		}
	}
	return readyNamespaceStatus(ScopeMachine, path, "root-owned machine namespace and fixed owner files are ready")
}

func inspectLinuxUserAcknowledgedNamespaceAt(path string, expectedUID int) NamespaceStatus {
	return inspectLinuxUserNamespaceAt(path, expectedUID)
}

func inspectLinuxUserNamespaceAt(path string, expectedUID int) NamespaceStatus {
	if !filepath.IsAbs(path) {
		return unsafeNamespaceStatus(ScopeUserAcknowledged, path, fmt.Errorf("%w: namespace path is not absolute", ErrNamespaceUnsafe), false)
	}
	if err := validateLinuxUserNamespaceParent(filepath.Dir(path), expectedUID); err != nil {
		return unsafeNamespaceStatus(ScopeUserAcknowledged, path, err, false)
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return missingNamespaceStatus(ScopeUserAcknowledged, path, "user-acknowledged namespace has not been prepared", false)
	}
	if err != nil {
		return unsafeNamespaceStatus(ScopeUserAcknowledged, path, fmt.Errorf("%w: inspect namespace: %v", ErrNamespaceUnsafe, err), false)
	}
	if err := validateLinuxPath(path, info, true, 0o700, expectedUID, -1); err != nil {
		return unsafeNamespaceStatus(ScopeUserAcknowledged, path, err, false)
	}
	for _, name := range namespaceFixedFilenames() {
		filePath := filepath.Join(path, name)
		fileInfo, err := os.Lstat(filePath)
		if err != nil {
			return unsafeNamespaceStatus(ScopeUserAcknowledged, path, fmt.Errorf("%w: inspect %s: %v", ErrNamespaceUnsafe, name, err), false)
		}
		if err := validateLinuxPath(filePath, fileInfo, false, 0o600, expectedUID, -1); err != nil {
			return unsafeNamespaceStatus(ScopeUserAcknowledged, path, err, false)
		}
	}
	return readyNamespaceStatus(ScopeUserAcknowledged, path, "private per-user namespace and fixed owner files are ready")
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

func validateLinuxUserNamespaceParent(path string, expectedUID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect user namespace parent %s: %v", ErrNamespaceUnsafe, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: user namespace parent %s is not a real directory", ErrNamespaceUnsafe, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: user namespace parent %s ownership is unavailable", ErrNamespaceUnsafe, path)
	}
	if int(stat.Uid) != expectedUID {
		return fmt.Errorf("%w: user namespace parent %s owner is %d, want uid %d", ErrNamespaceUnsafe, path, stat.Uid, expectedUID)
	}
	actualMode := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if actualMode != 0o700 {
		return fmt.Errorf("%w: user namespace parent %s mode is %04o, want 0700", ErrNamespaceUnsafe, path, actualMode)
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

	for _, name := range namespaceFixedFilenames() {
		filePath := filepath.Join(path, name)
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if name == safetyTripFilename {
			if err := initializeSafetyTripFile(file, time.Now()); err != nil {
				_ = file.Close()
				return fmt.Errorf("initialize %s: %w", name, err)
			}
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

func setupUserAcknowledgedNamespaceAt(path string) error {
	return setupLinuxUserAcknowledgedNamespaceAt(path, os.Geteuid())
}

func setupLinuxUserAcknowledgedNamespaceAt(path string, expectedUID int) error {
	status := inspectLinuxUserAcknowledgedNamespaceAt(path, expectedUID)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}

	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create user-acknowledged namespace: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("set user-acknowledged namespace mode: %w", err)
	}

	for _, name := range namespaceFixedFilenames() {
		filePath := filepath.Join(path, name)
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if name == safetyTripFilename {
			if err := initializeSafetyTripFile(file, time.Now()); err != nil {
				_ = file.Close()
				return fmt.Errorf("initialize %s: %w", name, err)
			}
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
		if err := os.Chmod(filePath, 0o600); err != nil {
			return fmt.Errorf("set %s mode: %w", name, err)
		}
	}

	status = inspectLinuxUserAcknowledgedNamespaceAt(path, expectedUID)
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
	if int(stat.Uid) != expectedUID || (expectedGID >= 0 && int(stat.Gid) != expectedGID) {
		wantOwner := fmt.Sprintf("uid %d", expectedUID)
		if expectedGID >= 0 {
			wantOwner = fmt.Sprintf("%d:%d", expectedUID, expectedGID)
		}
		return fmt.Errorf(
			"%w: %s owner is %d:%d, want %s",
			ErrNamespaceUnsafe,
			path,
			stat.Uid,
			stat.Gid,
			wantOwner,
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
