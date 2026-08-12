//go:build windows

package governor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsMachineNamespaceDirectory = "WinkYou-SafetyV2"

// FILE_ALL_ACCESS from the Windows SDK. x/sys intentionally exposes the
// component rights but not this aggregate.
const windowsFullControlMask windows.ACCESS_MASK = 0x001f01ff

func platformMachineNamespacePath() (string, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("resolve Windows ProgramData known folder: %w", err)
	}
	return filepath.Join(programData, windowsMachineNamespaceDirectory), nil
}

func inspectMachineNamespaceAt(path string) NamespaceStatus {
	if !filepath.IsAbs(path) {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: namespace path is not absolute", ErrNamespaceUnsafe))
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: inspect namespace parent %s: %v", ErrNamespaceUnsafe, parent, err))
	}
	if !parentInfo.IsDir() {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: namespace parent %s is not a directory", ErrNamespaceUnsafe, parent))
	}
	if err := rejectWindowsReparsePoint(parent); err != nil {
		return unsafeNamespaceStatus(path, err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return missingNamespaceStatus(path, "machine namespace has not been installed")
	}
	if err != nil {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: inspect namespace: %v", ErrNamespaceUnsafe, err))
	}
	if !info.IsDir() {
		return unsafeNamespaceStatus(path, fmt.Errorf("%w: namespace is not a directory", ErrNamespaceUnsafe))
	}
	if err := rejectWindowsReparsePoint(path); err != nil {
		return unsafeNamespaceStatus(path, err)
	}
	if err := validateWindowsDACL(path, windowsDirectoryAccessMask()); err != nil {
		return unsafeNamespaceStatus(path, err)
	}

	for _, name := range []string{ownerLockFilename, ownerMetadataFilename} {
		filePath := filepath.Join(path, name)
		fileInfo, err := os.Lstat(filePath)
		if err != nil {
			return unsafeNamespaceStatus(path, fmt.Errorf("%w: inspect %s: %v", ErrNamespaceUnsafe, name, err))
		}
		if !fileInfo.Mode().IsRegular() {
			return unsafeNamespaceStatus(path, fmt.Errorf("%w: %s is not a regular file", ErrNamespaceUnsafe, name))
		}
		if err := rejectWindowsReparsePoint(filePath); err != nil {
			return unsafeNamespaceStatus(path, err)
		}
		if err := validateWindowsSingleLink(filePath); err != nil {
			return unsafeNamespaceStatus(path, err)
		}
		if err := validateWindowsDACL(filePath, windowsFileAccessMask()); err != nil {
			return unsafeNamespaceStatus(path, err)
		}
	}

	return readyNamespaceStatus(path, "protected machine namespace and fixed owner files are ready")
}

func setupMachineNamespaceAt(path string) error {
	status := inspectMachineNamespaceAt(path)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}
	elevated, err := windowsProcessElevated()
	if err != nil {
		return fmt.Errorf("inspect process elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("%w: run wink setup-machine-scope from an elevated terminal", ErrElevationRequired)
	}
	return setupWindowsMachineNamespaceAt(path)
}

func setupWindowsMachineNamespaceAt(path string) error {
	status := inspectMachineNamespaceAt(path)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}

	if err := os.Mkdir(path, 0o755); err != nil {
		return fmt.Errorf("create machine namespace: %w", err)
	}
	for _, name := range []string{ownerLockFilename, ownerMetadataFilename} {
		filePath := filepath.Join(path, name)
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
		if err := setWindowsOwner(filePath); err != nil {
			return fmt.Errorf("set %s owner: %w", name, err)
		}
		if err := setWindowsDACL(filePath, windowsFileAccessMask()); err != nil {
			return fmt.Errorf("protect %s: %w", name, err)
		}
	}
	if err := setWindowsOwner(path); err != nil {
		return fmt.Errorf("set machine namespace owner: %w", err)
	}
	if err := setWindowsDACL(path, windowsDirectoryAccessMask()); err != nil {
		return fmt.Errorf("protect machine namespace: %w", err)
	}

	status = inspectMachineNamespaceAt(path)
	if !status.Ready {
		return fmt.Errorf("%w: %s", ErrNamespaceNotReady, status.Detail)
	}
	return nil
}

func setWindowsOwner(path string) error {
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	return setWindowsOwnerSID(path, administratorsSID)
}

func setWindowsOwnerSID(path string, owner *windows.SID) error {
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		owner,
		nil,
		nil,
		nil,
	); err != nil {
		return fmt.Errorf("set owner to %s: %w", owner.String(), err)
	}
	return nil
}

func windowsProcessElevated() (bool, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer func() { _ = token.Close() }()
	return token.IsElevated(), nil
}

func windowsDirectoryAccessMask() windows.ACCESS_MASK {
	return windows.FILE_LIST_DIRECTORY |
		windows.FILE_TRAVERSE |
		windows.FILE_READ_ATTRIBUTES |
		windows.READ_CONTROL |
		windows.SYNCHRONIZE
}

func windowsFileAccessMask() windows.ACCESS_MASK {
	return windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
}

func windowsACLSpec(authenticatedMask windows.ACCESS_MASK) ([]windows.EXPLICIT_ACCESS, map[string]windows.ACCESS_MASK, error) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve Administrators SID: %w", err)
	}
	authenticatedSID, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve Authenticated Users SID: %w", err)
	}

	entries := []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(systemSID, windowsFullControlMask),
		windowsAccessEntry(administratorsSID, windowsFullControlMask),
		windowsAccessEntry(authenticatedSID, authenticatedMask),
	}
	expected := map[string]windows.ACCESS_MASK{
		systemSID.String():         windowsFullControlMask,
		administratorsSID.String(): windowsFullControlMask,
		authenticatedSID.String():  authenticatedMask,
	}
	return entries, expected, nil
}

func windowsAccessEntry(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func setWindowsDACL(path string, authenticatedMask windows.ACCESS_MASK) error {
	entries, _, err := windowsACLSpec(authenticatedMask)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("set protected DACL: %w", err)
	}
	return nil
}

func validateWindowsDACL(path string, authenticatedMask windows.ACCESS_MASK) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%w: read %s security descriptor: %v", ErrNamespaceUnsafe, path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: read %s owner: %v", ErrNamespaceUnsafe, path, err)
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("%w: %s owner %s is neither Administrators nor LocalSystem", ErrNamespaceUnsafe, path, owner.String())
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("%w: read %s DACL control: %v", ErrNamespaceUnsafe, path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: %s DACL inherits from its parent", ErrNamespaceUnsafe, path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: read %s access entries: %v", ErrNamespaceUnsafe, path, err)
	}
	_, expected, err := windowsACLSpec(authenticatedMask)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNamespaceUnsafe, err)
	}
	if int(dacl.AceCount) != len(expected) {
		return fmt.Errorf("%w: %s has %d DACL entries, want %d", ErrNamespaceUnsafe, path, dacl.AceCount, len(expected))
	}

	seen := make(map[string]struct{}, len(expected))
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("%w: read %s DACL entry %d: %v", ErrNamespaceUnsafe, path, index, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return fmt.Errorf("%w: %s DACL entry %d is not an explicit allow entry", ErrNamespaceUnsafe, path, index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("%w: %s DACL entry %d has an invalid SID", ErrNamespaceUnsafe, path, index)
		}
		sidString := sid.String()
		expectedMask, ok := expected[sidString]
		if !ok || ace.Mask != expectedMask {
			return fmt.Errorf("%w: %s has an unexpected DACL entry for %s with mask %#x", ErrNamespaceUnsafe, path, sidString, ace.Mask)
		}
		if _, duplicate := seen[sidString]; duplicate {
			return fmt.Errorf("%w: %s has a duplicate DACL entry for %s", ErrNamespaceUnsafe, path, sidString)
		}
		seen[sidString] = struct{}{}
	}
	return nil
}

func rejectWindowsReparsePoint(path string) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: encode %s: %v", ErrNamespaceUnsafe, path, err)
	}
	attributes, err := windows.GetFileAttributes(pathPointer)
	if err != nil {
		return fmt.Errorf("%w: inspect %s attributes: %v", ErrNamespaceUnsafe, path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: %s is a reparse point", ErrNamespaceUnsafe, path)
	}
	return nil
}

func validateWindowsSingleLink(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: open %s for link validation: %v", ErrNamespaceUnsafe, path, err)
	}
	defer func() { _ = file.Close() }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return fmt.Errorf("%w: inspect %s links: %v", ErrNamespaceUnsafe, path, err)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%w: %s has %d hard links, want 1", ErrNamespaceUnsafe, path, info.NumberOfLinks)
	}
	return nil
}
