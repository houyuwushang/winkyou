//go:build windows

package governor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsMachineNamespaceDirectory = "WinkYou-SafetyV2"
	windowsUserNamespaceDirectory    = "WinkYou-SafetyUserV2"
)

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

func platformUserAcknowledgedNamespacePath() (string, error) {
	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("resolve Windows LocalAppData known folder: %w", err)
	}
	return filepath.Join(localAppData, windowsUserNamespaceDirectory), nil
}

func inspectMachineNamespaceAt(path string) NamespaceStatus {
	return inspectWindowsNamespaceAt(path, ScopeMachine)
}

func inspectUserAcknowledgedNamespaceAt(path string) NamespaceStatus {
	return inspectWindowsNamespaceAt(path, ScopeUserAcknowledged)
}

func inspectWindowsNamespaceAt(path string, scope Scope) NamespaceStatus {
	requiresElevation := scope == ScopeMachine
	if !filepath.IsAbs(path) {
		return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: namespace path is not absolute", ErrNamespaceUnsafe), requiresElevation)
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: inspect namespace parent %s: %v", ErrNamespaceUnsafe, parent, err), requiresElevation)
	}
	if !parentInfo.IsDir() {
		return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: namespace parent %s is not a directory", ErrNamespaceUnsafe, parent), requiresElevation)
	}
	if err := rejectWindowsReparsePoint(parent); err != nil {
		return unsafeNamespaceStatus(scope, path, err, requiresElevation)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		detail := "machine namespace has not been installed"
		if scope == ScopeUserAcknowledged {
			detail = "user-acknowledged namespace has not been prepared"
		}
		return missingNamespaceStatus(scope, path, detail, requiresElevation)
	}
	if err != nil {
		return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: inspect namespace: %v", ErrNamespaceUnsafe, err), requiresElevation)
	}
	if !info.IsDir() {
		return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: namespace is not a directory", ErrNamespaceUnsafe), requiresElevation)
	}
	if err := rejectWindowsReparsePoint(path); err != nil {
		return unsafeNamespaceStatus(scope, path, err, requiresElevation)
	}
	if err := validateWindowsNamespaceDACL(path, scope, windowsDirectoryAccessMask()); err != nil {
		return unsafeNamespaceStatus(scope, path, err, requiresElevation)
	}

	for _, name := range namespaceFixedFilenames() {
		filePath := filepath.Join(path, name)
		fileInfo, err := os.Lstat(filePath)
		if err != nil {
			return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: inspect %s: %v", ErrNamespaceUnsafe, name, err), requiresElevation)
		}
		if !fileInfo.Mode().IsRegular() {
			return unsafeNamespaceStatus(scope, path, fmt.Errorf("%w: %s is not a regular file", ErrNamespaceUnsafe, name), requiresElevation)
		}
		if err := rejectWindowsReparsePoint(filePath); err != nil {
			return unsafeNamespaceStatus(scope, path, err, requiresElevation)
		}
		if err := validateWindowsSingleLink(filePath); err != nil {
			return unsafeNamespaceStatus(scope, path, err, requiresElevation)
		}
		if err := validateWindowsNamespaceDACL(filePath, scope, windowsFileAccessMask()); err != nil {
			return unsafeNamespaceStatus(scope, path, err, requiresElevation)
		}
	}

	detail := "protected machine namespace and fixed owner files are ready"
	if scope == ScopeUserAcknowledged {
		detail = "protected per-user namespace and fixed owner files are ready"
	}
	return readyNamespaceStatus(scope, path, detail)
}

func setupMachineNamespaceAt(path string) error {
	status := inspectMachineNamespaceAt(path)
	if status.Ready {
		if err := validateWindowsMachinePairingLedgerAt(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if !status.Ready && status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}
	elevated, err := machineScopeElevated()
	if err != nil {
		return fmt.Errorf("inspect process elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("%w: run wink setup-machine-scope from an elevated terminal", ErrElevationRequired)
	}
	return setupWindowsMachineNamespaceAt(path)
}

func machineScopeElevated() (bool, error) {
	return windowsProcessElevated()
}

func setupWindowsMachineNamespaceAt(path string) error {
	status := inspectMachineNamespaceAt(path)
	if status.Ready {
		return setupWindowsMachinePairingLedgerAt(path, time.Now().UTC())
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}

	if err := os.Mkdir(path, 0o755); err != nil {
		return fmt.Errorf("create machine namespace: %w", err)
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
	if err := setupWindowsMachinePairingLedgerAt(path, time.Now().UTC()); err != nil {
		return err
	}

	status = inspectMachineNamespaceAt(path)
	if !status.Ready {
		return fmt.Errorf("%w: %s", ErrNamespaceNotReady, status.Detail)
	}
	return nil
}

func setupWindowsMachinePairingLedgerAt(namespace string, now time.Time) error {
	if err := validateWindowsMachinePairingLedgerAt(namespace); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	path := filepath.Join(namespace, pairingLedgerFilename)
	if err := createPairingLedgerFile(path, 0o600, now, false); err != nil {
		return fmt.Errorf("create %s: %w", pairingLedgerFilename, err)
	}
	if err := setWindowsOwner(path); err != nil {
		return fmt.Errorf("set %s owner: %w", pairingLedgerFilename, err)
	}
	if err := setWindowsDACL(path, windowsFileAccessMask()); err != nil {
		return fmt.Errorf("protect %s: %w", pairingLedgerFilename, err)
	}
	return validateWindowsMachinePairingLedgerAt(namespace)
}

func validateWindowsMachinePairingLedgerAt(namespace string) error {
	path := filepath.Join(namespace, pairingLedgerFilename)
	if err := validateMachinePairingLedgerFile(path); err != nil {
		return err
	}
	validationTime := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	if _, err := readPairingLedgerSnapshot(path, validationTime, "", validateMachinePairingLedgerFile); err != nil {
		return fmt.Errorf("%w: pairing journal validation failed: %v", ErrNamespaceUnsafe, err)
	}
	return nil
}

func setupUserAcknowledgedNamespaceAt(path string) error {
	status := inspectUserAcknowledgedNamespaceAt(path)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}
	return setupWindowsUserAcknowledgedNamespaceAt(path)
}

func setupWindowsUserAcknowledgedNamespaceAt(path string) error {
	status := inspectUserAcknowledgedNamespaceAt(path)
	if status.Ready {
		return nil
	}
	if status.State != NamespaceMissing {
		return fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}

	userSID, err := windowsCurrentUserSID()
	if err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create user-acknowledged namespace: %w", err)
	}
	if err := setWindowsOwnerSID(path, userSID); err != nil {
		return fmt.Errorf("set user-acknowledged namespace owner: %w", err)
	}
	if err := setWindowsUserDACL(path); err != nil {
		return fmt.Errorf("protect user-acknowledged namespace: %w", err)
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
		if err := setWindowsOwnerSID(filePath, userSID); err != nil {
			return fmt.Errorf("set %s owner: %w", name, err)
		}
		if err := setWindowsUserDACL(filePath); err != nil {
			return fmt.Errorf("protect %s: %w", name, err)
		}
	}
	status = inspectUserAcknowledgedNamespaceAt(path)
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

func windowsCurrentUserSID() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("resolve process user SID: %w", err)
	}
	return windows.StringToSid(user.User.Sid.String())
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

func windowsUserACLSpec() ([]windows.EXPLICIT_ACCESS, map[string]windows.ACCESS_MASK, *windows.SID, error) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve Administrators SID: %w", err)
	}
	userSID, err := windowsCurrentUserSID()
	if err != nil {
		return nil, nil, nil, err
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(systemSID, windowsFullControlMask),
		windowsAccessEntry(administratorsSID, windowsFullControlMask),
		windowsAccessEntry(userSID, windowsFullControlMask),
	}
	expected := map[string]windows.ACCESS_MASK{
		systemSID.String():         windowsFullControlMask,
		administratorsSID.String(): windowsFullControlMask,
		userSID.String():           windowsFullControlMask,
	}
	return entries, expected, userSID, nil
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
	return setWindowsExplicitDACL(path, entries)
}

func setWindowsUserDACL(path string) error {
	entries, _, _, err := windowsUserACLSpec()
	if err != nil {
		return err
	}
	return setWindowsExplicitDACL(path, entries)
}

func setWindowsExplicitDACL(path string, entries []windows.EXPLICIT_ACCESS) error {
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
	_, expected, err := windowsACLSpec(authenticatedMask)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNamespaceUnsafe, err)
	}
	return validateWindowsExplicitDACL(path, expected, func(owner *windows.SID) bool {
		return owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)
	}, "Administrators or LocalSystem")
}

func validateWindowsNamespaceDACL(path string, scope Scope, authenticatedMask windows.ACCESS_MASK) error {
	if scope == ScopeMachine {
		return validateWindowsDACL(path, authenticatedMask)
	}
	_, expected, userSID, err := windowsUserACLSpec()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNamespaceUnsafe, err)
	}
	return validateWindowsExplicitDACL(path, expected, func(owner *windows.SID) bool {
		return owner.String() == userSID.String()
	}, userSID.String())
}

func validateWindowsExplicitDACL(path string, expected map[string]windows.ACCESS_MASK, ownerAllowed func(*windows.SID) bool, ownerDescription string) error {
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
	if !ownerAllowed(owner) {
		return fmt.Errorf("%w: %s owner %s is not %s", ErrNamespaceUnsafe, path, owner.String(), ownerDescription)
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
