//go:build windows

package pairgen

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFullControl windows.ACCESS_MASK = 0x001f01ff

func protectPrivatePath(path string, directory bool) error {
	userSID, err := currentUserSID()
	if err != nil {
		return err
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{accessEntry(userSID), accessEntry(systemSID)}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		userSID, nil, acl, nil); err != nil {
		return err
	}
	return validatePrivatePath(path, directory)
}

func validatePrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || (!directory && !info.Mode().IsRegular()) {
		return ErrOutputUnavailable
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrOutputUnavailable
	}
	attributes, err := windows.GetFileAttributes(pathPointer)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrOutputUnavailable
	}
	if !directory {
		file, err := os.Open(path)
		if err != nil {
			return ErrOutputUnavailable
		}
		var details windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &details)
		_ = file.Close()
		if err != nil || details.NumberOfLinks != 1 {
			return ErrOutputUnavailable
		}
	}
	userSID, err := currentUserSID()
	if err != nil {
		return ErrOutputUnavailable
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return ErrOutputUnavailable
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrOutputUnavailable
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || owner.String() != userSID.String() {
		return ErrOutputUnavailable
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrOutputUnavailable
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return ErrOutputUnavailable
	}
	expected := map[string]struct{}{userSID.String(): {}, systemSID.String(): {}}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != windowsFullControl {
			return ErrOutputUnavailable
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return ErrOutputUnavailable
		}
		if _, ok := expected[sid.String()]; !ok {
			return ErrOutputUnavailable
		}
		delete(expected, sid.String())
	}
	if len(expected) != 0 {
		return ErrOutputUnavailable
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.StringToSid(user.User.Sid.String())
}

func accessEntry(sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windowsFullControl,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID,
			TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}
}

func syncPrivateDirectory(string) error { return nil }
