//go:build linux

package sshchildwrapper

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstallationValidationRejectsSymlinkHardlinkAndWritableParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "gatec")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(directory, "wrapper")
	binary := filepath.Join(directory, "wink")
	for _, path := range []string{wrapper, binary} {
		if err := os.WriteFile(path, []byte("synthetic-test-file"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	expectedUID := uint32(os.Geteuid())
	if err := validateInstallationAt(root, wrapper, binary, expectedUID); err != nil {
		t.Fatalf("valid installation: %v", err)
	}

	if err := os.Chmod(directory, 0o722); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallationAt(root, wrapper, binary, expectedUID); !errors.Is(err, ErrWrapperInvalid) {
		t.Fatalf("writable parent error=%v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(directory, "wrapper-link")
	if err := os.Symlink(wrapper, link); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallationAt(root, link, binary, expectedUID); !errors.Is(err, ErrWrapperInvalid) {
		t.Fatalf("symlink error=%v", err)
	}

	hardlink := filepath.Join(directory, "wrapper-hardlink")
	if err := os.Link(wrapper, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallationAt(root, wrapper, binary, expectedUID); !errors.Is(err, ErrWrapperInvalid) {
		t.Fatalf("hardlink error=%v", err)
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(wrapper, &stat); err != nil || stat.Nlink < 2 {
		t.Fatalf("hardlink witness nlink=%d err=%v", stat.Nlink, err)
	}
}
