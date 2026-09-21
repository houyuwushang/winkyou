//go:build linux && fieldc1c

package fieldc1c

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"winkyou/internal/governor"
)

func localMachineReference() (string, error) {
	info, err := os.Lstat("/etc/machine-id")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return "", ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", ErrInvalid
	}
	file, err := os.Open("/etc/machine-id")
	if err != nil {
		return "", ErrInvalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 34))
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(data)
	id := strings.TrimSuffix(string(data), "\n")
	if !hexValue(id, 16) {
		return "", ErrInvalid
	}
	path, err := governor.MachineNamespacePath()
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte("winkyou-c1c-machine-scope/1\n" + id + "\n" + path))
	return "machine-scope-sha256/1:" + hex.EncodeToString(digest[:]), nil
}

// The forced-command environment intentionally has no HOME. Resolve UID 0's
// local home from the root-owned passwd file, without NSS, DNS, or environment
// fallback. No process execution is needed for this read-only operation.
func canonicalFieldHome() (string, error) {
	if os.Geteuid() != 0 {
		return "", ErrInvalid
	}
	info, err := os.Lstat("/etc/passwd")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return "", ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", ErrInvalid
	}
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", ErrInvalid
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, MaxInstanceBytes+1))
	if err != nil || len(payload) > MaxInstanceBytes {
		return "", ErrInvalid
	}
	defer clear(payload)
	var homeDirectory string
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[2] != "0" {
			continue
		}
		if homeDirectory != "" || !filepath.IsAbs(fields[5]) || filepath.Clean(fields[5]) != fields[5] {
			return "", ErrInvalid
		}
		homeDirectory = fields[5]
	}
	if homeDirectory == "" || safeParents(homeDirectory) != nil {
		return "", ErrInvalid
	}
	return homeDirectory, nil
}

func safeParents(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrInvalid
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return ErrInvalid
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
