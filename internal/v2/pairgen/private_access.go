package pairgen

import (
	"io"
	"os"
	"path/filepath"
)

// ReadPrivateFile reuses the reviewed owner-only path validation for Gate C
// local request, artifact, manifest, identity and known-host inputs.
func ReadPrivateFile(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 || !filepath.IsAbs(path) {
		return nil, ErrOutputUnavailable
	}
	if err := validatePrivatePath(path, false); err != nil {
		return nil, ErrOutputUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrOutputUnavailable
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(payload)) > maximum {
		clear(payload)
		return nil, ErrOutputUnavailable
	}
	if err := validatePrivatePath(path, false); err != nil {
		clear(payload)
		return nil, ErrOutputUnavailable
	}
	return payload, nil
}

// WritePrivateFileExclusive creates and synchronizes one owner-only regular
// file. It never adopts, truncates, repairs, or follows an existing leaf.
func WritePrivateFileExclusive(path string, payload []byte) error {
	if path == "" || !filepath.IsAbs(path) {
		return ErrOutputUnavailable
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrOutputUnavailable
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(path)
		}
	}()
	if err := protectPrivatePath(path, false); err != nil {
		return ErrOutputUnavailable
	}
	if _, err := file.Write(payload); err != nil {
		return ErrOutputUnavailable
	}
	if err := file.Sync(); err != nil {
		return ErrOutputUnavailable
	}
	if err := file.Close(); err != nil {
		return ErrOutputUnavailable
	}
	if err := protectPrivatePath(path, false); err != nil {
		return ErrOutputUnavailable
	}
	failed = false
	return nil
}

func SyncPrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || validatePrivateDirectoryContainer(path) != nil {
		return ErrOutputUnavailable
	}
	if err := syncPrivateDirectory(path); err != nil {
		return ErrOutputUnavailable
	}
	return nil
}

// validatePrivateDirectoryContainer intentionally accepts the already
// reviewed machine namespace as a container even though it is not the
// per-user 0700 output directory used by the pair generator. The leaf files
// remain owner-only and O_EXCL.
func validatePrivateDirectoryContainer(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOutputUnavailable
	}
	return nil
}
