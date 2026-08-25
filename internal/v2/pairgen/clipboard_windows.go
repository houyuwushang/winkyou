//go:build windows

package pairgen

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// writeClipboard sends the single recipient artifact through stdin to the
// OS-provided clipboard utility. The secret never appears in argv, the
// environment, stdout, stderr, or a shell command line. Resolving clip.exe
// from the system directory also avoids PATH-based binary substitution.
func writeClipboard(ctx context.Context, payload []byte) error {
	if ctx == nil || ctx.Err() != nil || len(payload) == 0 {
		return ErrClipboardUnavailable
	}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil || systemDirectory == "" {
		return ErrClipboardUnavailable
	}
	command := exec.CommandContext(ctx, filepath.Join(systemDirectory, "clip.exe"))
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return ErrClipboardUnavailable
	}
	return nil
}
