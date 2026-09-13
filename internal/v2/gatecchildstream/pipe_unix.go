//go:build unix

package gatecchildstream

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// adoptPipe consumes an exclusively transferred pipe BEFORE any I/O. Reusing
// os.Stdin's wrapper after SetNonblock would leave it outside Go's poller. A
// single temporary CLOEXEC duplicate permits a pollable wrapper; the original
// wrapper is closed before returning, including every failure path. This does
// not open a path, socket, second stream or process, and exposes no descriptor.
func adoptPipe(original *os.File, deadline time.Time) (*os.File, error) {
	if original == nil {
		return nil, ErrInvalidStream
	}
	defer original.Close()
	info, err := original.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return nil, ErrInvalidStream
	}
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, ErrInvalidStream
	}
	descriptor := -1
	var adoptErr error
	err = raw.Control(func(fd uintptr) {
		// Never repopulate stdin/stdout/stderr, or acquire an inheritable alias.
		descriptor, adoptErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 3)
		if adoptErr == nil {
			adoptErr = unix.SetNonblock(descriptor, true)
		}
	})
	if err != nil || adoptErr != nil {
		if descriptor >= 0 {
			_ = unix.Close(descriptor)
		}
		return nil, ErrInvalidStream
	}
	owned := os.NewFile(uintptr(descriptor), "gate-c-owned-pipe")
	if owned == nil {
		_ = unix.Close(descriptor)
		return nil, ErrInvalidStream
	}
	// Verify poller admission; unsupported pipe handles fail before protocol I/O.
	if owned.SetDeadline(deadline) != nil || original.Close() != nil {
		_ = owned.Close()
		return nil, ErrInvalidStream
	}
	return owned, nil
}

func setPipeReadDeadline(file *os.File, deadline time.Time) error {
	return file.SetReadDeadline(deadline)
}

func setPipeWriteDeadline(file *os.File, deadline time.Time) error {
	return file.SetWriteDeadline(deadline)
}
