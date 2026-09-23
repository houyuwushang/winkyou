//go:build linux && fieldc1c

package c1crouter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func inode(path string) (uint64, error) {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return 0, ErrOwnership
	}
	return st.Ino, nil
}

func openNamespace(name string, expected uint64) (*os.File, error) {
	if name == "" || strings.ContainsAny(name, "/\\.\r\n ") {
		return nil, ErrOwnership
	}
	fd, e := unix.Open("/var/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrOwnership
	}
	f := os.NewFile(uintptr(fd), "owned-network-namespace")
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrOwnership
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	init, e := inode("/proc/1/ns/net")
	if e != nil || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || st.Ino == init || expected != 0 && st.Ino != expected {
		_ = f.Close()
		return nil, ErrOwnership
	}
	return f, nil
}

// All bind/open calls run synchronously on the locked thread; readers may
// subsequently use these namespace-bound fds without inheriting namespace
// authority. A failed restore discards the OS thread.
func inNamespace(target *os.File, body func() error) error {
	if target == nil || body == nil {
		return ErrOwnership
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, e := os.Open("/proc/thread-self/ns/net")
		if e != nil {
			runtime.UnlockOSThread()
			done <- ErrOwnership
			return
		}
		if unix.Setns(int(target.Fd()), unix.CLONE_NEWNET) != nil {
			_ = original.Close()
			runtime.UnlockOSThread()
			done <- ErrOwnership
			return
		}
		returned := false
		defer func() {
			if recover() != nil || !returned {
				e = errIO
			}
			if unix.Setns(int(original.Fd()), unix.CLONE_NEWNET) == nil {
				runtime.UnlockOSThread()
			} else {
				e = ErrOwnership
			}
			_ = original.Close()
			done <- e
		}()
		e = body()
		returned = true
	}()
	return <-done
}

type cappedOutput struct {
	bytes.Buffer
	maximum int
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.maximum {
		return 0, ErrResource
	}
	return b.Buffer.Write(p)
}

func executable(name string) (string, error) {
	if !oneOf(name, "ip", "nft", "ss", "conntrack", "sysctl") {
		return "", ErrInvalid
	}
	for _, base := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p, e := filepath.EvalSymlinks(filepath.Join(base, name))
		if e != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil && st.Uid == 0 && st.Mode&0o022 == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o111 != 0 {
			return p, nil
		}
	}
	return "", ErrCommandUnavailable
}

// argv comes only from a typed plan, never a serialized command or shell.
// Captured output is private; every outward error is a stable class.
func runCommand(ctx context.Context, ns, name string, input io.Reader, args ...string) ([]byte, error) {
	program, e := executable(name)
	if e != nil {
		return nil, e
	}
	if ns != "" {
		file, err := openNamespace(ns, 0)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		ip, err := executable("ip")
		if err != nil {
			return nil, err
		}
		args = append([]string{"netns", "exec", ns, program}, args...)
		program = ip
	}
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, program, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdin = input
	cmd.WaitDelay = 100 * time.Millisecond
	output := &cappedOutput{maximum: 1024 * 1024}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	data := append([]byte(nil), output.Bytes()...)
	if commandCtx.Err() != nil {
		return data, commandCtx.Err()
	}
	if errors.Is(err, exec.ErrNotFound) {
		return data, ErrCommandUnavailable
	}
	if err != nil {
		return data, err
	} // caller must classify; never print this error
	return data, nil
}
