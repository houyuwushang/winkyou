//go:build linux && natlab

package natlab

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Capture an I/O failure and both namespace identities on the same OS thread.
// Error text deliberately excludes paths, command output and arbitrary errors.
type hostSysctlError struct {
	op        string
	errno     string
	threadNet uint64
	initNet   uint64
	cause     error
}

func (e *hostSysctlError) Error() string {
	return fmt.Sprintf("GATE_B3_HOST_SYSCTL op=%s errno=%s thread_net=%d init_net=%d", e.op, e.errno, e.threadNet, e.initNet)
}

func (e *hostSysctlError) Unwrap() error { return e.cause }

func hostSysctlFailure(op string, err error) error {
	if err == nil {
		return nil
	}
	name := "UNKNOWN"
	var number syscall.Errno
	if errors.As(err, &number) {
		if value := unix.ErrnoName(number); value != "" {
			name = value
		}
	}
	var thread, initial unix.Stat_t
	_ = unix.Stat("/proc/thread-self/ns/net", &thread)
	_ = unix.Stat("/proc/1/ns/net", &initial)
	return &hostSysctlError{op: op, errno: name, threadNet: thread.Ino, initNet: initial.Ino, cause: err}
}

type HostSysctl struct{}

type hostSysctlWitness struct {
	ThreadNet uint64
	InitNet   uint64
}

type hostSysctlReply struct {
	value   []byte
	witness hostSysctlWitness
	err     error
}

// These are the only host proc entries used by the lab. The shared ceiling is
// the only writable one; its existing caller-side authorization stays intact.
func hostSysctlPathAllowed(path string, write bool) bool {
	switch path {
	case "/proc/sys/net/netfilter/nf_conntrack_max":
		return true
	case "/proc/sys/net/netfilter/nf_conntrack_count",
		"/proc/sys/net/netfilter/nf_conntrack_udp_timeout",
		"/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream":
		return !write
	}
	return false
}

// Each request owns a locked thread, enters init explicitly, and discards the
// thread with Goexit. No caller thread or test subprocess must start in init;
// neither namespace restoration nor a reusable scheduler thread is trusted.
func (HostSysctl) request(path string, value []byte, write, legacy bool) hostSysctlReply {
	if !hostSysctlPathAllowed(path, write) {
		return hostSysctlReply{err: errors.New("host sysctl path rejected")}
	}
	if write {
		if number, err := strconv.ParseUint(strings.TrimSpace(string(value)), 10, 64); err != nil || number == 0 {
			return hostSysctlReply{err: errors.New("host sysctl value rejected")}
		}
	}
	result := make(chan hostSysctlReply, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.Goexit()
		var reply hostSysctlReply
		defer func() { result <- reply }()
		initial, err := os.Open("/proc/1/ns/net")
		if err != nil {
			reply.err = hostSysctlFailure("enter", err)
			return
		}
		defer initial.Close()
		if err = unix.Setns(int(initial.Fd()), unix.CLONE_NEWNET); err != nil {
			reply.err = hostSysctlFailure("enter", err)
			return
		}
		var threadNS, initNS unix.Stat_t
		if err = unix.Stat("/proc/thread-self/ns/net", &threadNS); err != nil {
			reply.err = hostSysctlFailure("identity", err)
			return
		}
		if err = unix.Fstat(int(initial.Fd()), &initNS); err != nil {
			reply.err = hostSysctlFailure("identity", err)
			return
		}
		reply.witness = hostSysctlWitness{ThreadNet: threadNS.Ino, InitNet: initNS.Ino}
		if threadNS.Dev != initNS.Dev || threadNS.Ino != initNS.Ino {
			reply.err = hostSysctlFailure("identity", unix.EXDEV)
			return
		}
		op := "read"
		if write {
			op = "write"
		}
		if legacy {
			key := strings.ReplaceAll(strings.TrimPrefix(path, "/proc/sys/"), "/", ".")
			args := []string{"-n", key}
			if write {
				args = []string{"-qw", key + "=" + strings.TrimSpace(string(value))}
			}
			var text string
			text, err = runCommand("sysctl", args...)
			reply.value = []byte(text)
		} else if write {
			err = os.WriteFile(path, value, 0)
		} else {
			reply.value, err = os.ReadFile(path)
		}
		reply.err = hostSysctlFailure(op, err)
	}()
	return <-result
}

func readHostSysctlDiagnostic(path string) ([]byte, error) {
	r := (HostSysctl{}).request(path, nil, false, false)
	return r.value, r.err
}

func writeHostSysctlDiagnostic(path string, value []byte) error {
	return (HostSysctl{}).request(path, value, true, false).err
}

// Preserve the legacy measurement's subprocess cost while selecting its
// namespace through the same thread-bound path as the proc implementation.
func runHostSysctlDiagnostic(op string, args ...string) (string, error) {
	var key string
	switch {
	case op == "read" && len(args) == 2 && args[0] == "-n":
		key = args[1]
	case op == "write" && len(args) == 2 && args[0] == "-qw":
		key = args[1]
	case op == "write" && len(args) == 3 && args[0] == "-q" && args[1] == "-w":
		key = args[2]
	default:
		return "", errors.New("host sysctl arguments rejected")
	}
	value := []byte(nil)
	if op == "write" {
		var found bool
		var text string
		key, text, found = strings.Cut(key, "=")
		if !found {
			return "", errors.New("host sysctl write value missing")
		}
		value = []byte(text + "\n")
	}
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	r := (HostSysctl{}).request(path, value, op == "write", true)
	return string(r.value), r.err
}
