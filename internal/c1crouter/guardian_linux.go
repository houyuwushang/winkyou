//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
)

type ceilingGuard struct {
	lock    *os.File
	journal *journal
}

func acquireCeiling(snapshot fieldc1c.RouterSnapshot, j *journal) (*ceilingGuard, error) {
	guard := &ceilingGuard{journal: j}
	if !snapshot.Configuration.AllowGlobalConntrackCeiling {
		return guard, nil
	}
	if !time.Now().Before(snapshot.Deadline) {
		return nil, ErrInvalid
	}
	if snapshot.Configuration.DisposableEnvironmentReference == "" {
		return nil, ErrOwnership
	}
	init, e := inode("/proc/1/ns/net")
	current, readErr := inode("/proc/self/ns/net")
	if e != nil || readErr != nil || init != current {
		return nil, ErrOwnership
	}
	f, e := openCeilingLock(true)
	if e != nil {
		return nil, ErrOwnership
	}
	guard.lock = f
	original, e := readSysctl("net.netfilter.nf_conntrack_max")
	if e != nil || original < MappingHardCap {
		_ = f.Close()
		return nil, ErrResource
	}
	count, e := readSysctl("net.netfilter.nf_conntrack_count")
	if e != nil || count >= MappingHardCap/2 {
		_ = f.Close()
		return nil, ErrResource
	}
	// Persist before changing the shared knob; a child cannot release this
	// lock or discard the saved original. The guardian is a separate process.
	j.value.CeilingOriginal = &original
	if j.save() != nil {
		_ = f.Close()
		return nil, errIO
	}
	if e = writeSysctl("net.netfilter.nf_conntrack_max", MappingHardCap); e != nil {
		return guard, e
	}
	return guard, nil
}
func readSysctl(key string) (uint64, error) {
	b, e := runCommand(context.Background(), "", "sysctl", nil, "-n", key)
	if e != nil {
		return 0, errIO
	}
	n, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if e != nil {
		return 0, errIO
	}
	return n, nil
}
func writeSysctl(key string, value uint64) error {
	if _, e := runCommand(context.Background(), "", "sysctl", nil, "-q", "-w", key+"="+strconv.FormatUint(value, 10)); e != nil {
		return errIO
	}
	if got, e := readSysctl(key); e != nil || got != value {
		return errIO
	}
	return nil
}
func (g *ceilingGuard) restore() error {
	if g == nil || g.lock == nil {
		return nil
	}
	defer g.lock.Close()
	if g.journal.value.CeilingOriginal == nil {
		return ErrOwnership
	}
	if e := writeSysctl("net.netfilter.nf_conntrack_max", *g.journal.value.CeilingOriginal); e != nil {
		return e
	}
	g.journal.value.CeilingRestored = true
	return g.journal.save()
}

// A SIGKILL of the guardian itself cannot execute a defer. Explicit teardown
// therefore re-acquires the same exclusive lock and checks the crash journal.
func restoreInterruptedCeiling(s fieldc1c.RouterSnapshot, j *journal) error {
	if j.value.CeilingOriginal == nil || j.value.CeilingRestored {
		return nil
	}
	if !s.Configuration.AllowGlobalConntrackCeiling {
		return ErrOwnership
	}
	f, e := openCeilingLock(false)
	if e != nil {
		return ErrOwnership
	}
	defer f.Close()
	init, e := inode("/proc/1/ns/net")
	current, e2 := inode("/proc/self/ns/net")
	if e != nil || e2 != nil || init != current {
		return ErrOwnership
	}
	value, e := readSysctl("net.netfilter.nf_conntrack_max")
	if e != nil {
		return e
	}
	if value != MappingHardCap && value != *j.value.CeilingOriginal {
		return ErrOwnership
	}
	if e = writeSysctl("net.netfilter.nf_conntrack_max", *j.value.CeilingOriginal); e != nil {
		return e
	}
	j.value.CeilingRestored = true
	return j.save()
}

// Same machine-wide lock as the existing Gate B guardian. /run/lock is often
// a root-owned sticky directory; require sticky protection if others can write.
// The lock itself must be a single-linked root-owned regular file, never a link
// or an object another user can modify. It contains no private evidence.
func openCeilingLock(create bool) (*os.File, error) {
	const dir = "/run/lock"
	var parent unix.Stat_t
	if privateDirectory("/run") != nil || unix.Lstat(dir, &parent) != nil || parent.Uid != 0 || parent.Mode&unix.S_IFMT != unix.S_IFDIR || (parent.Mode&0o022 != 0 && parent.Mode&unix.S_ISVTX == 0) {
		return nil, ErrOwnership
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT
	}
	path := filepath.Join(dir, "winkyou-gate-b3-conntrack.lock")
	fd, e := unix.Open(path, flags, 0o600)
	if e != nil {
		return nil, ErrOwnership
	}
	f := os.NewFile(uintptr(fd), "conntrack-ceiling-lock")
	var st, current unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0o022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil || unix.Lstat(path, &current) != nil || current.Ino != st.Ino || current.Dev != st.Dev {
		_ = f.Close()
		return nil, ErrOwnership
	}
	return f, nil
}
