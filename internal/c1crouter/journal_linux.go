//go:build linux && fieldc1c

package c1crouter

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
)

type ownership struct {
	Schema          string    `json:"schema"`
	Digest          string    `json:"digest"`
	PID             int       `json:"pid"`
	Start           string    `json:"start"`
	ChildPID        int       `json:"child_pid"`
	ChildStart      string    `json:"child_start"`
	Namespaces      [2]uint64 `json:"namespace_inodes"`
	Placeholders    [2]uint64 `json:"placeholder_inodes"`
	TransitForward  *int      `json:"transit_forward_original"`
	CeilingOriginal *uint64   `json:"ceiling_original"`
	CeilingRestored bool      `json:"ceiling_restored"`
	Clean           bool      `json:"clean"`
}
type journal struct {
	dir   string
	value ownership
	lock  *os.File
}

func processStart(pid int) (string, error) {
	if pid <= 1 {
		return "", ErrOwnership
	}
	b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil {
		return "", ErrOwnership
	}
	// comm may contain spaces/parentheses. starttime is field 22, after comm.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", ErrOwnership
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) < 20 {
		return "", ErrOwnership
	}
	if _, e = strconv.ParseUint(fields[19], 10, 64); e != nil {
		return "", ErrOwnership
	}
	return fields[19], nil
}
func newJournal(snapshot fieldc1c.RouterSnapshot) (*journal, error) {
	// evidence and instance parents must already be private; only this
	// instance's directory hierarchy may be created.
	base := filepath.Dir(filepath.Dir(snapshot.Directory))
	if e := os.Mkdir(base, 0o700); e != nil && !os.IsExist(e) {
		return nil, ErrOwnership
	}
	if privateDirectory(base) != nil || claimDirectory(snapshot.Directory) != nil {
		return nil, ErrOwnership
	}
	f, e := os.OpenFile(filepath.Join(snapshot.Directory, "owner.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if e != nil {
		return nil, ErrOwnership
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = f.Close()
		return nil, ErrOwnership
	}
	start, e := processStart(os.Getpid())
	if e != nil {
		_ = f.Close()
		return nil, e
	}
	j := &journal{dir: snapshot.Directory, lock: f, value: ownership{Schema: "winkyou-router-ownership/1", Digest: snapshot.Digest, PID: os.Getpid(), Start: start}}
	if e = j.save(); e != nil {
		_ = f.Close()
		return nil, e
	}
	return j, nil
}
func (j *journal) save() error {
	b, e := json.Marshal(j.value)
	if e != nil {
		return errIO
	}
	defer clear(b)
	// A killed writer may leave an incomplete temporary record. Never parse
	// it as authority, overwrite it, or let it block the guardian's cleanup:
	// each update claims a fresh 0600 O_EXCL file. The last durable rename is
	// the only recovery authority; interrupted bytes remain private evidence.
	f, e := os.CreateTemp(j.dir, "ownership.pending-")
	if e != nil {
		return ErrOwnership
	}
	tmp := f.Name()
	n, e := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil || n != len(b) || syncErr != nil || closeErr != nil {
		return errIO
	}
	if os.Rename(tmp, filepath.Join(j.dir, "ownership.json")) != nil || syncDir(j.dir) != nil {
		return errIO
	}
	return nil
}
func readOwnership(snapshot fieldc1c.RouterSnapshot) (ownership, error) {
	if privateDirectory(snapshot.Directory) != nil {
		return ownership{}, ErrOwnership
	}
	fd, e := unix.Open(filepath.Join(snapshot.Directory, "ownership.json"), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return ownership{}, ErrOwnership
	}
	f := os.NewFile(uintptr(fd), "owned-journal")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Size > 8192 {
		return ownership{}, ErrOwnership
	}
	var value ownership
	decoder := json.NewDecoder(io.LimitReader(f, 8193))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || value.Schema != "winkyou-router-ownership/1" || value.Digest != snapshot.Digest || value.PID <= 1 || value.Start == "" {
		return ownership{}, ErrOwnership
	}
	return value, nil
}
func (j *journal) close() {
	if j.lock != nil {
		_ = j.lock.Close()
		j.lock = nil
	}
}
