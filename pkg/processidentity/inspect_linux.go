//go:build linux

package processidentity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Inspect returns field 22 (starttime) from /proc/pid/stat. starttime is the
// number of clock ticks since boot at which this particular process started.
func Inspect(pid int) (id string, alive bool, err error) {
	if err := validatePID(pid); err != nil {
		return "", false, err
	}

	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	stat, err := os.ReadFile(statPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("process identity: read %s: %w", statPath, err)
	}

	id, processState, err := parseLinuxStatDetails(stat)
	if err != nil {
		return "", false, fmt.Errorf("process identity: parse %s: %w", statPath, err)
	}
	if processState == "Z" || processState == "X" || processState == "x" {
		return id, false, nil
	}
	return id, true, nil
}

func parseLinuxStat(stat []byte) (string, error) {
	id, _, err := parseLinuxStatDetails(stat)
	return id, err
}

func parseLinuxStatDetails(stat []byte) (string, string, error) {
	text := strings.TrimSpace(string(stat))
	openParen := strings.IndexByte(text, '(')
	closeParen := strings.LastIndex(text, ") ")
	if openParen <= 0 || closeParen <= openParen {
		return "", "", errors.New("malformed process stat command field")
	}

	statPID := strings.TrimSpace(text[:openParen])
	parsedPID, err := strconv.ParseUint(statPID, 10, 64)
	if err != nil || parsedPID == 0 {
		return "", "", fmt.Errorf("invalid process stat pid %q", statPID)
	}

	// The first item after the command is field 3 (state), so field 22 is
	// item 19 in this zero-based slice.
	fields := strings.Fields(text[closeParen+2:])
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return "", "", fmt.Errorf("process stat has %d post-command fields; need at least %d", len(fields), startTimeIndex+1)
	}
	startTime, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return "", "", fmt.Errorf("invalid process starttime %q: %w", fields[startTimeIndex], err)
	}
	return strconv.FormatUint(startTime, 10), fields[0], nil
}
