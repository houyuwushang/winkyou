//go:build !unix && !windows

package gatecchildstream

import (
	"os"
	"time"
)

func adoptPipe(file *os.File, _ time.Time) (*os.File, error) {
	if file != nil {
		_ = file.Close()
	}
	return nil, ErrInvalidStream
}
func setPipeReadDeadline(*os.File, time.Time) error  { return ErrInvalidStream }
func setPipeWriteDeadline(*os.File, time.Time) error { return ErrInvalidStream }
