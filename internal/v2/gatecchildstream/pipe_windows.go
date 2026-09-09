//go:build windows

package gatecchildstream

import (
	"os"
	"time"
)

// Windows os.File.Close uses CancelIoEx for pipes and waits for active I/O.
// Native file deadlines are NOT supported by these synchronous handles. Keep
// the existing timer -> Close cancellation, not a new native-deadline gate.
func adoptPipe(file *os.File, _ time.Time) (*os.File, error) {
	if file == nil {
		return nil, ErrInvalidStream
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		_ = file.Close()
		return nil, ErrInvalidStream
	}
	return file, nil
}

func setPipeReadDeadline(*os.File, time.Time) error  { return nil }
func setPipeWriteDeadline(*os.File, time.Time) error { return nil }
