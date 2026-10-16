//go:build linux && natlab

package natlab

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestHostSysctlDiagnostic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := hostSysctlFailure("write", &os.PathError{Op: "open", Path: "private-path-must-not-escape", Err: syscall.EACCES})
	var witness *hostSysctlError
	if !errors.As(err, &witness) || !errors.Is(err, syscall.EACCES) || witness.threadNet == 0 || witness.initNet == 0 {
		t.Fatalf("failure lost errno or namespace identities: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "GATE_B3_HOST_SYSCTL op=write errno=EACCES thread_net=") || strings.Contains(err.Error(), "private-path") {
		t.Fatalf("diagnostic format or redaction changed: %v", err)
	}
	if hostSysctlFailure("read", nil) != nil {
		t.Fatal("successful I/O acquired a failure")
	}
}
