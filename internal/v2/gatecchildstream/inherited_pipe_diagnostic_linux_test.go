//go:build linux

package gatecchildstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const inheritedPipeDiagnosticEnv = "WINKYOU_PR127_INHERITED_PIPE_DIAGNOSTIC"

type inheritedPipeDiagnostic struct {
	ReadSyscallObserved bool  `json:"read_syscall_observed"`
	NativeDeadline      bool  `json:"native_deadline"`
	CloseReturned       bool  `json:"close_returned"`
	DrainError          bool  `json:"drain_error"`
	Closed              bool  `json:"closed"`
	Drained             bool  `json:"drained"`
	ReadJoined          bool  `json:"read_joined"`
	CloseMillis         int64 `json:"close_ms"`
}

// This is a diagnostic RED regression, not approval of a missing drain. It
// exercises the production Stream with an inherited blocking stdin rather
// than net.Pipe. No socket, SSH, governor, artifact or peer material exists.
func TestInheritedStdinReadMustDrainWithoutPeerEOF(t *testing.T) {
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("diagnostic executable unavailable")
	}
	input, peer := mustDiagnosticPipe(t)
	defer input.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestInheritedStdinDiagnosticHelper$", "-test.timeout=6s")
	command.Env = append(os.Environ(), inheritedPipeDiagnosticEnv+"="+directory)
	command.Stdin, command.Stdout, command.Stderr = input, io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("diagnostic child start failed")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	waited := false
	defer func() {
		_ = peer.Close()
		if !waited {
			_ = command.Process.Kill() // Only the child created by this test.
			<-done
		}
	}()
	_ = input.Close()

	var beforeEOF inheritedPipeDiagnostic
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	waiting := true
	for waiting {
		payload, readErr := os.ReadFile(filepath.Join(directory, "before-eof.json"))
		if readErr == nil && json.Unmarshal(payload, &beforeEOF) == nil {
			waiting = false
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("diagnostic child did not publish bounded close result")
		case <-done:
			waited = true
			t.Fatal("diagnostic child exited before close result")
		case <-ticker.C:
		}
	}
	// EOF is supplied only AFTER the production Close result is captured.
	// Releasing this owned pipe also makes a failing regression leave no reader.
	_ = peer.Close()
	select {
	case err := <-done:
		waited = true
		if err != nil {
			t.Fatal("diagnostic child did not join after peer EOF")
		}
	case <-ctx.Done():
		t.Fatal("diagnostic child exceeded external cleanup deadline")
	}
	joined, err := os.ReadFile(filepath.Join(directory, "reader-joined"))
	if err != nil || string(joined) != "joined" {
		t.Fatal("diagnostic reader join was not witnessed")
	}
	t.Logf("inherited stdin: read_syscall=%t native_deadline=%t close_returned=%t drain_error=%t closed=%t drained=%t read_joined_before_peer_eof=%t close_ms=%d reader_joined_after_peer_eof=true child_exited=true sockets=0",
		beforeEOF.ReadSyscallObserved, beforeEOF.NativeDeadline, beforeEOF.CloseReturned,
		beforeEOF.DrainError, beforeEOF.Closed, beforeEOF.Drained, beforeEOF.ReadJoined, beforeEOF.CloseMillis)
	if !beforeEOF.ReadSyscallObserved {
		t.Fatal("inherited blocking read precondition was not observed")
	}
	if !beforeEOF.CloseReturned || beforeEOF.DrainError || !beforeEOF.Closed || !beforeEOF.Drained || !beforeEOF.ReadJoined {
		t.Fatal("accepted inherited stdin did not interrupt and drain its read without peer EOF")
	}
}

func TestInheritedStdinDiagnosticHelper(t *testing.T) {
	directory := os.Getenv(inheritedPipeDiagnosticEnv)
	if directory == "" {
		t.Skip("owned diagnostic subprocess only")
	}
	absolute := time.Now().Add(5 * time.Second)
	nativeDeadline := os.Stdin.SetReadDeadline(absolute) == nil
	stream, err := New(os.Stdin, &memoryWriteCloser{}, absolute)
	if err != nil {
		t.Fatal("diagnostic stream rejected")
	}
	thread := make(chan int, 1)
	readDone := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		thread <- unix.Gettid()
		_, _ = stream.Read(make([]byte, 1))
		close(readDone)
	}()
	tid := <-thread
	observed := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		payload, readErr := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/syscall", tid))
		fields := strings.Fields(string(payload))
		if readErr == nil && len(fields) >= 2 {
			number, numberErr := strconv.ParseUint(fields[0], 0, 64)
			descriptor, descriptorErr := strconv.ParseUint(fields[1], 0, 64)
			if numberErr == nil && descriptorErr == nil && number == unix.SYS_READ && descriptor == 0 {
				observed = true
				break
			}
		}
		time.Sleep(time.Millisecond) // Bounded passive syscall observation only.
	}
	started := time.Now()
	closeErr := stream.Close()
	witness := stream.Witness()
	report := inheritedPipeDiagnostic{
		ReadSyscallObserved: observed, NativeDeadline: nativeDeadline, CloseReturned: true,
		DrainError: errors.Is(closeErr, ErrDrain), Closed: witness.Closed, Drained: witness.Drained,
		CloseMillis: time.Since(started).Milliseconds(),
	}
	select {
	case <-readDone:
		report.ReadJoined = true
	default:
	}
	payload, err := json.Marshal(report)
	if err != nil || os.WriteFile(filepath.Join(directory, "before-eof.json"), payload, 0o600) != nil {
		t.Fatal("diagnostic close result write failed")
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("diagnostic inherited read did not join after peer EOF")
	}
	if os.WriteFile(filepath.Join(directory, "reader-joined"), []byte("joined"), 0o600) != nil {
		t.Fatal("diagnostic join result write failed")
	}
}

func mustDiagnosticPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("diagnostic pipe unavailable")
	}
	return reader, writer
}
