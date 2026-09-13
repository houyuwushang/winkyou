//go:build linux

package gatecchildstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const inheritedPipeDiagnosticEnv = "WINKYOU_PR127_INHERITED_PIPE_DIAGNOSTIC"

type inheritedPipeDiagnostic struct {
	ReadInFlight     bool  `json:"read_in_flight"`
	PollWaitObserved bool  `json:"poll_wait_observed"`
	NativeDeadline   bool  `json:"native_deadline"`
	OriginalClosed   bool  `json:"original_closed"`
	CloseReturned    bool  `json:"close_returned"`
	DrainError       bool  `json:"drain_error"`
	Closed           bool  `json:"closed"`
	Drained          bool  `json:"drained"`
	ReadJoined       bool  `json:"read_joined"`
	CloseMillis      int64 `json:"close_ms"`
}

// The original RED is retained in history. Pollable adoption moves the read
// from blocking read(0) into Go's poller on the sole adopted descriptor. Prove
// that actual OS wait, not merely goroutine scheduling before Read, then keep
// every original close/drain/join assertion with the peer write end still open.
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
	var exitErr error
	defer func() {
		_ = peer.Close()
		if !waited {
			_ = command.Process.Kill() // Only the child created by this test.
			<-done
		}
	}()
	_ = input.Close()

	var beforeEOF inheritedPipeDiagnostic
	readReport := func() bool {
		payload, readErr := os.ReadFile(filepath.Join(directory, "before-eof.json"))
		return readErr == nil && json.Unmarshal(payload, &beforeEOF) == nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	waiting := true
	for waiting {
		if readReport() {
			waiting = false
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("diagnostic child did not publish bounded close result")
		case exitErr = <-done:
			waited = true
			// A drained helper can publish and exit before the next poll. Exit
			// is a reason to read its final files, not to discard their witness.
			if !readReport() {
				t.Fatalf("diagnostic child exited without close result: exit_success=%t", exitErr == nil)
			}
			waiting = false
		case <-ticker.C:
		}
	}
	// EOF is supplied only AFTER the production Close result is captured.
	// Releasing this owned pipe also makes a failing regression leave no reader.
	_ = peer.Close()
	if !waited {
		select {
		case exitErr = <-done:
			waited = true
		case <-ctx.Done():
			t.Fatal("diagnostic child exceeded external cleanup deadline")
		}
	}
	// Wait establishes that the final reader-joined file can now be read even
	// if both it and the child exit preceded the parent's first observation.
	joined, err := os.ReadFile(filepath.Join(directory, "reader-joined"))
	if err != nil || string(joined) != "joined" {
		t.Fatal("diagnostic reader join was not witnessed")
	}
	if exitErr != nil {
		t.Fatal("diagnostic child reported unsuccessful exit")
	}
	t.Logf("inherited stdin: read_in_flight=%t poll_wait=%t original_native_deadline=%t original_closed=%t close_returned=%t drain_error=%t closed=%t drained=%t read_joined_before_peer_eof=%t close_ms=%d reader_joined_after_peer_eof=true child_exited=true sockets=0",
		beforeEOF.ReadInFlight, beforeEOF.PollWaitObserved, beforeEOF.NativeDeadline, beforeEOF.OriginalClosed, beforeEOF.CloseReturned,
		beforeEOF.DrainError, beforeEOF.Closed, beforeEOF.Drained, beforeEOF.ReadJoined, beforeEOF.CloseMillis)
	if beforeEOF.NativeDeadline || !beforeEOF.OriginalClosed || !beforeEOF.ReadInFlight || !beforeEOF.PollWaitObserved {
		t.Fatal("inherited blocking pipe was not exclusively adopted into an observed poller read")
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
	_, originalErr := os.Stdin.Stat()
	readDone := make(chan struct{})
	go func() {
		_, _ = stream.Read(make([]byte, 1))
		close(readDone)
	}()
	observed := observePipePollWait("(*Stream).Read")
	stream.mu.Lock()
	inFlight := stream.ops == 1
	stream.mu.Unlock()
	started := time.Now()
	closeErr := stream.Close()
	witness := stream.Witness()
	report := inheritedPipeDiagnostic{
		ReadInFlight: inFlight, PollWaitObserved: observed, NativeDeadline: nativeDeadline,
		OriginalClosed: errors.Is(originalErr, os.ErrClosed), CloseReturned: true,
		DrainError: errors.Is(closeErr, ErrDrain), Closed: witness.Closed, Drained: witness.Drained,
		CloseMillis: time.Since(started).Milliseconds(),
	}
	select {
	case <-readDone:
		report.ReadJoined = true
	case <-time.After(time.Second):
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

// Inspect only whether this exact operation is asleep in the OS poller. Never
// log stack text (which includes private paths). No sleeps gate production I/O.
func observePipePollWait(operation string) bool {
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "[IO wait]") && strings.Contains(stack, "internal/poll.runtime_pollWait(") &&
				strings.Contains(stack, "winkyou/internal/v2/gatecchildstream."+operation+"(") {
				return true
			}
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func mustDiagnosticPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("diagnostic pipe unavailable")
	}
	return reader, writer
}
