//go:build windows

package gatecchildstream

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsPipeKeepsCloseBasedCancellationWithoutNativeDeadlines(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "close"
		if expired {
			name = "expired-deadline"
		}
		t.Run(name, func(t *testing.T) {
			input, peer, err := os.Pipe()
			if err != nil {
				t.Fatal("owned pipe unavailable")
			}
			defer peer.Close()
			defer input.Close()
			absolute := time.Now().Add(5 * time.Second)
			if err := input.SetReadDeadline(absolute); !errors.Is(err, os.ErrNoDeadline) {
				t.Fatal("synchronous Windows pipe deadline precondition changed")
			}
			stream, err := New(input, &memoryWriteCloser{}, absolute)
			if err != nil {
				t.Fatal("existing Windows pipe rejected")
			}
			pipeInfo := inspectWindowsPipe(input)
			done := make(chan error, 1)
			go func() { _, err := stream.Read(make([]byte, 1)); done <- err }()
			observed := false
			buffer := make([]byte, 64<<10)
			defer clear(buffer)
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				n := runtime.Stack(buffer, true)
				for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
					if strings.Contains(stack, "[syscall]") && strings.Contains(stack, "syscall.SyscallN(") &&
						strings.Contains(stack, "winkyou/internal/v2/gatecchildstream.(*Stream).Read(") {
						observed = true
					}
				}
				if observed {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !observed {
				t.Fatal("real Windows pipe read was not observed")
			}
			started := time.Now()
			if expired {
				if err := stream.SetDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			closeErr, timedOut, syscallCount := closeWithWitness(stream, peer, 5*time.Second)
			t.Logf("CHILDSTREAM_CLOSE_WITNESS expired=%t timed_out=%t syscall_goroutines=%d file_type_pipe=%t named_pipe_info=%t close_ms=%d", expired, timedOut, syscallCount, pipeInfo.fileTypePipe, pipeInfo.namedPipeInfo, time.Since(started).Milliseconds())
			if timedOut {
				t.Fatal("Stream.Close exceeded the five-second witness deadline")
			}
			if closeErr != nil && !errors.Is(closeErr, ErrDrain) {
				t.Fatalf("Stream.Close error=%v", closeErr)
			}
			select {
			case err := <-done:
				if err == nil || expired && !errors.Is(err, ErrDeadline) {
					t.Fatalf("cancelled read=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Windows pipe read required peer EOF")
			}
			if closeErr != nil || !stream.Witness().Drained {
				t.Fatal("Windows pipe did not drain")
			}
			t.Logf("windows pipe: expired=%t close_ms=%d read_joined=true peer_eof=false sockets=0", expired, time.Since(started).Milliseconds())
		})
	}
}

// TestWindowsPipeCloseReturnsBoundedDrainError is the production-regression
// contract for a synchronous Windows pipe. The peer stays open and silent so
// a Close implementation that waits synchronously for the in-flight ReadFile
// cannot hide behind peer EOF. The pre-fix implementation must RED here.
func TestWindowsPipeCloseReturnsBoundedDrainError(t *testing.T) {
	input, peer, err := os.Pipe()
	if err != nil {
		t.Fatal("owned pipe unavailable")
	}
	defer peer.Close()
	defer input.Close()
	absolute := time.Now().Add(5 * time.Second)
	if err := input.SetReadDeadline(absolute); !errors.Is(err, os.ErrNoDeadline) {
		t.Fatal("synchronous Windows pipe deadline precondition changed")
	}
	reader := &blockingWindowsPipeReader{
		file:         input,
		closeEntered: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	stream, err := New(reader, &memoryWriteCloser{}, absolute)
	if err != nil {
		t.Fatal("existing Windows pipe rejected")
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := stream.Read(make([]byte, 1))
		readDone <- readErr
	}()
	if !waitForWindowsPipeReadSyscall(t) {
		t.Fatal("real Windows pipe read was not observed")
	}

	closeErr, timedOut, syscallCount := closeWithReleaseWitness(stream, peer, reader.releaseClose, DrainTimeout+500*time.Millisecond)
	t.Logf("CHILDSTREAM_CLOSE_BOUNDARY timed_out=%t syscall_goroutines=%d close_err=err_drain drained=%t", timedOut, syscallCount, stream.Witness().Drained)
	if timedOut {
		t.Fatal("Stream.Close exceeded DrainTimeout plus 500ms")
	}
	if !errors.Is(closeErr, ErrDrain) {
		t.Fatalf("Stream.Close error=%v, want ErrDrain", closeErr)
	}
	if stream.Witness().Drained {
		t.Fatal("Stream.Close reported drained after the bounded drain failure")
	}
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Windows pipe read did not join after close release")
	}
}

// blockingWindowsPipeReader keeps the underlying real synchronous pipe read
// active while holding the Close call. The gate models the OS close wait
// observed in the first production witness without adding a sleep or changing
// the pipe's read path. The production fix must return ErrDrain while this
// close worker remains blocked, then finish after the gate is released.
type blockingWindowsPipeReader struct {
	file         *os.File
	closeEntered chan struct{}
	releaseClose chan struct{}
	closeOnce    sync.Once
}

func (reader *blockingWindowsPipeReader) Read(buffer []byte) (int, error) {
	return reader.file.Read(buffer)
}

func (reader *blockingWindowsPipeReader) Close() error {
	reader.closeOnce.Do(func() { close(reader.closeEntered) })
	<-reader.releaseClose
	return reader.file.Close()
}

func closeWithReleaseWitness(stream *Stream, peer *os.File, release chan struct{}, timeout time.Duration) (error, bool, int) {
	result := make(chan error, 1)
	go func() { result <- stream.Close() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	releaseOnce := sync.Once{}
	releaseClose := func() { releaseOnce.Do(func() { close(release) }) }
	select {
	case err := <-result:
		releaseClose()
		return err, false, countSyscallGoroutines()
	case <-timer.C:
		// Releasing the test peer and close gate is cleanup only. It happens
		// after the witness deadline so a peer EOF cannot hide the bounded
		// Close contract.
		if peer != nil {
			_ = peer.Close()
		}
		releaseClose()
		select {
		case <-result:
			return ErrDrain, true, countSyscallGoroutines()
		case <-time.After(time.Second):
			return ErrDrain, true, countSyscallGoroutines()
		}
	}
}

func waitForWindowsPipeReadSyscall(t *testing.T) bool {
	t.Helper()
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "[syscall]") && strings.Contains(stack, "syscall.SyscallN(") &&
				strings.Contains(stack, "winkyou/internal/v2/gatecchildstream.(*Stream).Read(") {
				return true
			}
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

type windowsPipeInfo struct {
	fileTypePipe  bool
	namedPipeInfo bool
}

func inspectWindowsPipe(file *os.File) windowsPipeInfo {
	if file == nil {
		return windowsPipeInfo{}
	}
	fileType, err := windows.GetFileType(windows.Handle(file.Fd()))
	if err != nil {
		return windowsPipeInfo{}
	}
	var flags, outBuffer, inBuffer, instances uint32
	namedInfoErr := windows.GetNamedPipeInfo(windows.Handle(file.Fd()), &flags, &outBuffer, &inBuffer, &instances)
	return windowsPipeInfo{fileTypePipe: fileType == windows.FILE_TYPE_PIPE, namedPipeInfo: namedInfoErr == nil}
}

func closeWithWitness(stream *Stream, peer *os.File, timeout time.Duration) (error, bool, int) {
	result := make(chan error, 1)
	go func() { result <- stream.Close() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err, false, countSyscallGoroutines()
	case <-timer.C:
		// Releasing the test peer is cleanup only. It is deliberately after the
		// witness deadline so a peer EOF cannot hide an unbounded Close.
		if peer != nil {
			_ = peer.Close()
		}
		select {
		case <-result:
			return ErrDrain, true, countSyscallGoroutines()
		case <-time.After(time.Second):
			return ErrDrain, true, countSyscallGoroutines()
		}
	}
}

func countSyscallGoroutines() int {
	buffer := make([]byte, 128<<10)
	defer clear(buffer)
	n := runtime.Stack(buffer, true)
	count := 0
	for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
		if strings.Contains(stack, "[syscall]") {
			count++
		}
	}
	return count
}
