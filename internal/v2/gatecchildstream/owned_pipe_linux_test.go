//go:build linux

package gatecchildstream

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOwnedPipeWriteCancellationNeedsNoPeerRead(t *testing.T) {
	peer, original := mustDiagnosticPipe(t)
	defer peer.Close()
	stream, err := New(newBlockingReadCloser(), original, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := original.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("original output alias survived adoption")
	}
	file := stream.writer.(*os.File)
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	// Fill the pipe without changing production accounting or asking the
	// unread peer to cooperate. Only the subsequent one-byte Stream.Write is
	// protocol I/O. CLOEXEC and nonblocking are checked without File.Fd(),
	// which could itself put a pollable Go file back in blocking mode.
	var fillErr error
	if err := raw.Control(func(fd uintptr) {
		flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
		fdFlags, fdErr := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || fdErr != nil || flags&unix.O_NONBLOCK == 0 || fdFlags&unix.FD_CLOEXEC == 0 {
			fillErr = errors.New("adopted descriptor is not nonblocking CLOEXEC")
			return
		}
		buffer := make([]byte, 4096)
		for i := 0; i < 1024; i++ {
			_, err = unix.Write(int(fd), buffer)
			if errors.Is(err, unix.EAGAIN) {
				return
			}
			if err != nil {
				fillErr = errors.New("pipe fill failed")
				return
			}
		}
		fillErr = errors.New("pipe did not reach bounded backpressure")
	}); err != nil || fillErr != nil {
		t.Fatal("backpressure precondition failed")
	}
	written := make(chan error, 1)
	go func() { _, err := stream.Write([]byte{1}); written <- err }()
	if !observePipePollWait("(*Stream).Write") {
		t.Fatal("owned output write did not enter the poller")
	}
	started := time.Now()
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write incorrectly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write survived close with peer still unread")
	}
	if w := stream.Witness(); !w.Drained || !w.Closed || w.BytesWritten != 0 {
		t.Fatalf("write drain witness=%+v", w)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("adopted output descriptor survived close")
	}
	t.Logf("unread pipe: drained=true bytes_written=0 close_ms=%d sockets=0", time.Since(started).Milliseconds())
}

func TestOwnedPipeExpiredDeadlineInterruptsRead(t *testing.T) {
	input, peer := mustDiagnosticPipe(t)
	defer peer.Close()
	stream, err := New(input, &memoryWriteCloser{}, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	read := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); read <- err }()
	if !observePipePollWait("(*Stream).Read") {
		t.Fatal("owned input did not enter the poller")
	}
	if err := stream.SetDeadline(time.Now()); err != nil {
		t.Fatal("cancellation deadline was rejected")
	}
	select {
	case err := <-read:
		if !errors.Is(err, ErrDeadline) {
			t.Fatalf("expired read=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired deadline required peer EOF")
	}
	if err := stream.Close(); err != nil || !stream.Witness().Drained {
		t.Fatal("expired pipe did not drain")
	}
}

func TestPipePartialAdoptionClosesAllOwnersAndRejectsFiles(t *testing.T) {
	// Initialize the runtime poller before the descriptor baseline.
	warmRead, warmWrite := mustDiagnosticPipe(t)
	_ = warmRead.Close()
	_ = warmWrite.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("descriptor inventory unavailable")
	}
	input, peer := mustDiagnosticPipe(t)
	output, err := os.CreateTemp(t.TempDir(), "not-a-pipe-")
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	stream, adoptErr := New(input, output, time.Now().Add(time.Second))
	if stream != nil || !errors.Is(adoptErr, ErrInvalidStream) {
		t.Fatal("ordinary file accepted as bounded pipe")
	}
	for _, file := range []*os.File{input, output} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("partial adoption retained an owner")
		}
	}
	_ = peer.Close()
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("partial adoption leaked a descriptor")
	}
	writer := &memoryWriteCloser{}
	if stream, err := New((*os.File)(nil), writer, time.Now().Add(time.Second)); stream != nil || !errors.Is(err, ErrInvalidStream) || !writer.closed {
		t.Fatal("nil file did not fail closed")
	}
}
