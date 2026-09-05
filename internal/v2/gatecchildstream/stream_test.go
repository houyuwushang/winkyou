package gatecchildstream

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/oobcarrier"
)

func TestStreamCarriesOnlyBoundedRawBytesAndDrains(t *testing.T) {
	input, inputPeer := net.Pipe()
	outputPeer, output := net.Pipe()
	defer inputPeer.Close()
	defer outputPeer.Close()
	stream, err := New(input, output, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	incoming := []byte("raw-wyrc-input")
	writeDone := make(chan error, 1)
	go func() { _, err := inputPeer.Write(incoming); writeDone <- err }()
	buffer := make([]byte, len(incoming))
	if _, err := io.ReadFull(stream, buffer); err != nil || !bytes.Equal(buffer, incoming) {
		t.Fatalf("read=%q err=%v", buffer, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}

	outgoing := []byte("raw-wyrc-output")
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, len(outgoing))
		_, err := io.ReadFull(outputPeer, buffer)
		if err == nil && !bytes.Equal(buffer, outgoing) {
			err = errors.New("outgoing bytes changed")
		}
		readDone <- err
	}()
	if n, err := stream.Write(outgoing); err != nil || n != len(outgoing) {
		t.Fatalf("Write n=%d err=%v", n, err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	witness := stream.Witness()
	if witness.BytesRead != len(incoming) || witness.BytesWritten != len(outgoing) || !witness.Closed || !witness.Drained {
		t.Fatalf("witness=%+v", witness)
	}
}

func TestStreamEnforcesIndependentDirectionBudgets(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, oobcarrier.MaxApplicationBytes+1)
	reader := &memoryReadCloser{Reader: bytes.NewReader(payload)}
	writer := &memoryWriteCloser{}
	stream, err := New(reader, writer, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	read := make([]byte, oobcarrier.MaxApplicationBytes+1)
	if n, err := io.ReadFull(stream, read[:oobcarrier.MaxApplicationBytes]); err != nil || n != oobcarrier.MaxApplicationBytes {
		t.Fatalf("ReadFull n=%d err=%v", n, err)
	}
	if n, err := stream.Read(read[:1]); n != 0 || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over-budget read n=%d err=%v", n, err)
	}
	if err := waitClosed(stream); err != nil {
		t.Fatal(err)
	}

	reader = &memoryReadCloser{Reader: bytes.NewReader(nil)}
	writer = &memoryWriteCloser{}
	stream, err = New(reader, writer, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Write(payload[:oobcarrier.MaxApplicationBytes]); err != nil || n != oobcarrier.MaxApplicationBytes {
		t.Fatalf("within-budget write n=%d err=%v", n, err)
	}
	if n, err := stream.Write(payload[:1]); n != 0 || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over-budget write n=%d err=%v", n, err)
	}
	if err := waitClosed(stream); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDeadlineCannotBeExtendedAndExpiresRead(t *testing.T) {
	input, inputPeer := net.Pipe()
	outputPeer, output := net.Pipe()
	defer inputPeer.Close()
	defer outputPeer.Close()
	absolute := time.Now().Add(250 * time.Millisecond)
	stream, err := New(input, output, absolute)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(absolute.Add(time.Second)); !errors.Is(err, ErrDeadline) {
		t.Fatalf("deadline extension error=%v", err)
	}
	if err := stream.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrDeadline) {
		t.Fatalf("deadline read n=%d err=%v", n, err)
	}
	if !stream.Witness().Deadline {
		t.Fatal("deadline witness missing")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseUnblocksInflightReadAndWaitsForDrain(t *testing.T) {
	reader := newBlockingReadCloser()
	writer := &memoryWriteCloser{}
	stream, err := New(reader, writer, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); readDone <- err }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not drain")
	}
	if witness := stream.Witness(); !witness.Closed || !witness.Drained || !witness.EOF {
		t.Fatalf("witness=%+v", witness)
	}
}

func TestNewRejectsUnboundedPipeTypes(t *testing.T) {
	if stream, err := New(bytes.NewReader(nil), io.Discard, time.Now().Add(time.Second)); stream != nil || !errors.Is(err, ErrInvalidStream) {
		t.Fatalf("stream=%v err=%v", stream, err)
	}
}

func TestStreamDoesNotRequireNativePipeDeadlines(t *testing.T) {
	reader := newBlockingReadCloser()
	writer := &memoryWriteCloser{}
	stream, err := New(reader, writer, time.Now().Add(25*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrDeadline) {
		t.Fatalf("deadline read n=%d err=%v", n, err)
	}
	if err := waitClosed(stream); err != nil {
		t.Fatal(err)
	}
	if witness := stream.Witness(); !witness.Deadline || !witness.Drained || !witness.Closed {
		t.Fatalf("witness=%+v", witness)
	}
}

func waitClosed(stream *Stream) error {
	select {
	case <-stream.closed:
		return nil
	case <-time.After(time.Second):
		return errors.New("stream did not close")
	}
}

type memoryReadCloser struct {
	*bytes.Reader
	closed bool
}

func (reader *memoryReadCloser) SetDeadline(time.Time) error { return nil }
func (reader *memoryReadCloser) Close() error {
	reader.closed = true
	return nil
}

type memoryWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (writer *memoryWriteCloser) SetDeadline(time.Time) error { return nil }
func (writer *memoryWriteCloser) Close() error {
	writer.closed = true
	return nil
}

type blockingReadCloser struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{started: make(chan struct{}), closed: make(chan struct{})}
}

func (reader *blockingReadCloser) Read([]byte) (int, error) {
	reader.startOnce.Do(func() { close(reader.started) })
	<-reader.closed
	return 0, io.EOF
}

func (reader *blockingReadCloser) SetDeadline(time.Time) error { return nil }
func (reader *blockingReadCloser) Close() error {
	reader.closeOnce.Do(func() { close(reader.closed) })
	return nil
}
