package gatecchildstream

import (
	"errors"
	"io"
	"sync"
	"time"

	"winkyou/internal/v2/oobcarrier"
)

const DrainTimeout = 2 * time.Second

var (
	ErrInvalidStream  = errors.New("gatecchildstream: invalid bounded stream")
	ErrBudgetExceeded = errors.New("gatecchildstream: byte budget exceeded")
	ErrDeadline       = errors.New("gatecchildstream: deadline reached")
	ErrClosed         = errors.New("gatecchildstream: stream closed")
	ErrDrain          = errors.New("gatecchildstream: stream drain failed")
)

type Witness struct {
	BytesRead    int  `json:"bytes_read"`
	BytesWritten int  `json:"bytes_written"`
	Deadline     bool `json:"deadline"`
	EOF          bool `json:"eof"`
	Drained      bool `json:"drained"`
	Closed       bool `json:"closed"`
}

// Stream owns exactly one input pipe and one output pipe. rendezvouswire and
// oobcarrier retain the authoritative eight-frame validation; this adapter
// independently enforces the same 8,256-byte per-direction ceiling.
type Stream struct {
	reader io.ReadCloser
	writer io.WriteCloser

	mu               sync.Mutex
	readMu           sync.Mutex
	writeMu          sync.Mutex
	ops              sync.WaitGroup
	absoluteDeadline time.Time
	deadline         time.Time
	deadlineTimer    *time.Timer
	closing          bool
	witness          Witness
	closed           chan struct{}
	closeOnce        sync.Once
	closeErr         error
}

func New(input io.Reader, output io.Writer, absoluteDeadline time.Time) (*Stream, error) {
	reader, readOK := input.(io.ReadCloser)
	writer, writeOK := output.(io.WriteCloser)
	if !readOK || !writeOK || reader == nil || writer == nil || absoluteDeadline.IsZero() || !absoluteDeadline.After(time.Now()) {
		return nil, ErrInvalidStream
	}
	stream := &Stream{
		reader: reader, writer: writer, absoluteDeadline: absoluteDeadline, deadline: absoluteDeadline,
		closed: make(chan struct{}),
	}
	if err := stream.SetDeadline(absoluteDeadline); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

func (stream *Stream) Read(buffer []byte) (int, error) {
	if stream == nil {
		return 0, ErrClosed
	}
	stream.readMu.Lock()
	defer stream.readMu.Unlock()
	if !stream.beginOperation() {
		return 0, ErrClosed
	}
	defer stream.ops.Done()
	stream.mu.Lock()
	remaining := oobcarrier.MaxApplicationBytes - stream.witness.BytesRead
	stream.mu.Unlock()
	if remaining <= 0 && len(buffer) > 0 {
		go func() { _ = stream.Close() }()
		return 0, ErrBudgetExceeded
	}
	if len(buffer) > remaining {
		buffer = buffer[:remaining]
	}
	n, err := stream.reader.Read(buffer)
	stream.mu.Lock()
	stream.witness.BytesRead += n
	if errors.Is(err, io.EOF) {
		stream.witness.EOF = true
	}
	if deadlineExpired(stream.deadline, err) {
		stream.witness.Deadline = true
		err = ErrDeadline
	} else if stream.witness.Deadline {
		err = ErrDeadline
	}
	stream.mu.Unlock()
	return n, err
}

func (stream *Stream) Write(payload []byte) (int, error) {
	if stream == nil {
		return 0, ErrClosed
	}
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()
	if !stream.beginOperation() {
		return 0, ErrClosed
	}
	defer stream.ops.Done()
	stream.mu.Lock()
	if stream.witness.BytesWritten+len(payload) > oobcarrier.MaxApplicationBytes {
		stream.mu.Unlock()
		go func() { _ = stream.Close() }()
		return 0, ErrBudgetExceeded
	}
	stream.mu.Unlock()
	n, err := stream.writer.Write(payload)
	stream.mu.Lock()
	stream.witness.BytesWritten += n
	if deadlineExpired(stream.deadline, err) {
		stream.witness.Deadline = true
		err = ErrDeadline
	} else if stream.witness.Deadline {
		err = ErrDeadline
	}
	stream.mu.Unlock()
	return n, err
}

func (stream *Stream) SetDeadline(deadline time.Time) error {
	if stream == nil || deadline.IsZero() {
		return ErrInvalidStream
	}
	stream.mu.Lock()
	if stream.closing || deadline.After(stream.absoluteDeadline) || !deadline.After(time.Now()) {
		stream.mu.Unlock()
		return ErrDeadline
	}
	stream.deadline = deadline
	if stream.deadlineTimer != nil {
		stream.deadlineTimer.Stop()
	}
	stream.deadlineTimer = time.AfterFunc(time.Until(deadline), func() {
		stream.mu.Lock()
		if stream.closing || !stream.deadline.Equal(deadline) {
			stream.mu.Unlock()
			return
		}
		stream.witness.Deadline = true
		stream.mu.Unlock()
		_ = stream.Close()
	})
	stream.mu.Unlock()
	return nil
}

func (stream *Stream) Close() error {
	if stream == nil {
		return nil
	}
	stream.closeOnce.Do(func() {
		stream.mu.Lock()
		stream.closing = true
		if stream.deadlineTimer != nil {
			stream.deadlineTimer.Stop()
		}
		stream.mu.Unlock()
		readErr := stream.reader.Close()
		writeErr := stream.writer.Close()
		drained := make(chan struct{})
		go func() {
			stream.ops.Wait()
			close(drained)
		}()
		timer := time.NewTimer(DrainTimeout)
		defer timer.Stop()
		select {
		case <-drained:
			stream.mu.Lock()
			stream.witness.Drained = true
			stream.closeErr = errors.Join(readErr, writeErr)
			stream.mu.Unlock()
		case <-timer.C:
			stream.mu.Lock()
			stream.closeErr = ErrDrain
			stream.mu.Unlock()
		}
		stream.mu.Lock()
		stream.witness.Closed = true
		stream.mu.Unlock()
		close(stream.closed)
	})
	<-stream.closed
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.closeErr
}

func (stream *Stream) Witness() Witness {
	if stream == nil {
		return Witness{Closed: true, Drained: true}
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.witness
}

func (stream *Stream) beginOperation() bool {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closing {
		return false
	}
	stream.ops.Add(1)
	return true
}

func deadlineExpired(deadline time.Time, err error) bool {
	if err == nil || deadline.IsZero() {
		return false
	}
	type timeoutError interface{ Timeout() bool }
	var timeout timeoutError
	return !time.Now().Before(deadline) || errors.As(err, &timeout) && timeout.Timeout()
}

var _ oobcarrier.BoundedStream = (*Stream)(nil)
