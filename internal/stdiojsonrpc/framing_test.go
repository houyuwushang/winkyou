package stdiojsonrpc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameReaderSupportsStickyFrames(t *testing.T) {
	input := append(testFrame(`{"one":1}`), testFrame(`{"two":2}`)...)
	reader, err := NewFrameReader(bytes.NewReader(input), 256, 1024)
	if err != nil {
		t.Fatalf("new frame reader: %v", err)
	}
	first, err := reader.ReadFrame()
	if err != nil || string(first) != `{"one":1}` {
		t.Fatalf("first frame = %q, %v", first, err)
	}
	second, err := reader.ReadFrame()
	if err != nil || string(second) != `{"two":2}` {
		t.Fatalf("second frame = %q, %v", second, err)
	}
	if _, err := reader.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal read error = %v, want EOF", err)
	}
}

func TestFrameReaderRejectsBoundaryViolations(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxBody   int
		class     string
		unwrapEOF bool
	}{
		{name: "zero length", input: "Content-Length: 0\r\n\r\n", maxBody: 16, class: ClassInvalidRequest},
		{name: "oversized", input: "Content-Length: 17\r\n\r\n", maxBody: 16, class: ClassRequestTooLarge},
		{name: "half body", input: "Content-Length: 4\r\n\r\n{}", maxBody: 16, class: ClassInvalidRequest, unwrapEOF: true},
		{name: "half header", input: "Content-Length: 4\r\n", maxBody: 16, class: ClassInvalidRequest, unwrapEOF: true},
		{name: "LF header", input: "Content-Length: 2\n\n{}", maxBody: 16, class: ClassInvalidRequest},
		{name: "unknown header", input: "X-Test: 2\r\n\r\n{}", maxBody: 16, class: ClassInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, err := NewFrameReader(strings.NewReader(test.input), 128, test.maxBody)
			if err != nil {
				t.Fatalf("new reader: %v", err)
			}
			_, err = reader.ReadFrame()
			var framing *FramingError
			if !errors.As(err, &framing) || framing.Class != test.class {
				t.Fatalf("framing error = %#v, want class %q", err, test.class)
			}
			if test.unwrapEOF && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("framing error = %v, want unexpected EOF", err)
			}
		})
	}
}

func TestFrameWriterHandlesPartialWrites(t *testing.T) {
	output := &oneByteWriter{}
	writer, err := NewFrameWriter(output, 32)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	if err := writer.WriteFrame([]byte(`{}`)); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if got, want := output.String(), "Content-Length: 2\r\n\r\n{}"; got != want {
		t.Fatalf("framed output = %q, want %q", got, want)
	}
}

type oneByteWriter struct {
	buffer bytes.Buffer
}

func (writer *oneByteWriter) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	return writer.buffer.Write(payload[:1])
}

func (writer *oneByteWriter) String() string {
	return writer.buffer.String()
}

func testFrame(payload string) []byte {
	return []byte("Content-Length: " + intString(len(payload)) + "\r\n\r\n" + payload)
}

func intString(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = digits[value%10]
		value /= 10
	}
	return string(buffer[position:])
}
