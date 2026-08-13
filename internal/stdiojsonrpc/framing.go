package stdiojsonrpc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const ContentLengthHeader = "Content-Length"

type FramingError struct {
	Class  string
	Detail string
	Limit  int64
	Err    error
}

func (e *FramingError) Error() string {
	if e == nil {
		return "stdio framing error"
	}
	if e.Detail != "" {
		return e.Detail
	}
	return "stdio framing error"
}

func (e *FramingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type FrameReader struct {
	reader         *bufio.Reader
	maxHeaderBytes int
	maxBodyBytes   int
}

func NewFrameReader(input io.Reader, maxHeaderBytes, maxBodyBytes int) (*FrameReader, error) {
	if input == nil {
		return nil, errors.New("stdio frame input is nil")
	}
	if maxHeaderBytes < 64 || maxBodyBytes <= 0 {
		return nil, errors.New("stdio frame limits are invalid")
	}
	return &FrameReader{
		reader:         bufio.NewReaderSize(input, maxHeaderBytes),
		maxHeaderBytes: maxHeaderBytes,
		maxBodyBytes:   maxBodyBytes,
	}, nil
}

func (reader *FrameReader) ReadFrame() ([]byte, error) {
	if reader == nil || reader.reader == nil {
		return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame reader is unavailable"}
	}
	totalHeaderBytes := 0
	contentLength := -1
	for {
		line, err := reader.reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame header exceeds the hard limit", Limit: int64(reader.maxHeaderBytes), Err: err}
		}
		if errors.Is(err, io.EOF) && len(line) == 0 && totalHeaderBytes == 0 {
			return nil, io.EOF
		}
		if err != nil {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame header is incomplete", Err: io.ErrUnexpectedEOF}
		}
		totalHeaderBytes += len(line)
		if totalHeaderBytes > reader.maxHeaderBytes {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame header exceeds the hard limit", Limit: int64(reader.maxHeaderBytes)}
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame headers require CRLF line endings"}
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
		name, value, ok := strings.Cut(string(line[:len(line)-2]), ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), ContentLengthHeader) {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame contains an unsupported header"}
		}
		if contentLength >= 0 {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame contains duplicate Content-Length headers"}
		}
		parsed, parseErr := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
		if parseErr != nil || parsed <= 0 {
			return nil, &FramingError{Class: ClassInvalidRequest, Detail: "Content-Length must be a positive decimal integer", Err: parseErr}
		}
		if parsed > int64(reader.maxBodyBytes) {
			return nil, &FramingError{Class: ClassRequestTooLarge, Detail: "request body exceeds the hard limit", Limit: int64(reader.maxBodyBytes)}
		}
		contentLength = int(parsed)
	}
	if contentLength < 0 {
		return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame is missing Content-Length"}
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader.reader, body); err != nil {
		return nil, &FramingError{Class: ClassInvalidRequest, Detail: "stdio frame body is incomplete", Err: io.ErrUnexpectedEOF}
	}
	return body, nil
}

type FrameWriter struct {
	output       io.Writer
	maxBodyBytes int
}

func NewFrameWriter(output io.Writer, maxBodyBytes int) (*FrameWriter, error) {
	if output == nil {
		return nil, errors.New("stdio frame output is nil")
	}
	if maxBodyBytes <= 0 {
		return nil, errors.New("stdio response limit is invalid")
	}
	return &FrameWriter{output: output, maxBodyBytes: maxBodyBytes}, nil
}

func (writer *FrameWriter) WriteFrame(payload []byte) error {
	if writer == nil || writer.output == nil {
		return errors.New("stdio frame writer is unavailable")
	}
	if len(payload) == 0 {
		return errors.New("stdio response body is empty")
	}
	if len(payload) > writer.maxBodyBytes {
		return fmt.Errorf("stdio response body exceeds %d bytes", writer.maxBodyBytes)
	}
	header := []byte(fmt.Sprintf("%s: %d\r\n\r\n", ContentLengthHeader, len(payload)))
	if err := writeAll(writer.output, header); err != nil {
		return err
	}
	return writeAll(writer.output, payload)
}

func writeAll(output io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := output.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
