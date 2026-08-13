package stdiojsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestServerConcurrencyLimitIsImmediateAndExplainable(t *testing.T) {
	limits := testLimits()
	limits.MaxConcurrent = 1
	input := append(
		testFrame(`{"jsonrpc":"2.0","id":"first","method":"wait","params":{}}`),
		testFrame(`{"jsonrpc":"2.0","id":"second","method":"wait","params":{}}`)...,
	)
	handler := HandlerFunc(func(ctx context.Context, _ Request, _ ProgressReporter) (any, *RPCError) {
		<-ctx.Done()
		return nil, nil
	})
	var output bytes.Buffer
	server := mustServer(t, bytes.NewReader(input), &output, handler, limits, nil)
	if err := server.Run(context.Background()); err != nil {
		t.Fatalf("run server: %v", err)
	}
	frames := decodeOutputFrames(t, output.Bytes())
	assertErrorClass(t, frames, "second", ClassConcurrencyLimit)
	assertErrorClass(t, frames, "first", ClassCancelled)
}

func TestServerCancelPropagatesAndProgressBindsOriginalID(t *testing.T) {
	limits := testLimits()
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	started := make(chan struct{})
	handler := HandlerFunc(func(ctx context.Context, _ Request, progress ProgressReporter) (any, *RPCError) {
		if err := progress.Report("waiting", true); err != nil {
			return nil, NewRPCError(CodeInternalError, ClassInternalError, "progress failed", false)
		}
		close(started)
		<-ctx.Done()
		return nil, nil
	})
	server := mustServer(t, inputReader, outputWriter, handler, limits, nil)
	runDone := make(chan error, 1)
	go func() { runDone <- server.Run(context.Background()) }()
	frames := asyncFrames(outputReader, limits.MaxResponseBytes)
	writeTestFrame(t, inputWriter, `{"jsonrpc":"2.0","id":"work-1","method":"wait","params":{}}`)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	writeTestFrame(t, inputWriter, `{"jsonrpc":"2.0","id":"cancel-1","method":"cancel","params":{"request_id":"work-1"}}`)

	seenProgress := false
	seenCancelResult := false
	seenCancelled := false
	deadline := time.After(2 * time.Second)
	for !(seenProgress && seenCancelResult && seenCancelled) {
		select {
		case frame := <-frames:
			if frame.Method == ProgressNotificationMethod {
				var progress Progress
				if err := json.Unmarshal(frame.Params, &progress); err != nil {
					t.Fatalf("decode progress: %v", err)
				}
				seenProgress = string(progress.RequestID) == `"work-1"` && progress.Stage == "waiting" && progress.Cancellable
			}
			if frame.ID == "cancel-1" && frame.Result != nil {
				var result struct {
					Cancelled bool `json:"cancelled"`
				}
				if err := json.Unmarshal(frame.Result, &result); err != nil {
					t.Fatalf("decode cancel result: %v", err)
				}
				seenCancelResult = result.Cancelled
			}
			if frame.ID == "work-1" && frame.Error != nil && frame.Error.Data.Class == ClassCancelled {
				seenCancelled = true
			}
		case <-deadline:
			t.Fatalf("frames incomplete: progress=%t cancel=%t cancelled=%t", seenProgress, seenCancelResult, seenCancelled)
		}
	}
	_ = inputWriter.Close()
	if err := <-runDone; err != nil {
		t.Fatalf("run server: %v", err)
	}
	_ = outputWriter.Close()
}

func TestServerEOFAndParentCancellationCancelInFlightWork(t *testing.T) {
	for _, test := range []struct {
		name   string
		finish func(context.CancelFunc, *io.PipeWriter)
	}{
		{name: "stdin EOF", finish: func(_ context.CancelFunc, writer *io.PipeWriter) { _ = writer.Close() }},
		{name: "parent cancellation", finish: func(cancel context.CancelFunc, _ *io.PipeWriter) { cancel() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputReader, inputWriter := io.Pipe()
			started := make(chan struct{})
			cancelled := make(chan struct{})
			handler := HandlerFunc(func(ctx context.Context, _ Request, _ ProgressReporter) (any, *RPCError) {
				close(started)
				<-ctx.Done()
				close(cancelled)
				return nil, nil
			})
			server := mustServer(t, inputReader, io.Discard, handler, testLimits(), nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runDone := make(chan error, 1)
			go func() { runDone <- server.Run(ctx) }()
			writeTestFrame(t, inputWriter, `{"jsonrpc":"2.0","id":1,"method":"wait","params":{}}`)
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("handler did not start")
			}
			test.finish(cancel, inputWriter)
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("in-flight handler was not cancelled")
			}
			select {
			case err := <-runDone:
				if err != nil {
					t.Fatalf("run server: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not stop")
			}
			_ = inputWriter.Close()
		})
	}
}

func TestServerDeadlineAndRateLimitsUseStableClasses(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		inputReader, inputWriter := io.Pipe()
		outputReader, outputWriter := io.Pipe()
		handler := HandlerFunc(func(ctx context.Context, _ Request, _ ProgressReporter) (any, *RPCError) {
			<-ctx.Done()
			return nil, nil
		})
		selector := func(Request) (time.Duration, *RPCError) { return 10 * time.Millisecond, nil }
		server := mustServer(t, inputReader, outputWriter, handler, testLimits(), selector)
		runDone := make(chan error, 1)
		go func() { runDone <- server.Run(context.Background()) }()
		frames := asyncFrames(outputReader, testLimits().MaxResponseBytes)
		writeTestFrame(t, inputWriter, `{"jsonrpc":"2.0","id":"deadline","method":"wait","params":{}}`)
		select {
		case frame := <-frames:
			if frame.Error == nil || frame.Error.Data.Class != ClassDeadlineExceeded {
				t.Fatalf("deadline frame = %+v", frame)
			}
		case <-time.After(time.Second):
			t.Fatal("deadline response timed out")
		}
		_ = inputWriter.Close()
		if err := <-runDone; err != nil {
			t.Fatalf("run server: %v", err)
		}
		_ = outputWriter.Close()
	})

	t.Run("rate", func(t *testing.T) {
		limits := testLimits()
		limits.RequestsPerSecond = 1
		limits.RateBurst = 1
		input := append(
			testFrame(`{"jsonrpc":"2.0","id":"one","method":"read","params":{}}`),
			testFrame(`{"jsonrpc":"2.0","id":"two","method":"read","params":{}}`)...,
		)
		handler := HandlerFunc(func(context.Context, Request, ProgressReporter) (any, *RPCError) {
			return map[string]bool{"ok": true}, nil
		})
		var output bytes.Buffer
		server := mustServer(t, bytes.NewReader(input), &output, handler, limits, nil)
		if err := server.Run(context.Background()); err != nil {
			t.Fatalf("run server: %v", err)
		}
		assertErrorClass(t, decodeOutputFrames(t, output.Bytes()), "two", ClassRateLimited)
	})
}

func TestServerOversizedFrameReturnsStableErrorBeforeStopping(t *testing.T) {
	limits := testLimits()
	limits.MaxRequestBytes = 16
	input := bytes.NewBufferString("Content-Length: 17\r\n\r\n")
	var output bytes.Buffer
	server := mustServer(t, input, &output, HandlerFunc(func(context.Context, Request, ProgressReporter) (any, *RPCError) {
		t.Fatal("oversized request reached handler")
		return nil, nil
	}), limits, nil)
	if err := server.Run(context.Background()); err == nil {
		t.Fatal("oversized frame did not stop the server")
	}
	frames := decodeOutputFrames(t, output.Bytes())
	if len(frames) != 1 || frames[0].ID != "" || frames[0].Error == nil || frames[0].Error.Data.Class != ClassRequestTooLarge {
		t.Fatalf("oversized response = %+v", frames)
	}
}

type decodedFrame struct {
	ID     string
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  *RPCError
}

func decodeOutputFrames(t *testing.T, payload []byte) []decodedFrame {
	t.Helper()
	reader, err := NewFrameReader(bytes.NewReader(payload), 1024, 1<<20)
	if err != nil {
		t.Fatalf("new output reader: %v", err)
	}
	var frames []decodedFrame
	for {
		body, err := reader.ReadFrame()
		if err == io.EOF {
			return frames
		}
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		frames = append(frames, decodeFrame(t, body))
	}
}

func decodeFrame(t *testing.T, body []byte) decodedFrame {
	t.Helper()
	var wire struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("decode output frame %q: %v", body, err)
	}
	id := ""
	if len(wire.ID) > 0 && string(wire.ID) != "null" {
		if wire.ID[0] == '"' {
			if err := json.Unmarshal(wire.ID, &id); err != nil {
				t.Fatalf("decode string id: %v", err)
			}
		} else {
			id = string(wire.ID)
		}
	}
	return decodedFrame{ID: id, Method: wire.Method, Params: wire.Params, Result: wire.Result, Error: wire.Error}
}

func asyncFrames(input io.Reader, maxBody int) <-chan decodedFrame {
	frames := make(chan decodedFrame, 16)
	go func() {
		reader, err := NewFrameReader(input, 1024, maxBody)
		if err != nil {
			return
		}
		for {
			body, err := reader.ReadFrame()
			if err != nil {
				return
			}
			var wire struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
				Result json.RawMessage `json:"result"`
				Error  *RPCError       `json:"error"`
			}
			if json.Unmarshal(body, &wire) != nil {
				return
			}
			id := ""
			if len(wire.ID) > 0 && string(wire.ID) != "null" {
				if wire.ID[0] == '"' {
					_ = json.Unmarshal(wire.ID, &id)
				} else {
					id = string(wire.ID)
				}
			}
			frames <- decodedFrame{ID: id, Method: wire.Method, Params: wire.Params, Result: wire.Result, Error: wire.Error}
		}
	}()
	return frames
}

func assertErrorClass(t *testing.T, frames []decodedFrame, id, class string) {
	t.Helper()
	for _, frame := range frames {
		if frame.ID == id {
			if frame.Error == nil || frame.Error.Data.Class != class {
				t.Fatalf("frame %q = %+v, want error class %q", id, frame, class)
			}
			return
		}
	}
	t.Fatalf("response %q not found in %+v", id, frames)
}

func mustServer(t *testing.T, input io.Reader, output io.Writer, handler Handler, limits Limits, selector DeadlineSelector) *Server {
	t.Helper()
	server, err := NewServer(input, output, handler, limits, selector)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func writeTestFrame(t *testing.T, output io.Writer, payload string) {
	t.Helper()
	if _, err := output.Write(testFrame(payload)); err != nil {
		t.Fatalf("write input frame: %v", err)
	}
}

func testLimits() Limits {
	limits := DefaultLimits()
	limits.DefaultDeadline = 250 * time.Millisecond
	limits.MaxDeadline = time.Second
	limits.ShutdownTimeout = time.Second
	return limits
}
