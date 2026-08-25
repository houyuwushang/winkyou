package solverstdio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
)

func TestServeHandshakeGolden(t *testing.T) {
	authority := &fakeAuthority{
		info: governor.OwnerInfo{
			PID:          4242,
			InstanceID:   "00000000000000000000000000000001",
			StartedAt:    time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC),
			BuildVersion: "v1.2.3",
			Scope:        governor.ScopeMachine,
		},
		status: clearTrip(),
	}
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	dependencies := testDependencies(authority)
	runDone := make(chan error, 1)
	go func() {
		runDone <- serveWithDependencies(context.Background(), inputReader, outputWriter, Options{}, dependencies)
	}()
	request := `{"jsonrpc":"2.0","id":"handshake-1","method":"handshake","params":{"schema_version":"winkyou.stdio/v1","framing_version":"lsp-content-length/v1"}}`
	writeServeFrame(t, inputWriter, request)
	reader, err := stdiojsonrpc.NewFrameReader(outputReader, dependencies.Limits.MaxHeaderBytes, dependencies.Limits.MaxResponseBytes)
	if err != nil {
		t.Fatalf("new response reader: %v", err)
	}
	body, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, body, "", "  "); err != nil {
		t.Fatalf("format handshake: %v", err)
	}
	formatted.WriteByte('\n')
	want, err := os.ReadFile("testdata/handshake.golden.json")
	if err != nil {
		t.Fatalf("read handshake golden: %v\ngot:\n%s", err, formatted.Bytes())
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(formatted.Bytes(), want) {
		t.Fatalf("handshake changed\ngot:\n%s\nwant:\n%s", formatted.Bytes(), want)
	}
	_ = inputWriter.Close()
	if err := <-runDone; err != nil {
		t.Fatalf("serve: %v", err)
	}
	_ = outputWriter.Close()
	if !authority.closed {
		t.Fatal("authority was not released after stdin EOF")
	}
}

func TestServeHandshakeV2Golden(t *testing.T) {
	authority := &fakeAuthority{
		info: governor.OwnerInfo{
			PID:          4242,
			InstanceID:   "00000000000000000000000000000001",
			StartedAt:    time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC),
			BuildVersion: "v1.2.3",
			Scope:        governor.ScopeMachine,
		},
		status: clearTrip(),
	}
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	dependencies := testDependencies(authority)
	runDone := make(chan error, 1)
	go func() {
		runDone <- serveWithDependencies(context.Background(), inputReader, outputWriter, Options{}, dependencies)
	}()
	request := `{"jsonrpc":"2.0","id":"handshake-v2","method":"handshake","params":{"schema_version":"winkyou.stdio/v2","framing_version":"lsp-content-length/v1"}}`
	writeServeFrame(t, inputWriter, request)
	reader, err := stdiojsonrpc.NewFrameReader(outputReader, dependencies.Limits.MaxHeaderBytes, dependencies.Limits.MaxResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, err := reader.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, body, "", "  "); err != nil {
		t.Fatal(err)
	}
	formatted.WriteByte('\n')
	want, err := os.ReadFile("testdata/handshake-v2.golden.json")
	if err != nil {
		t.Fatalf("read v2 handshake golden: %v\ngot:\n%s", err, formatted.Bytes())
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(formatted.Bytes(), want) {
		t.Fatalf("v2 handshake changed\ngot:\n%s\nwant:\n%s", formatted.Bytes(), want)
	}
	_ = inputWriter.Close()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	_ = outputWriter.Close()
}

func TestServePipelinedHandshakeOrdersBeforeLaterRequests(t *testing.T) {
	// Both frames arrive in one write with stdin closing immediately after.
	// The handshake must complete before the pipelined status request is
	// dispatched, and EOF must drain the in-flight status to success.
	for attempt := 0; attempt < 20; attempt++ {
		authority := &fakeAuthority{status: clearTrip()}
		input := bytes.NewBuffer(nil)
		input.Write(serveFrame(`{"jsonrpc":"2.0","id":1,"method":"handshake","params":{"schema_version":"winkyou.stdio/v1","framing_version":"lsp-content-length/v1"}}`))
		input.Write(serveFrame(`{"jsonrpc":"2.0","id":2,"method":"status","params":{}}`))
		var output bytes.Buffer
		if err := serveWithDependencies(context.Background(), input, &output, Options{}, testDependencies(authority)); err != nil {
			t.Fatalf("serve: %v", err)
		}
		reader, err := stdiojsonrpc.NewFrameReader(bytes.NewReader(output.Bytes()), 1024, 1<<20)
		if err != nil {
			t.Fatalf("new response reader: %v", err)
		}
		responses := make(map[string]json.RawMessage)
		for {
			body, readErr := reader.ReadFrame()
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				t.Fatalf("read response: %v", readErr)
			}
			var envelope struct {
				ID     json.RawMessage `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(envelope.ID) != 0 && string(envelope.ID) != "null" {
				if len(envelope.Error) != 0 {
					t.Fatalf("attempt %d: request %s failed: %s", attempt, envelope.ID, envelope.Error)
				}
				responses[string(envelope.ID)] = envelope.Result
			}
		}
		if len(responses["1"]) == 0 || len(responses["2"]) == 0 {
			t.Fatalf("attempt %d: missing pipelined responses: %v", attempt, responses)
		}
	}
}

func serveFrame(payload string) []byte {
	return []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(payload), payload))
}

func TestServeFailsClosedWithOwnerPID(t *testing.T) {
	held := &governor.OwnerHeldError{Owner: governor.OwnerInfo{
		PID:          4242,
		InstanceID:   "00000000000000000000000000000002",
		StartedAt:    time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC),
		BuildVersion: "holder-build",
		Scope:        governor.ScopeMachine,
	}}
	dependencies := testDependencies(&fakeAuthority{})
	dependencies.Acquire = func(string) (authority, error) { return nil, held }
	err := serveWithDependencies(context.Background(), bytes.NewReader(nil), io.Discard, Options{}, dependencies)
	if err == nil || !strings.Contains(err.Error(), ClassGovernorLockUnavailable) || !strings.Contains(err.Error(), "pid 4242") {
		t.Fatalf("lock failure = %v", err)
	}
}

func TestServeReleasesAuthorityOnImmediateEOF(t *testing.T) {
	authority := &fakeAuthority{status: clearTrip()}
	if err := serveWithDependencies(context.Background(), bytes.NewReader(nil), io.Discard, Options{}, testDependencies(authority)); err != nil {
		t.Fatalf("serve EOF: %v", err)
	}
	if !authority.closed {
		t.Fatal("authority remained held after server exit")
	}
}

func TestServeMultiProcessLockFailsClosedWithoutBudgetMultiplication(t *testing.T) {
	namespace := t.TempDir()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "parent-build")
	if err != nil {
		t.Fatalf("acquire parent owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	command := exec.Command(os.Args[0], "-test.run=^TestStdioLockContenderHelper$")
	command.Env = append(os.Environ(), "WINKYOU_STDIO_LOCK_TEST_NAMESPACE="+namespace)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("contender unexpectedly acquired machine lock: %s", output)
	}
	text := string(output)
	if !strings.Contains(text, ClassGovernorLockUnavailable) || !strings.Contains(text, "pid "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("contender output = %q", text)
	}
}

func TestStdioLockContenderHelper(t *testing.T) {
	namespace := os.Getenv("WINKYOU_STDIO_LOCK_TEST_NAMESPACE")
	if namespace == "" {
		return
	}
	dependencies := testDependencies(&fakeAuthority{})
	dependencies.Acquire = func(build string) (authority, error) {
		return governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, build)
	}
	err := serveWithDependencies(context.Background(), bytes.NewReader(nil), io.Discard, Options{}, dependencies)
	if err == nil {
		fmt.Fprintln(os.Stderr, "contender unexpectedly acquired lock")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(23)
}

func testDependencies(authorityValue authority) dependencies {
	limits := stdiojsonrpc.DefaultLimits()
	return dependencies{
		Acquire: func(string) (authority, error) { return authorityValue, nil },
		Diagnose: staticDiagnose{report: passivediagnose.Report{
			SchemaVersion:          passivediagnose.SchemaVersion,
			GeneratedAt:            time.Date(2026, 8, 13, 4, 5, 6, 0, time.UTC),
			GovernorScope:          governor.ScopeMachine,
			NetworkActivityStarted: false,
		}},
		WriteReport: passivediagnose.WriteRedactedReport,
		Build: BuildInfo{
			Version:   "v1.2.3",
			Commit:    "0123456789abcdef",
			BuildTime: "2026-08-13T00:00:00Z",
			GoVersion: "go1.test",
		},
		Limits: limits,
	}
}

func writeServeFrame(t *testing.T, output io.Writer, payload string) {
	t.Helper()
	frame := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(payload), payload))
	if _, err := output.Write(frame); err != nil {
		t.Fatalf("write request frame: %v", err)
	}
}
