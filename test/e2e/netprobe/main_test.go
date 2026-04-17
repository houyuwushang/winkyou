package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winkyou/pkg/probe/model"
)

func TestRunTCPCommands(t *testing.T) {
	addr := freeTCPAddr(t)
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"tcp-serve", "--listen", addr, "--expect", "ping", "--reply", "pong", "--timeout", "2s"}, nil)
	}()
	time.Sleep(50 * time.Millisecond)
	if err := run([]string{"tcp-check", "--addr", addr, "--message", "ping", "--expect", "pong", "--timeout", "2s"}, nil); err != nil {
		t.Fatalf("tcp-check error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("tcp-serve error = %v", err)
	}
}

func TestRunUDPCommands(t *testing.T) {
	addr := freeUDPAddr(t)
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"udp-serve", "--listen", addr, "--expect", "ping", "--reply", "pong", "--timeout", "2s"}, nil)
	}()
	time.Sleep(50 * time.Millisecond)
	if err := run([]string{"udp-check", "--addr", addr, "--message", "ping", "--expect", "pong", "--timeout", "2s"}, nil); err != nil {
		t.Fatalf("udp-check error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("udp-serve error = %v", err)
	}
}

func TestRunScriptOutputsStructuredResult(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "script.json")
	if err := os.WriteFile(scriptPath, []byte(`{"plan_id":"lab/demo","steps":[{"type":"report","event":"script_completed"}]}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var out bytes.Buffer
	if err := run([]string{"script-run", "--script", scriptPath}, &out); err != nil {
		t.Fatalf("script-run error = %v", err)
	}

	var result model.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v\noutput=%s", err, out.String())
	}
	if !result.Success || result.PlanID != "lab/demo" {
		t.Fatalf("script result = %+v, want successful lab/demo result", result)
	}
	if len(result.Events) != 1 || result.Events[0].Event != "script_completed" {
		t.Fatalf("script events = %+v, want script_completed", result.Events)
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr() error = %v", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}
