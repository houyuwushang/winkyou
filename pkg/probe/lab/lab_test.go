package lab

import (
	"context"
	"net"
	"testing"
	"time"

	"winkyou/pkg/probe/model"
)

func TestRunnerRunMinimalScript(t *testing.T) {
	addr, cleanup := startUDPReceiver(t)
	defer cleanup()

	script := model.Script{
		PlanID: "lab/demo",
		Steps: []model.Step{
			{Type: model.StepUDPSend, Addr: addr, Payload: "hello"},
			{Type: model.StepSleep, DurationMS: 10},
			{Type: model.StepReport, Event: "script_completed"},
		},
	}

	result, err := (Runner{}).Run(context.Background(), script)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Success {
		t.Fatalf("Run() success = false, want true: %+v", result)
	}
	if result.PlanID != "lab/demo" {
		t.Fatalf("PlanID = %q, want lab/demo", result.PlanID)
	}
	if len(result.Events) != 3 {
		t.Fatalf("Events len = %d, want 3", len(result.Events))
	}
	if result.Events[0].Event != model.StepUDPSend || result.Events[2].Event != "script_completed" {
		t.Fatalf("Events = %+v, want udp_send ... script_completed", result.Events)
	}
	if result.FinishedAt.IsZero() {
		t.Fatal("FinishedAt should be set")
	}
}

func TestRunnerRunTCPCheck(t *testing.T) {
	addr := startTCPResponder(t, "ping", "pong")
	script := model.Script{
		PlanID: "lab/tcp-check",
		Steps: []model.Step{
			{Type: model.StepTCPCheck, Addr: addr, Message: "ping", Expect: "pong"},
		},
	}

	result, err := (Runner{}).Run(context.Background(), script)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Success || len(result.Events) != 1 || result.Events[0].Event != model.StepTCPCheck {
		t.Fatalf("Run() result = %+v, want successful tcp_check event", result)
	}
}

func startUDPReceiver(t *testing.T) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr() error = %v", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		_, _, _ = conn.ReadFromUDP(buf)
	}()
	return conn.LocalAddr().String(), func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func startTCPResponder(t *testing.T, request, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) != request {
			return
		}
		_, _ = conn.Write([]byte(reply))
	}()
	return ln.Addr().String()
}
