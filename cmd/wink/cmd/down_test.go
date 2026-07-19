package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/processidentity"
)

func TestDownUsesAuthenticatedGracefulShutdown(t *testing.T) {
	processStartID, err := processidentity.Current()
	if err != nil {
		t.Fatalf("current process identity: %v", err)
	}
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	requestSeen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/shutdown" {
			http.NotFound(w, r)
			return
		}
		requestSeen <- r.Header.Get("X-Wink-Shutdown-Token")
		w.WriteHeader(http.StatusAccepted)
		go func() { _ = winkclient.RemoveRuntimeState(stateKey) }()
	}))
	defer server.Close()

	state := &winkclient.RuntimeState{
		InstanceID:      "instance-a",
		PID:             os.Getpid(),
		ProcessStartID:  processStartID,
		UpdatedAt:       time.Now(),
		ControlEndpoint: strings.TrimPrefix(server.URL, "http://"),
		ShutdownToken:   "test-token",
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	cmd := newDownCmd(&Options{ConfigPath: stateKey})
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--timeout", "2s"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("down execute: %v", err)
	}
	if token := <-requestSeen; token != "test-token" {
		t.Fatalf("shutdown token = %q, want test-token", token)
	}
	if !strings.Contains(output.String(), fmt.Sprintf("gracefully stopped pid=%d", os.Getpid())) {
		t.Fatalf("output = %q, want graceful stop", output.String())
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); !errors.Is(err, winkclient.ErrRuntimeStateNotFound) {
		t.Fatalf("runtime state after stop error = %v, want not found", err)
	}
}

func TestDownDoesNotForceAfterGracefulFailureByDefault(t *testing.T) {
	processStartID, err := processidentity.Current()
	if err != nil {
		t.Fatalf("current process identity: %v", err)
	}
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer server.Close()

	state := &winkclient.RuntimeState{
		InstanceID:      "instance-a",
		PID:             os.Getpid(),
		ProcessStartID:  processStartID,
		UpdatedAt:       time.Now(),
		ControlEndpoint: strings.TrimPrefix(server.URL, "http://"),
		ShutdownToken:   "wrong-token",
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	cmd := newDownCmd(&Options{ConfigPath: stateKey})
	cmd.SetArgs([]string{"--timeout", "1s"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "graceful stop failed") {
		t.Fatalf("down error = %v, want graceful failure", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("runtime state was removed after failed graceful stop: %v", err)
	}
}

func TestDownForceNeverFallsBackToPIDForManagedRuntime(t *testing.T) {
	processStartID, err := processidentity.Current()
	if err != nil {
		t.Fatalf("current process identity: %v", err)
	}
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer server.Close()
	state := &winkclient.RuntimeState{
		InstanceID:      "instance-a",
		PID:             os.Getpid(),
		ProcessStartID:  processStartID,
		UpdatedAt:       time.Now(),
		ControlEndpoint: strings.TrimPrefix(server.URL, "http://"),
		ShutdownToken:   "wrong-token",
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	cmd := newDownCmd(&Options{ConfigPath: stateKey})
	cmd.SetArgs([]string{"--timeout", "1s", "--force"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "never bypasses authenticated shutdown") {
		t.Fatalf("down --force error = %v, want managed no-fallback error", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("runtime state was removed after managed --force failure: %v", err)
	}
}

func TestDownRejectsReusedPIDIdentityBeforeHTTP(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	state := &winkclient.RuntimeState{
		InstanceID:      "instance-a",
		PID:             os.Getpid(),
		ProcessStartID:  "definitely-not-this-process",
		UpdatedAt:       time.Now(),
		ControlEndpoint: strings.TrimPrefix(server.URL, "http://"),
		ShutdownToken:   "test-token",
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	cmd := newDownCmd(&Options{ConfigPath: stateKey})
	cmd.SetArgs([]string{"--force"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no longer the recorded process instance") {
		t.Fatalf("down reused PID error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("shutdown HTTP requests = %d, want 0", requests.Load())
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("runtime state was removed after identity mismatch: %v", err)
	}
}

func TestWaitRuntimeStateRemovedRejectsReplacement(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	if err := winkclient.WriteRuntimeState(stateKey, &winkclient.RuntimeState{InstanceID: "instance-b"}); err != nil {
		t.Fatalf("write replacement state: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := waitRuntimeStateRemoved(ctx, stateKey, "instance-a")
	if err == nil || !strings.Contains(err.Error(), "replaced by instance") {
		t.Fatalf("wait replacement error = %v", err)
	}
}

func TestDownManagedStateWithoutEndpointNeverFallsBackToPID(t *testing.T) {
	processStartID, err := processidentity.Current()
	if err != nil {
		t.Fatalf("current process identity: %v", err)
	}
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	state := &winkclient.RuntimeState{
		InstanceID:     "instance-a",
		PID:            os.Getpid(),
		ProcessStartID: processStartID,
		UpdatedAt:      time.Now(),
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	cmd := newDownCmd(&Options{ConfigPath: stateKey})
	cmd.SetArgs([]string{"--force"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no control endpoint") {
		t.Fatalf("managed endpoint-less down error = %v", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("managed endpoint-less state was removed: %v", err)
	}
}

func TestDownLegacyRequiresForceAndRefusesCurrentPID(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	state := &winkclient.RuntimeState{PID: os.Getpid(), UpdatedAt: time.Now()}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	cmd := newDownCmd(&Options{ConfigPath: stateKey})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "retry with --force") {
		t.Fatalf("legacy down error = %v, want explicit force requirement", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("legacy state was removed without force: %v", err)
	}

	cmd = newDownCmd(&Options{ConfigPath: stateKey})
	cmd.SetArgs([]string{"--force"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "refusing to terminate the current") {
		t.Fatalf("legacy self-force error = %v", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("legacy state was removed after force failure: %v", err)
	}
}

func TestLoopbackControlURLRejectsExternalAddress(t *testing.T) {
	if _, err := loopbackControlURL("203.0.113.10:32110"); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("loopbackControlURL error = %v, want non-loopback rejection", err)
	}
	got, err := loopbackControlURL("[::1]:32110")
	if err != nil {
		t.Fatalf("loopbackControlURL IPv6: %v", err)
	}
	if got != "http://[::1]:32110" {
		t.Fatalf("loopbackControlURL = %q", got)
	}
}
