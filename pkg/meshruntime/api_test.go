package meshruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestShutdownRouteRequiresConfiguredTokenAndLoopbackCaller(t *testing.T) {
	withoutToken, err := New(Config{NodeID: "no-shutdown", MeshListen: "off", ControlListen: "off"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/shutdown", nil)
	request.RemoteAddr = "127.0.0.1:50000"
	response := httptest.NewRecorder()
	withoutToken.controlMux().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("shutdown without configured token status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if err := withoutToken.Close(); err != nil {
		t.Fatal(err)
	}

	const token = "process-specific-token"
	runtime, err := New(Config{NodeID: "authorized-shutdown", MeshListen: "off", ControlListen: "off"}, Options{ShutdownToken: token})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		remoteAddr string
		token      string
	}{
		{name: "non-loopback", remoteAddr: "192.0.2.10:50000", token: token},
		{name: "wrong token", remoteAddr: "127.0.0.1:50000", token: "wrong"},
		{name: "missing token", remoteAddr: "[::1]:50000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/shutdown", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set(ShutdownTokenHeader, test.token)
			response := httptest.NewRecorder()
			runtime.controlMux().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
			}
			select {
			case <-runtime.Done():
				t.Fatal("unauthorized shutdown closed runtime")
			default:
			}
		})
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/shutdown", nil)
	request.RemoteAddr = "127.0.0.1:50000"
	request.Header.Set(ShutdownTokenHeader, token)
	response = httptest.NewRecorder()
	runtime.controlMux().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("authorized shutdown status = %d, want %d", response.Code, http.StatusAccepted)
	}
	select {
	case <-runtime.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("authorized shutdown did not close runtime")
	}
}

func TestStatusExposesShutdownMetadataOnlyInProcess(t *testing.T) {
	const token = "do-not-serialize-this-token"
	runtime, err := New(Config{NodeID: "status-shutdown", MeshListen: "off", ControlListen: "off"}, Options{ShutdownToken: token})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	status := runtime.Status()
	if status.ShutdownToken != token {
		t.Fatalf("shutdown token = %q, want configured token", status.ShutdownToken)
	}
	payload, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), token) || strings.Contains(string(payload), "shutdown_token") {
		t.Fatalf("HTTP status JSON leaked shutdown token: %s", payload)
	}
}

func TestDecodeJSONRequiresExactlyOneValue(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "single value", body: `{"target":"127.0.0.1:22"}`},
		{name: "trailing whitespace", body: "{\"target\":\"127.0.0.1:22\"}\n\t  "},
		{name: "second object", body: `{"target":"127.0.0.1:22"} {"target":"127.0.0.1:23"}`, wantErr: true},
		{name: "second scalar", body: `{"target":"127.0.0.1:22"} true`, wantErr: true},
		{name: "trailing non JSON", body: `{"target":"127.0.0.1:22"} trailing`, wantErr: true},
		{name: "unknown field", body: `{"target":"127.0.0.1:22","extra":true}`, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/v1/tcp/target", strings.NewReader(test.body))
			var body tcpTargetRequest
			err := decodeJSON(request, &body)
			if test.wantErr && err == nil {
				t.Fatal("decodeJSON() error = nil")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("decodeJSON() error = %v", err)
			}
		})
	}
}

func TestTCPAPIErrorStatus(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "not found", err: fmt.Errorf("wrapped: %w", ErrTCPForwardNotFound), status: http.StatusNotFound},
		{name: "immutable", err: fmt.Errorf("wrapped: %w", ErrTCPConfigImmutable), status: http.StatusConflict},
		{name: "listener conflict", err: fmt.Errorf("wrapped: %w", ErrTCPForwardConflict), status: http.StatusConflict},
		{name: "listener limit", err: fmt.Errorf("wrapped: %w", ErrTCPForwardLimit), status: http.StatusConflict},
		{name: "not started", err: fmt.Errorf("wrapped: %w", ErrTCPRuntimeNotStarted), status: http.StatusServiceUnavailable},
		{name: "closed", err: fmt.Errorf("wrapped: %w", ErrTCPRuntimeClosed), status: http.StatusServiceUnavailable},
		{name: "unexpected", err: errors.New("unexpected failure"), status: http.StatusInternalServerError},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpAPIErrorStatus(test.err); got != test.status {
				t.Fatalf("tcpAPIErrorStatus(%v) = %d, want %d", test.err, got, test.status)
			}
		})
	}
}

func TestTCPAPIEndpointStatusCodes(t *testing.T) {
	type fixture func(*testing.T) (*meshRuntime, string)
	tests := []struct {
		name    string
		method  string
		path    string
		fixture fixture
		status  int
	}{
		{
			name: "target invalid is bad request", method: http.MethodPut, path: "/v1/tcp/target",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{NodeID: "A"}, `{"target":"192.0.2.1:22"}`),
			status:  http.StatusBadRequest,
		},
		{
			name: "target second JSON value is bad request", method: http.MethodPut, path: "/v1/tcp/target",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{NodeID: "A"}, `{"target":"127.0.0.1:22"} {}`),
			status:  http.StatusBadRequest,
		},
		{
			name: "configured target is immutable", method: http.MethodPut, path: "/v1/tcp/target",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{NodeID: "A", TCPTarget: "127.0.0.1:22"}, `{"target":"127.0.0.1:23"}`),
			status:  http.StatusConflict,
		},
		{
			name: "configured target cannot be cleared", method: http.MethodDelete, path: "/v1/tcp/target",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{NodeID: "A", TCPTarget: "127.0.0.1:22"}, ""),
			status:  http.StatusConflict,
		},
		{
			name: "target runtime not started", method: http.MethodPut, path: "/v1/tcp/target",
			fixture: tcpAPIFixture(tcpAPINotStarted, runtimeConfig{NodeID: "A"}, `{"target":"127.0.0.1:22"}`),
			status:  http.StatusServiceUnavailable,
		},
		{
			name: "target runtime closed", method: http.MethodDelete, path: "/v1/tcp/target",
			fixture: tcpAPIFixture(tcpAPIClosed, runtimeConfig{NodeID: "A"}, ""),
			status:  http.StatusServiceUnavailable,
		},
		{
			name: "target unexpected failure", method: http.MethodPut, path: "/v1/tcp/target",
			fixture: func(t *testing.T) (*meshRuntime, string) {
				runtime := newTCPAPIRuntime(t, tcpAPIStarted, runtimeConfig{NodeID: "A"})
				if err := runtime.tcp.forwarder.Close(); err != nil {
					t.Fatal(err)
				}
				return runtime, `{"target":"127.0.0.1:22"}`
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "forward invalid is bad request", method: http.MethodPost, path: "/v1/tcp/forwards",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{NodeID: "A"}, `{"listen":"0.0.0.0:22025","remote_id":"B"}`),
			status:  http.StatusBadRequest,
		},
		{
			name: "configured forward is immutable", method: http.MethodDelete, path: "/v1/tcp/forwards/config-001",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{
				NodeID: "A", tcpForwardSpecs: []tcpForwardSpec{{Listen: "127.0.0.1:0", RemoteID: "B"}},
			}, ""),
			status: http.StatusConflict,
		},
		{
			name: "forward conflict", method: http.MethodPost, path: "/v1/tcp/forwards",
			fixture: func(t *testing.T) (*meshRuntime, string) {
				runtime := newTCPAPIRuntime(t, tcpAPIStarted, runtimeConfig{NodeID: "A"})
				view, err := runtime.tcp.AddForward("127.0.0.1:0", "B", tcpForwardSourceRuntime)
				if err != nil {
					t.Fatal(err)
				}
				return runtime, fmt.Sprintf(`{"listen":%q,"remote_id":"C"}`, view.Listen)
			},
			status: http.StatusConflict,
		},
		{
			name: "forward runtime not started", method: http.MethodPost, path: "/v1/tcp/forwards",
			fixture: tcpAPIFixture(tcpAPINotStarted, runtimeConfig{NodeID: "A"}, `{"listen":"127.0.0.1:22025","remote_id":"B"}`),
			status:  http.StatusServiceUnavailable,
		},
		{
			name: "forward runtime closed", method: http.MethodDelete, path: "/v1/tcp/forwards/runtime-001",
			fixture: tcpAPIFixture(tcpAPIClosed, runtimeConfig{NodeID: "A"}, ""),
			status:  http.StatusServiceUnavailable,
		},
		{
			name: "forward missing", method: http.MethodDelete, path: "/v1/tcp/forwards/runtime-999",
			fixture: tcpAPIFixture(tcpAPIStarted, runtimeConfig{NodeID: "A"}, ""),
			status:  http.StatusNotFound,
		},
		{
			name: "forward unexpected failure", method: http.MethodPost, path: "/v1/tcp/forwards",
			fixture: func(t *testing.T) (*meshRuntime, string) {
				runtime := newTCPAPIRuntime(t, tcpAPIStarted, runtimeConfig{NodeID: "A"})
				if err := runtime.tcp.forwarder.Close(); err != nil {
					t.Fatal(err)
				}
				return runtime, `{"listen":"127.0.0.1:0","remote_id":"B"}`
			},
			status: http.StatusInternalServerError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, body := test.fixture(t)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(body))
			response := httptest.NewRecorder()
			runtime.controlMux().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

type tcpAPIState int

const (
	tcpAPINotStarted tcpAPIState = iota
	tcpAPIStarted
	tcpAPIClosed
)

func tcpAPIFixture(state tcpAPIState, config runtimeConfig, body string) func(*testing.T) (*meshRuntime, string) {
	return func(t *testing.T) (*meshRuntime, string) {
		return newTCPAPIRuntime(t, state, config), body
	}
}

func newTCPAPIRuntime(t *testing.T, state tcpAPIState, config runtimeConfig) *meshRuntime {
	t.Helper()
	tcp := newTCPTestRuntime(t, config)
	if state != tcpAPINotStarted {
		if err := tcp.Start(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if state == tcpAPIClosed {
		if err := tcp.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return &meshRuntime{cfg: config, tcp: tcp}
}
