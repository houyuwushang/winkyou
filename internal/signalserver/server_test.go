package signalserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testCodeA = "alpha-code-000001"
	testCodeB = "wrong-code-000001"
)

func TestExchangeFlowAThenBAndOneTimeDeletion(t *testing.T) {
	server := newTestServer(t)
	first := postExchange(t, server, testCodeA, "a", `{"mapped":"192.0.2.10:40000"}`, "192.0.2.1:50000")
	assertStatusBody(t, first, http.StatusNoContent, "")

	second := postExchange(t, server, testCodeA, "b", `{"mapped":"198.51.100.20:41000"}`, "198.51.100.1:50001")
	assertPeerPayload(t, second, `{"mapped":"192.0.2.10:40000"}`)

	third := postExchange(t, server, testCodeA, "a", `{"mapped":"192.0.2.10:40000"}`, "192.0.2.1:50002")
	assertPeerPayload(t, third, `{"mapped":"198.51.100.20:41000"}`)
	stats := server.Snapshot()
	if stats.Stored != 2 || stats.Delivered != 2 || stats.Completed != 1 || stats.ActiveCodes != 0 {
		t.Fatalf("completed stats = %+v", stats)
	}

	// The consumed code has no retrievable residue. Reusing it starts a fresh
	// mailbox and receives the same 204 response as any other new code.
	again := postExchange(t, server, testCodeA, "a", `{"mapped":"192.0.2.10:40000"}`, "192.0.2.1:50003")
	assertStatusBody(t, again, http.StatusNoContent, "")
}

func TestExchangeFlowBThenA(t *testing.T) {
	server := newTestServer(t)
	assertStatusBody(t, postExchange(t, server, testCodeA, "b", `{"role":"b"}`, "192.0.2.2:50000"), http.StatusNoContent, "")
	assertPeerPayload(t, postExchange(t, server, testCodeA, "a", `{"role":"a"}`, "198.51.100.2:50000"), `{"role":"b"}`)
	assertPeerPayload(t, postExchange(t, server, testCodeA, "b", `{"role":"b"}`, "192.0.2.2:50001"), `{"role":"a"}`)
	if stats := server.Snapshot(); stats.Completed != 1 || stats.ActiveCodes != 0 {
		t.Fatalf("reverse flow stats = %+v", stats)
	}
}

func TestDuplicateRoleIsIdempotentAndCannotReplacePayload(t *testing.T) {
	server := newTestServer(t)
	assertStatusBody(t, postExchange(t, server, testCodeA, "a", `{"value":"original"}`, "192.0.2.3:50000"), http.StatusNoContent, "")
	assertStatusBody(t, postExchange(t, server, testCodeA, "a", `{"value":"replacement"}`, "192.0.2.3:50001"), http.StatusNoContent, "")
	peer := postExchange(t, server, testCodeA, "b", `{"value":"peer"}`, "198.51.100.3:50000")
	assertPeerPayload(t, peer, `{"value":"original"}`)
	if stats := server.Snapshot(); stats.Stored != 2 {
		t.Fatalf("duplicate stored payload: %+v", stats)
	}
}

func TestWrongCodeHasSamePendingResponseAndCannotEnumerate(t *testing.T) {
	server := newTestServer(t)
	known := postExchange(t, server, testCodeA, "a", `{"value":1}`, "192.0.2.4:50000")
	wrong := postExchange(t, server, testCodeB, "b", `{"value":2}`, "198.51.100.4:50000")
	if known.Code != wrong.Code || known.Body.String() != wrong.Body.String() || known.Header().Get("Content-Type") != wrong.Header().Get("Content-Type") {
		t.Fatalf("pending responses differ: known=%d/%q wrong=%d/%q", known.Code, known.Body.String(), wrong.Code, wrong.Body.String())
	}
	if stats := server.Snapshot(); stats.ActiveCodes != 2 {
		t.Fatalf("wrong code joined an existing mailbox: %+v", stats)
	}
}

func TestTTLExpiresBeforePeerSubmission(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	current := defaultSettings()
	current.now = clock.Now
	server, err := newServer(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")}, current)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	assertStatusBody(t, postExchange(t, server, testCodeA, "a", `{"value":1}`, "192.0.2.5:50000"), http.StatusNoContent, "")
	clock.Advance(MailboxTTL + time.Nanosecond)
	peer := postExchange(t, server, testCodeA, "b", `{"value":2}`, "198.51.100.5:50000")
	assertStatusBody(t, peer, http.StatusNoContent, "")
	if stats := server.Snapshot(); stats.Expired != 1 || stats.ActiveCodes != 1 || stats.Delivered != 0 {
		t.Fatalf("expiration stats = %+v", stats)
	}
}

func TestBodyCodeRoleAndPayloadValidation(t *testing.T) {
	server := newTestServer(t)
	tests := []struct {
		name        string
		body        string
		contentType string
		status      int
	}{
		{name: "short code", body: `{"code":"short","role":"a","payload":{"v":1}}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "invalid code character", body: `{"code":"UPPER-code-000001","role":"a","payload":{"v":1}}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "invalid role", body: `{"code":"alpha-code-000001","role":"c","payload":{"v":1}}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "null payload", body: `{"code":"alpha-code-000001","role":"a","payload":null}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "unknown field", body: `{"code":"alpha-code-000001","role":"a","payload":{"v":1},"extra":true}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "wrong content type", body: `{"code":"alpha-code-000001","role":"a","payload":{"v":1}}`, contentType: "text/plain", status: http.StatusUnsupportedMediaType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := postRaw(t, server, test.body, test.contentType, "192.0.2.6:50000")
			if result.Code != test.status || !strings.Contains(result.Body.String(), `"error":"invalid_request"`) {
				t.Fatalf("response = %d %q", result.Code, result.Body.String())
			}
		})
	}

	large := strings.Repeat("x", MaxBodyBytes)
	body, err := json.Marshal(exchangeRequest{Code: testCodeA, Role: "a", Payload: json.RawMessage(fmt.Sprintf("%q", large))})
	if err != nil {
		t.Fatalf("marshal large request: %v", err)
	}
	result := postRaw(t, server, string(body), "application/json", "192.0.2.7:50000")
	if result.Code != http.StatusRequestEntityTooLarge || !strings.Contains(result.Body.String(), "request_too_large") {
		t.Fatalf("large response = %d %q", result.Code, result.Body.String())
	}
}

func TestActiveCodeCapacityIsBounded(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	current := defaultSettings()
	current.now = clock.Now
	server, err := newServer(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")}, current)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	for index := 0; index < MaxActiveCodes; index++ {
		code := fmt.Sprintf("capacity-code-%04d", index)
		result := postExchange(t, server, code, "a", `{"value":1}`, "192.0.2.8:50000")
		assertStatusBody(t, result, http.StatusNoContent, "")
		clock.Advance(time.Second)
	}
	result := postExchange(t, server, "capacity-over-0001", "a", `{"value":1}`, "192.0.2.8:50001")
	assertStatusBody(t, result, http.StatusNoContent, "")
	if stats := server.Snapshot(); stats.ActiveCodes != MaxActiveCodes || stats.CapacityRejected != 1 {
		t.Fatalf("capacity stats = %+v", stats)
	}
}

func TestPerSourceRateLimitAndBoundedConcurrentExchange(t *testing.T) {
	t.Run("per-source", func(t *testing.T) {
		server := newTestServer(t)
		for index := 0; index < PerSourceMaxRPS; index++ {
			code := fmt.Sprintf("source-rate-%04d", index)
			assertStatusBody(t, postExchange(t, server, code, "a", `{"value":1}`, "192.0.2.9:50000"), http.StatusNoContent, "")
		}
		limited := postExchange(t, server, "source-rate-over", "a", `{"value":1}`, "192.0.2.9:50001")
		if limited.Code != http.StatusTooManyRequests || !strings.Contains(limited.Body.String(), "rate_limited") {
			t.Fatalf("rate response = %d %q", limited.Code, limited.Body.String())
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		current := defaultSettings()
		current.globalRate = 1024
		current.perSourceRate = 1024
		server, err := newServer(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")}, current)
		if err != nil {
			t.Fatalf("new server: %v", err)
		}
		var wait sync.WaitGroup
		for index := 0; index < 64; index++ {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				role := "a"
				if index%2 == 1 {
					role = "b"
				}
				result := postExchange(t, server, testCodeA, role, fmt.Sprintf(`{"value":%d}`, index), fmt.Sprintf("192.0.2.%d:50000", 20+index%20))
				if result.Code != http.StatusNoContent && result.Code != http.StatusOK {
					t.Errorf("concurrent response = %d %q", result.Code, result.Body.String())
				}
			}(index)
		}
		wait.Wait()
		if stats := server.Snapshot(); stats.ActiveCodes > 1 || stats.Completed == 0 {
			t.Fatalf("concurrent stats = %+v", stats)
		}
	})
}

func TestGlobalRateAndSourceTableAreBounded(t *testing.T) {
	t.Run("global", func(t *testing.T) {
		current := defaultSettings()
		current.globalRate = 2
		current.perSourceRate = 2
		server, err := newServer(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")}, current)
		if err != nil {
			t.Fatalf("new server: %v", err)
		}
		for index := 0; index < 2; index++ {
			result := postExchange(t, server, fmt.Sprintf("global-rate-%04d", index), "a", `{"value":1}`, fmt.Sprintf("192.0.2.%d:50000", 40+index))
			assertStatusBody(t, result, http.StatusNoContent, "")
		}
		limited := postExchange(t, server, "global-rate-over", "a", `{"value":1}`, "192.0.2.42:50000")
		if limited.Code != http.StatusTooManyRequests || !strings.Contains(limited.Body.String(), "rate_limited") {
			t.Fatalf("global rate response = %d %q", limited.Code, limited.Body.String())
		}
	})

	t.Run("source table", func(t *testing.T) {
		clock := &fakeClock{current: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
		current := defaultSettings()
		current.now = clock.Now
		current.globalRate = 1024
		current.perSourceRate = 1024
		current.maxSourceBuckets = 2
		server, err := newServer(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")}, current)
		if err != nil {
			t.Fatalf("new server: %v", err)
		}
		for index := 0; index < 2; index++ {
			result := postExchange(t, server, fmt.Sprintf("source-table-%04d", index), "a", `{"value":1}`, fmt.Sprintf("192.0.2.%d:50000", 50+index))
			assertStatusBody(t, result, http.StatusNoContent, "")
		}
		limited := postExchange(t, server, "source-table-over", "a", `{"value":1}`, "192.0.2.52:50000")
		if limited.Code != http.StatusTooManyRequests {
			t.Fatalf("source table response = %d %q", limited.Code, limited.Body.String())
		}

		clock.Advance(SourceIdleLimit + time.Nanosecond)
		recovered := postExchange(t, server, "source-table-new", "a", `{"value":1}`, "192.0.2.53:50000")
		assertStatusBody(t, recovered, http.StatusNoContent, "")
	})
}

func TestNoRedirectStaticSurfaceOrClientAddressInStats(t *testing.T) {
	server := newTestServer(t)
	for _, request := range []struct {
		method string
		path   string
		status int
	}{
		{method: http.MethodGet, path: ExchangePath, status: http.StatusMethodNotAllowed},
		{method: http.MethodPost, path: ExchangePath + "/", status: http.StatusNotFound},
		{method: http.MethodGet, path: "/", status: http.StatusNotFound},
	} {
		req := httptest.NewRequest(request.method, "http://signal.invalid"+request.path, nil)
		req.RemoteAddr = "192.0.2.10:50000"
		result := httptest.NewRecorder()
		server.ServeHTTP(result, req)
		if result.Code != request.status || result.Header().Get("Location") != "" {
			t.Fatalf("%s %s = %d location=%q", request.method, request.path, result.Code, result.Header().Get("Location"))
		}
	}
	encoded, err := json.Marshal(server.Snapshot())
	if err != nil {
		t.Fatalf("marshal stats: %v", err)
	}
	if strings.Contains(string(encoded), "192.0.2.10") {
		t.Fatalf("aggregate stats contain the client address: %s", encoded)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	for _, forbidden := range []string{"client_ip", "source_ip", "code", "payload"} {
		if _, found := fields[forbidden]; found {
			t.Fatalf("aggregate stats contain forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestOpenServesLoopbackAndShutsDownWithContext(t *testing.T) {
	server, err := Open(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatalf("open server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	url := "http://" + server.ListenAddr().String() + ExchangePath
	body := `{"code":"alpha-code-000001","role":"a","payload":{"value":1}}`
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("post loopback: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("loopback status = %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := New(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func postExchange(t *testing.T, server *Server, code, role, payload, remote string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"code":%q,"role":%q,"payload":%s}`, code, role, payload)
	return postRaw(t, server, body, "application/json", remote)
}

func postRaw(t *testing.T, server *Server, body, contentType, remote string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://signal.invalid"+ExchangePath, strings.NewReader(body))
	request.RemoteAddr = remote
	request.Header.Set("Content-Type", contentType)
	result := httptest.NewRecorder()
	server.ServeHTTP(result, request)
	return result
}

func assertStatusBody(t *testing.T, result *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if result.Code != status || result.Body.String() != body {
		t.Fatalf("response = %d %q, want %d %q", result.Code, result.Body.String(), status, body)
	}
	if result.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q", result.Header().Get("Cache-Control"))
	}
}

func assertPeerPayload(t *testing.T, result *httptest.ResponseRecorder, want string) {
	t.Helper()
	if result.Code != http.StatusOK {
		t.Fatalf("peer response = %d %q", result.Code, result.Body.String())
	}
	var decoded exchangeResponse
	if err := json.Unmarshal(result.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode peer response: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(decoded.Payload), bytes.TrimSpace([]byte(want))) {
		t.Fatalf("peer payload = %s, want %s", decoded.Payload, want)
	}
}

type fakeClock struct {
	mu      sync.Mutex
	current time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.current
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.current = clock.current.Add(duration)
	clock.mu.Unlock()
}
