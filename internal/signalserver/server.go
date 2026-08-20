package signalserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ExchangePath = "/v1/exchange"

	MailboxTTL       = 120 * time.Second
	MaxActiveCodes   = 64
	MaxBodyBytes     = 4 * 1024
	MinCodeLength    = 16
	MaxCodeLength    = 64
	GlobalMaxRPS     = 64
	PerSourceMaxRPS  = 8
	MaxSourceBuckets = 4096
	SourceIdleLimit  = 5 * time.Minute

	ReadHeaderTimeout = 2 * time.Second
	ReadTimeout       = 5 * time.Second
	WriteTimeout      = 5 * time.Second
	IdleTimeout       = 10 * time.Second
	ShutdownTimeout   = 5 * time.Second
)

var (
	ErrInvalidConfig = errors.New("signalserver: invalid configuration")
	ErrAlreadyServed = errors.New("signalserver: Serve may be called only once")
)

type Config struct {
	ListenAddr netip.AddrPort
}

type Stats struct {
	Requests         uint64 `json:"requests"`
	Stored           uint64 `json:"stored"`
	Delivered        uint64 `json:"delivered"`
	Completed        uint64 `json:"completed"`
	Expired          uint64 `json:"expired"`
	Invalid          uint64 `json:"invalid"`
	RateLimited      uint64 `json:"rate_limited"`
	CapacityRejected uint64 `json:"capacity_rejected"`
	ActiveCodes      int    `json:"active_codes"`
}

type settings struct {
	ttl              time.Duration
	maxActiveCodes   int
	maxBodyBytes     int64
	globalRate       int
	perSourceRate    int
	maxSourceBuckets int
	sourceIdleLimit  time.Duration
	now              func() time.Time
}

func defaultSettings() settings {
	return settings{
		ttl:              MailboxTTL,
		maxActiveCodes:   MaxActiveCodes,
		maxBodyBytes:     MaxBodyBytes,
		globalRate:       GlobalMaxRPS,
		perSourceRate:    PerSourceMaxRPS,
		maxSourceBuckets: MaxSourceBuckets,
		sourceIdleLimit:  SourceIdleLimit,
		now:              time.Now,
	}
}

type mailboxSlot struct {
	payload   []byte
	submitted bool
	retrieved bool
}

type mailbox struct {
	digest    [sha256.Size]byte
	expiresAt time.Time
	slots     [2]mailboxSlot
}

type Server struct {
	listener   net.Listener
	listenAddr netip.AddrPort
	httpServer *http.Server
	settings   settings

	mu        sync.Mutex
	mailboxes []mailbox
	admission *admissionController
	stats     Stats

	served    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// New constructs the bounded handler without opening a listener. It is useful
// for httptest and does not grant a network capability.
func New(config Config) (*Server, error) {
	return newServer(config, defaultSettings())
}

func newServer(config Config, current settings) (*Server, error) {
	address, err := normalizeListenAddr(config.ListenAddr)
	if err != nil {
		return nil, err
	}
	if current.ttl <= 0 || current.maxActiveCodes <= 0 || current.maxBodyBytes <= 0 || current.globalRate <= 0 || current.perSourceRate <= 0 || current.maxSourceBuckets <= 0 || current.sourceIdleLimit <= 0 || current.now == nil {
		return nil, fmt.Errorf("%w: invalid resource settings", ErrInvalidConfig)
	}
	now := current.now()
	server := &Server{
		listenAddr: address,
		settings:   current,
		mailboxes:  make([]mailbox, 0, current.maxActiveCodes),
		admission:  newAdmissionController(current.globalRate, current.perSourceRate, current.maxSourceBuckets, current.sourceIdleLimit, now),
	}
	server.httpServer = &http.Server{
		Addr:              address.String(),
		Handler:           server,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    8 * 1024,
		// net/http's default logger includes the remote address for some
		// protocol and panic paths. This test-only exchange keeps application
		// logs aggregate-only, so framework diagnostics are deliberately
		// suppressed rather than risking a client-address leak.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return server, nil
}

// Open creates the single TCP listener owned by cmd/wink-signal.
func Open(config Config) (*Server, error) {
	server, err := New(config)
	if err != nil {
		return nil, err
	}
	network := "tcp6"
	if server.listenAddr.Addr().Is4() {
		network = "tcp4"
	}
	listener, err := net.Listen(network, server.listenAddr.String())
	if err != nil {
		return nil, fmt.Errorf("signalserver: listen: %w", err)
	}
	actual, err := tcpAddrPort(listener.Addr())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	server.listener = listener
	server.listenAddr = actual
	server.httpServer.Addr = actual.String()
	return server, nil
}

func normalizeListenAddr(address netip.AddrPort) (netip.AddrPort, error) {
	if !address.IsValid() || address.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("%w: literal IPv4 or bracketed IPv6 listen address is required", ErrInvalidConfig)
	}
	value := address.Addr().Unmap()
	if !(value.IsUnspecified() || value.IsLoopback() || value.IsGlobalUnicast()) {
		return netip.AddrPort{}, fmt.Errorf("%w: listen address must be unicast, loopback, or unspecified", ErrInvalidConfig)
	}
	return netip.AddrPortFrom(value, address.Port()), nil
}

func tcpAddrPort(address net.Addr) (netip.AddrPort, error) {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil {
		return netip.AddrPort{}, fmt.Errorf("%w: TCP listener returned an unexpected address", ErrInvalidConfig)
	}
	endpoint := tcpAddress.AddrPort()
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: TCP listener returned an invalid endpoint", ErrInvalidConfig)
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), nil
}

func (server *Server) ListenAddr() netip.AddrPort {
	if server == nil {
		return netip.AddrPort{}
	}
	return server.listenAddr
}

func (server *Server) Serve(ctx context.Context) error {
	if server == nil || server.listener == nil || server.httpServer == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if !server.served.CompareAndSwap(false, true) {
		return ErrAlreadyServed
	}
	serveDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
			defer cancel()
			_ = server.httpServer.Shutdown(shutdownCtx)
		case <-serveDone:
		}
	}()
	err := server.httpServer.Serve(server.listener)
	close(serveDone)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		if server.httpServer != nil {
			server.closeErr = server.httpServer.Close()
		} else if server.listener != nil {
			server.closeErr = server.listener.Close()
		}
		if errors.Is(server.closeErr, http.ErrServerClosed) || errors.Is(server.closeErr, net.ErrClosed) {
			server.closeErr = nil
		}
	})
	return server.closeErr
}

func (server *Server) Snapshot() Stats {
	if server == nil {
		return Stats{}
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	server.removeExpiredLocked(server.settings.now())
	result := server.stats
	result.ActiveCodes = len(server.mailboxes)
	return result
}

type exchangeRequest struct {
	Code    string          `json:"code"`
	Role    string          `json:"role"`
	Payload json.RawMessage `json:"payload"`
}

type exchangeResponse struct {
	Payload json.RawMessage `json:"payload"`
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setResponseHeaders(response.Header())
	source, err := requestSource(request.RemoteAddr)
	if err != nil {
		server.recordInvalid()
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	now := server.settings.now()
	server.mu.Lock()
	server.stats.Requests++
	admission := server.admission.allow(source, now)
	if admission != admissionAllowed {
		server.stats.RateLimited++
		server.mu.Unlock()
		writeAPIError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	server.mu.Unlock()
	if request.URL.Path != ExchangePath || request.URL.RawQuery != "" {
		server.recordInvalid()
		http.NotFound(response, request)
		return
	}
	if request.Method != http.MethodPost {
		server.recordInvalid()
		response.Header().Set("Allow", http.MethodPost)
		writeAPIError(response, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	if mediaType, _, parseErr := mime.ParseMediaType(request.Header.Get("Content-Type")); parseErr != nil || mediaType != "application/json" {
		server.recordInvalid()
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, server.settings.maxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input exchangeRequest
	if err := decoder.Decode(&input); err != nil {
		server.recordInvalid()
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeAPIError(response, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		server.recordInvalid()
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	role, valid := validateExchangeRequest(input)
	if !valid {
		server.recordInvalid()
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}

	payload, status := server.exchange(input.Code, role, input.Payload, now)
	switch status {
	case http.StatusNoContent:
		response.WriteHeader(status)
	case http.StatusOK:
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(status)
		_ = json.NewEncoder(response).Encode(exchangeResponse{Payload: payload})
	default:
		writeAPIError(response, http.StatusInternalServerError, "internal_error")
	}
}

func validateExchangeRequest(input exchangeRequest) (int, bool) {
	if len(input.Code) < MinCodeLength || len(input.Code) > MaxCodeLength {
		return 0, false
	}
	for _, current := range []byte(input.Code) {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return 0, false
		}
	}
	role := 0
	if input.Role == "b" {
		role = 1
	} else if input.Role != "a" {
		return 0, false
	}
	trimmed := bytes.TrimSpace(input.Payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || !json.Valid(trimmed) {
		return 0, false
	}
	return role, true
}

func (server *Server) exchange(code string, role int, payload []byte, now time.Time) (json.RawMessage, int) {
	digest := sha256.Sum256([]byte(code))
	server.mu.Lock()
	defer server.mu.Unlock()
	server.removeExpiredLocked(now)
	index := server.findMailboxLocked(digest)
	if index < 0 {
		if len(server.mailboxes) >= server.settings.maxActiveCodes {
			// Do not reveal whether a submitted code already exists when the
			// bounded mailbox table is full. A new code is dropped behind the
			// same pending response used for every unpaired submission.
			server.stats.CapacityRejected++
			return nil, http.StatusNoContent
		}
		entry := mailbox{digest: digest, expiresAt: now.Add(server.settings.ttl)}
		entry.slots[role] = mailboxSlot{payload: append([]byte(nil), payload...), submitted: true}
		server.mailboxes = append(server.mailboxes, entry)
		server.stats.Stored++
		return nil, http.StatusNoContent
	}

	entry := &server.mailboxes[index]
	own := &entry.slots[role]
	peer := &entry.slots[1-role]
	if !own.submitted {
		own.payload = append([]byte(nil), payload...)
		own.submitted = true
		server.stats.Stored++
	}
	if !peer.submitted || own.retrieved {
		return nil, http.StatusNoContent
	}
	result := append(json.RawMessage(nil), peer.payload...)
	own.retrieved = true
	server.stats.Delivered++
	if entry.slots[0].retrieved && entry.slots[1].retrieved {
		server.clearAndRemoveMailboxLocked(index)
		server.stats.Completed++
	}
	return result, http.StatusOK
}

func (server *Server) findMailboxLocked(digest [sha256.Size]byte) int {
	index := -1
	for current := range server.mailboxes {
		if subtle.ConstantTimeCompare(server.mailboxes[current].digest[:], digest[:]) == 1 {
			index = current
		}
	}
	return index
}

func (server *Server) removeExpiredLocked(now time.Time) {
	for index := len(server.mailboxes) - 1; index >= 0; index-- {
		if now.Before(server.mailboxes[index].expiresAt) {
			continue
		}
		server.clearAndRemoveMailboxLocked(index)
		server.stats.Expired++
	}
}

func (server *Server) clearAndRemoveMailboxLocked(index int) {
	entry := &server.mailboxes[index]
	for slot := range entry.slots {
		clear(entry.slots[slot].payload)
		entry.slots[slot].payload = nil
	}
	copy(server.mailboxes[index:], server.mailboxes[index+1:])
	last := len(server.mailboxes) - 1
	server.mailboxes[last] = mailbox{}
	server.mailboxes = server.mailboxes[:last]
}

func requestSource(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, err
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, ErrInvalidConfig
	}
	return address, nil
}

func (server *Server) recordInvalid() {
	server.mu.Lock()
	server.stats.Invalid++
	server.mu.Unlock()
}

func setResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
}

func writeAPIError(response http.ResponseWriter, status int, class string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = fmt.Fprintf(response, "{\"error\":%q}\n", class)
}
