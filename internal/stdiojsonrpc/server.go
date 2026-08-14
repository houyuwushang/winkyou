package stdiojsonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	CancelMethod               = "cancel"
	ProgressNotificationMethod = "winkyou/progress"
)

type Limits struct {
	MaxHeaderBytes    int
	MaxRequestBytes   int
	MaxResponseBytes  int
	MaxConcurrent     int
	RequestsPerSecond int
	RateBurst         int
	DefaultDeadline   time.Duration
	MaxDeadline       time.Duration
	ShutdownTimeout   time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxHeaderBytes:    1024,
		MaxRequestBytes:   64 << 10,
		MaxResponseBytes:  1 << 20,
		MaxConcurrent:     4,
		RequestsPerSecond: 20,
		RateBurst:         20,
		DefaultDeadline:   5 * time.Second,
		MaxDeadline:       30 * time.Second,
		ShutdownTimeout:   2 * time.Second,
	}
}

func (limits Limits) Validate() error {
	if limits.MaxHeaderBytes < 64 || limits.MaxRequestBytes <= 0 || limits.MaxResponseBytes <= 0 {
		return errors.New("stdio byte limits must be positive")
	}
	if limits.MaxConcurrent <= 0 || limits.RequestsPerSecond <= 0 || limits.RateBurst <= 0 {
		return errors.New("stdio admission limits must be positive")
	}
	if limits.DefaultDeadline <= 0 || limits.MaxDeadline < limits.DefaultDeadline || limits.ShutdownTimeout <= 0 {
		return errors.New("stdio deadline limits are invalid")
	}
	return nil
}

type Handler interface {
	Handle(context.Context, Request, ProgressReporter) (any, *RPCError)
}

type HandlerFunc func(context.Context, Request, ProgressReporter) (any, *RPCError)

func (function HandlerFunc) Handle(ctx context.Context, request Request, progress ProgressReporter) (any, *RPCError) {
	return function(ctx, request, progress)
}

type DeadlineSelector func(Request) (time.Duration, *RPCError)

type ProgressReporter interface {
	Report(stage string, cancellable bool) error
}

type Progress struct {
	RequestID         json.RawMessage `json:"request_id"`
	Stage             string          `json:"stage"`
	RemainingBudgetMS int64           `json:"remaining_budget_ms"`
	Cancellable       bool            `json:"cancellable"`
}

type Server struct {
	reader           *FrameReader
	writer           *FrameWriter
	handler          Handler
	deadlineSelector DeadlineSelector
	limits           Limits
	synchronous      map[string]struct{}
	writeMu          sync.Mutex
	inflightMu       sync.Mutex
	inflight         map[string]*inflightRequest
	semaphore        chan struct{}
	rate             *tokenBucket
	wait             sync.WaitGroup
}

type inflightRequest struct {
	id       ID
	cancel   context.CancelFunc
	deadline time.Time
	active   atomic.Bool
}

func NewServer(input io.Reader, output io.Writer, handler Handler, limits Limits, selector DeadlineSelector) (*Server, error) {
	if handler == nil {
		return nil, errors.New("stdio JSON-RPC handler is nil")
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	reader, err := NewFrameReader(input, limits.MaxHeaderBytes, limits.MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	writer, err := NewFrameWriter(output, limits.MaxResponseBytes)
	if err != nil {
		return nil, err
	}
	return &Server{
		reader:           reader,
		writer:           writer,
		handler:          handler,
		deadlineSelector: selector,
		limits:           limits,
		synchronous:      make(map[string]struct{}),
		inflight:         make(map[string]*inflightRequest),
		semaphore:        make(chan struct{}, limits.MaxConcurrent),
		rate:             newTokenBucket(limits.RequestsPerSecond, limits.RateBurst),
	}, nil
}

// MarkSynchronousMethod makes the named method execute inline in the dispatch
// loop, so its completion is ordered before any later pipelined request is
// started. It must be called before Run and is intended for fast,
// ordering-critical methods such as a protocol handshake.
func (server *Server) MarkSynchronousMethod(method string) {
	if server == nil || strings.TrimSpace(method) == "" {
		return
	}
	server.synchronous[method] = struct{}{}
}

func (server *Server) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type frameResult struct {
		payload []byte
		err     error
	}
	frames := make(chan frameResult)
	go func() {
		for {
			payload, err := server.reader.ReadFrame()
			select {
			case frames <- frameResult{payload: payload, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		var payload []byte
		var err error
		select {
		case <-ctx.Done():
			return server.shutdown(true)
		case frame := <-frames:
			payload, err = frame.payload, frame.err
		}
		if errors.Is(err, io.EOF) {
			// EOF means the client finished sending requests, not that it
			// stopped wanting responses. Drain in-flight work instead of
			// cancelling it; cancellation stays reserved for explicit cancel,
			// deadlines, context shutdown, and fatal transport errors.
			return server.shutdown(false)
		}
		if err != nil {
			server.writeFramingError(err)
			cancel()
			return errors.Join(err, server.shutdown(true))
		}
		request, rpcErr := ParseRequest(payload)
		if rpcErr != nil {
			if err := server.writeError(nil, rpcErr); err != nil {
				cancel()
				return errors.Join(err, server.shutdown(true))
			}
			continue
		}
		if request.Method == CancelMethod {
			if err := server.handleCancel(request); err != nil {
				cancel()
				return errors.Join(err, server.shutdown(true))
			}
			continue
		}
		if retryAfter, allowed := server.rate.Allow(time.Now()); !allowed {
			rpcErr := NewRPCError(CodeRateLimited, ClassRateLimited, "request rate exceeds the process hard limit", true)
			rpcErr.Data.Limit = int64(server.limits.RequestsPerSecond)
			rpcErr.Data.RetryAfterMS = maxInt64(1, retryAfter.Milliseconds())
			if err := server.writeError(request.ID.Raw(), rpcErr); err != nil {
				cancel()
				return errors.Join(err, server.shutdown(true))
			}
			continue
		}
		select {
		case server.semaphore <- struct{}{}:
		default:
			rpcErr := NewRPCError(CodeConcurrencyLimit, ClassConcurrencyLimit, "request concurrency exceeds the process hard limit", true)
			rpcErr.Data.Limit = int64(server.limits.MaxConcurrent)
			if err := server.writeError(request.ID.Raw(), rpcErr); err != nil {
				cancel()
				return errors.Join(err, server.shutdown(true))
			}
			continue
		}
		if rpcErr := server.start(ctx, request, server.isSynchronous(request.Method)); rpcErr != nil {
			<-server.semaphore
			if err := server.writeError(request.ID.Raw(), rpcErr); err != nil {
				cancel()
				return errors.Join(err, server.shutdown(true))
			}
		}
	}
}

func (server *Server) isSynchronous(method string) bool {
	_, synchronous := server.synchronous[method]
	return synchronous
}

func (server *Server) start(parent context.Context, request Request, inline bool) *RPCError {
	duration := server.limits.DefaultDeadline
	if server.deadlineSelector != nil {
		selected, rpcErr := server.deadlineSelector(request)
		if rpcErr != nil {
			return rpcErr
		}
		if selected > 0 {
			duration = selected
		}
	}
	if duration <= 0 || duration > server.limits.MaxDeadline {
		rpcErr := NewRPCError(CodeInvalidParams, ClassInvalidParams, "deadline_ms exceeds the protocol hard limit", false)
		rpcErr.Data.Limit = server.limits.MaxDeadline.Milliseconds()
		return rpcErr
	}
	requestCtx, cancel := context.WithTimeout(parent, duration)
	inflight := &inflightRequest{id: request.ID, cancel: cancel, deadline: time.Now().Add(duration)}
	inflight.active.Store(true)
	server.inflightMu.Lock()
	if _, exists := server.inflight[request.ID.Key()]; exists {
		server.inflightMu.Unlock()
		cancel()
		return NewRPCError(CodeInvalidRequest, ClassInvalidRequest, "request id is already in flight", false)
	}
	server.inflight[request.ID.Key()] = inflight
	server.inflightMu.Unlock()

	server.wait.Add(1)
	if inline {
		// Ordering-critical methods finish before the next pipelined request
		// is dispatched, so their effects are visible to later requests.
		server.execute(requestCtx, request, inflight)
		return nil
	}
	go server.execute(requestCtx, request, inflight)
	return nil
}

func (server *Server) execute(ctx context.Context, request Request, inflight *inflightRequest) {
	defer server.wait.Done()
	defer func() { <-server.semaphore }()
	defer inflight.cancel()
	reporter := &requestProgressReporter{server: server, request: inflight}
	var result any
	var rpcErr *RPCError
	func() {
		defer func() {
			if recover() != nil {
				result = nil
				rpcErr = NewRPCError(CodeInternalError, ClassInternalError, "request handler failed", false)
			}
		}()
		result, rpcErr = server.handler.Handle(ctx, request, reporter)
	}()
	inflight.active.Store(false)
	server.inflightMu.Lock()
	if server.inflight[request.ID.Key()] == inflight {
		delete(server.inflight, request.ID.Key())
	}
	server.inflightMu.Unlock()
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			rpcErr = NewRPCError(CodeDeadlineExceeded, ClassDeadlineExceeded, "request deadline exceeded", true)
		} else {
			rpcErr = NewRPCError(CodeCancelled, ClassCancelled, "request was cancelled", true)
		}
	}
	if rpcErr != nil {
		_ = server.writeError(request.ID.Raw(), rpcErr)
		return
	}
	_ = server.writeSuccess(request.ID.Raw(), result)
}

type cancelParams struct {
	RequestID json.RawMessage `json:"request_id"`
}

func (server *Server) handleCancel(request Request) error {
	var params cancelParams
	if rpcErr := decodeParams(request.Params, &params); rpcErr != nil {
		return server.writeError(request.ID.Raw(), rpcErr)
	}
	target, err := ParseID(params.RequestID)
	if err != nil {
		return server.writeError(request.ID.Raw(), NewRPCError(CodeInvalidParams, ClassInvalidParams, "cancel request_id is invalid", false))
	}
	server.inflightMu.Lock()
	inflight := server.inflight[target.Key()]
	server.inflightMu.Unlock()
	if inflight == nil || !inflight.active.Load() {
		return server.writeSuccess(request.ID.Raw(), map[string]any{"cancelled": false, "reason": "not_in_flight"})
	}
	inflight.cancel()
	return server.writeSuccess(request.ID.Raw(), map[string]any{"cancelled": true})
}

func decodeParams(raw json.RawMessage, destination any) *RPCError {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return NewRPCError(CodeInvalidParams, ClassInvalidParams, "params do not match the method schema", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return NewRPCError(CodeInvalidParams, ClassInvalidParams, "params contain trailing JSON", false)
	}
	return nil
}

type requestProgressReporter struct {
	server  *Server
	request *inflightRequest
}

func (reporter *requestProgressReporter) Report(stage string, cancellable bool) error {
	if reporter == nil || reporter.server == nil || reporter.request == nil || !reporter.request.active.Load() {
		return context.Canceled
	}
	if strings.TrimSpace(stage) == "" || strings.TrimSpace(stage) != stage || len(stage) > 64 || strings.IndexFunc(stage, unicode.IsControl) >= 0 {
		return errors.New("progress stage is invalid")
	}
	remaining := time.Until(reporter.request.deadline).Milliseconds()
	if remaining < 0 {
		remaining = 0
	}
	return reporter.server.writeNotification(ProgressNotificationMethod, Progress{
		RequestID:         reporter.request.id.Raw(),
		Stage:             stage,
		RemainingBudgetMS: remaining,
		Cancellable:       cancellable,
	})
}

func (server *Server) shutdown(cancelInflight bool) error {
	if cancelInflight {
		server.cancelAllInflight()
	}
	if server.waitInflight() {
		return nil
	}
	if !cancelInflight {
		// The bounded drain window expired; fall back to cancellation so the
		// process still stops within a second bounded window.
		server.cancelAllInflight()
		if server.waitInflight() {
			return nil
		}
	}
	return fmt.Errorf("stdio shutdown exceeded %s", server.limits.ShutdownTimeout)
}

func (server *Server) cancelAllInflight() {
	server.inflightMu.Lock()
	for _, request := range server.inflight {
		request.cancel()
	}
	server.inflightMu.Unlock()
}

func (server *Server) waitInflight() bool {
	done := make(chan struct{})
	go func() {
		server.wait.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(server.limits.ShutdownTimeout):
		return false
	}
}

func (server *Server) writeFramingError(err error) {
	framing := &FramingError{}
	if !errors.As(err, &framing) {
		_ = server.writeError(nil, NewRPCError(CodeInvalidRequest, ClassInvalidRequest, "stdio framing failed", false))
		return
	}
	code := CodeInvalidRequest
	if framing.Class == ClassRequestTooLarge {
		code = CodeRequestTooLarge
	}
	rpcErr := NewRPCError(code, framing.Class, framing.Detail, false)
	rpcErr.Data.Limit = framing.Limit
	_ = server.writeError(nil, rpcErr)
}

func (server *Server) writeSuccess(id json.RawMessage, result any) error {
	return server.writeJSON(successResponse{JSONRPC: JSONRPCVersion, ID: idOrNull(id), Result: result})
}

func (server *Server) writeError(id json.RawMessage, rpcErr *RPCError) error {
	if rpcErr == nil {
		rpcErr = NewRPCError(CodeInternalError, ClassInternalError, "internal request failure", false)
	}
	return server.writeJSON(errorResponse{JSONRPC: JSONRPCVersion, ID: idOrNull(id), Error: rpcErr})
}

func (server *Server) writeNotification(method string, params any) error {
	return server.writeJSON(notification{JSONRPC: JSONRPCVersion, Method: method, Params: params})
}

func (server *Server) writeJSON(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	server.writeMu.Lock()
	defer server.writeMu.Unlock()
	return server.writer.WriteFrame(payload)
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(rate, capacity int) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: float64(rate), capacity: float64(capacity), tokens: float64(capacity), last: now}
}

func (bucket *tokenBucket) Allow(now time.Time) (time.Duration, bool) {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens = minFloat(bucket.capacity, bucket.tokens+elapsed*bucket.rate)
		bucket.last = now
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return 0, true
	}
	missing := 1 - bucket.tokens
	return time.Duration(missing / bucket.rate * float64(time.Second)), false
}

func minFloat(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
