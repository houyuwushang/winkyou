package stdiojsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const JSONRPCVersion = "2.0"

const (
	CodeParseError       = -32700
	CodeInvalidRequest   = -32600
	CodeMethodNotFound   = -32601
	CodeInvalidParams    = -32602
	CodeInternalError    = -32603
	CodeRequestTooLarge  = -32001
	CodeRateLimited      = -32002
	CodeConcurrencyLimit = -32003
	CodeDeadlineExceeded = -32004
	CodeCancelled        = -32800
)

const (
	ClassParseError       = "parse_error"
	ClassInvalidRequest   = "invalid_request"
	ClassMethodNotFound   = "method_not_found"
	ClassInvalidParams    = "invalid_params"
	ClassInternalError    = "internal_error"
	ClassRequestTooLarge  = "request_too_large"
	ClassRateLimited      = "rate_limited"
	ClassConcurrencyLimit = "concurrency_limit"
	ClassDeadlineExceeded = "deadline_exceeded"
	ClassCancelled        = "cancelled"
)

// ErrorData carries a stable machine-readable class without exposing internal
// error strings. Limit and RetryAfterMS are populated only when meaningful.
type ErrorData struct {
	Class        string `json:"class"`
	Retryable    bool   `json:"retryable"`
	Limit        int64  `json:"limit,omitempty"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// RPCError is a JSON-RPC error object safe to return to a local client.
type RPCError struct {
	Code    int       `json:"code"`
	Message string    `json:"message"`
	Data    ErrorData `json:"data"`
}

func NewRPCError(code int, class, message string, retryable bool) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
		Data: ErrorData{
			Class:     class,
			Retryable: retryable,
		},
	}
}

// ID is the validated request identifier used for in-flight cancellation.
// Version 1 deliberately accepts only strings and canonical base-10 integers.
type ID struct {
	raw json.RawMessage
	key string
}

var integerIDPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func ParseID(raw json.RawMessage) (ID, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ID{}, fmt.Errorf("request id is required")
	}
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return ID{}, fmt.Errorf("request id string is invalid")
		}
		if !utf8.ValidString(value) || len(value) > 128 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return ID{}, fmt.Errorf("request id string is invalid")
		}
		copyRaw := append(json.RawMessage(nil), trimmed...)
		return ID{raw: copyRaw, key: "s:" + value}, nil
	}
	if !integerIDPattern.Match(trimmed) {
		return ID{}, fmt.Errorf("request id must be a string or canonical integer")
	}
	copyRaw := append(json.RawMessage(nil), trimmed...)
	return ID{raw: copyRaw, key: "n:" + string(trimmed)}, nil
}

func (id ID) Raw() json.RawMessage {
	return append(json.RawMessage(nil), id.raw...)
}

func (id ID) Key() string {
	return id.key
}

// Request is a validated JSON-RPC request. Params is absent or one JSON object.
type Request struct {
	ID     ID
	Method string
	Params json.RawMessage
}

type wireRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func ParseRequest(payload []byte) (Request, *RPCError) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire wireRequest
	if err := decoder.Decode(&wire); err != nil {
		return Request{}, NewRPCError(CodeParseError, ClassParseError, "request body is not valid JSON-RPC", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, NewRPCError(CodeInvalidRequest, ClassInvalidRequest, "request body contains trailing or invalid JSON", false)
	}
	if wire.JSONRPC != JSONRPCVersion {
		return Request{}, NewRPCError(CodeInvalidRequest, ClassInvalidRequest, "jsonrpc must be 2.0", false)
	}
	id, err := ParseID(wire.ID)
	if err != nil {
		return Request{}, NewRPCError(CodeInvalidRequest, ClassInvalidRequest, err.Error(), false)
	}
	method := strings.TrimSpace(wire.Method)
	if method == "" || method != wire.Method || len(method) > 128 || strings.IndexFunc(method, unicode.IsControl) >= 0 {
		return Request{}, NewRPCError(CodeInvalidRequest, ClassInvalidRequest, "method is invalid", false)
	}
	params := bytes.TrimSpace(wire.Params)
	if len(params) > 0 && params[0] != '{' {
		return Request{}, NewRPCError(CodeInvalidParams, ClassInvalidParams, "params must be an object", false)
	}
	return Request{ID: id, Method: method, Params: append(json.RawMessage(nil), params...)}, nil
}

type successResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

type errorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *RPCError       `json:"error"`
}

type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}
