// Package routed exposes packet and fixed-TCP services on top of mesh-routed
// binary data frames. Intermediate mesh nodes do not import this package.
package routed

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"winkyou/pkg/mesh"
)

var (
	ErrClosed          = errors.New("routed dataplane: closed")
	ErrHandlerExists   = errors.New("routed dataplane: handler already registered")
	ErrNoHandler       = errors.New("routed dataplane: no handler for frame type")
	ErrPacketTransport = errors.New("routed dataplane: packet transport unavailable")
)

type FrameHandler func(context.Context, mesh.DataFrame) error

type registeredHandler struct {
	id uint64
	fn FrameHandler
}

// Endpoint dispatches locally delivered mesh data frames. Transit nodes bypass
// Endpoint entirely and forward only from the binary routing header.
type Endpoint struct {
	node *mesh.Node

	mu       sync.RWMutex
	closed   bool
	packets  map[string]*PacketTransport
	handlers map[mesh.DataType]registeredHandler
	flowSeq  atomic.Uint64
	regSeq   atomic.Uint64
}

func NewEndpoint(node *mesh.Node) (*Endpoint, error) {
	if node == nil || node.NodeID() == "" {
		return nil, fmt.Errorf("routed dataplane: mesh node is required")
	}
	flowSeed, err := randomFlowSequenceSeed()
	if err != nil {
		return nil, err
	}
	endpoint := &Endpoint{
		node:     node,
		packets:  make(map[string]*PacketTransport),
		handlers: make(map[mesh.DataType]registeredHandler),
	}
	endpoint.flowSeq.Store(flowSeed)
	if err := node.SetDataHandler(endpoint.handleFrame); err != nil {
		return nil, err
	}
	return endpoint, nil
}

func randomFlowSequenceSeed() (uint64, error) {
	var encoded [8]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return 0, fmt.Errorf("routed dataplane: initialize flow sequence: %w", err)
	}
	seed := binary.BigEndian.Uint64(encoded[:])
	if seed == 0 {
		// Zero is reserved so a degenerate random sample still does not recreate
		// the deterministic process-start sequence used by older endpoints.
		seed = 1
	}
	return seed, nil
}

func (e *Endpoint) NodeID() string {
	if e == nil || e.node == nil {
		return ""
	}
	return e.node.NodeID()
}

func (e *Endpoint) Send(ctx context.Context, frame mesh.DataFrame) error {
	if e == nil || e.node == nil {
		return ErrClosed
	}
	e.mu.RLock()
	closed := e.closed
	e.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	return e.node.SendData(ctx, frame)
}

func (e *Endpoint) RegisterHandler(types []mesh.DataType, handler FrameHandler) (func(), error) {
	if e == nil || handler == nil || len(types) == 0 {
		return nil, fmt.Errorf("routed dataplane: frame types and handler are required")
	}
	id := e.regSeq.Add(1)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrClosed
	}
	for _, frameType := range types {
		if _, exists := e.handlers[frameType]; exists {
			return nil, fmt.Errorf("%w: %d", ErrHandlerExists, frameType)
		}
	}
	for _, frameType := range types {
		e.handlers[frameType] = registeredHandler{id: id, fn: handler}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Lock()
			for _, frameType := range types {
				if current, exists := e.handlers[frameType]; exists && current.id == id {
					delete(e.handlers, frameType)
				}
			}
			e.mu.Unlock()
		})
	}, nil
}

func (e *Endpoint) handleFrame(ctx context.Context, frame mesh.DataFrame) error {
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return ErrClosed
	}
	if frame.Type == mesh.DataTypePacket {
		transport := e.packets[frame.Source]
		e.mu.RUnlock()
		if transport == nil {
			return fmt.Errorf("%w: source %s", ErrPacketTransport, frame.Source)
		}
		return transport.deliver(frame)
	}
	handler := e.handlers[frame.Type]
	e.mu.RUnlock()
	if handler.fn == nil {
		return fmt.Errorf("%w: %d", ErrNoHandler, frame.Type)
	}
	return handler.fn(ctx, frame)
}

func (e *Endpoint) nextFlowID() uint64 {
	for {
		id := e.flowSeq.Add(1)
		if id != 0 {
			return id
		}
	}
}

func (e *Endpoint) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	transports := make([]*PacketTransport, 0, len(e.packets))
	for _, transport := range e.packets {
		transports = append(transports, transport)
	}
	e.packets = make(map[string]*PacketTransport)
	e.handlers = make(map[mesh.DataType]registeredHandler)
	e.mu.Unlock()
	_ = e.node.SetDataHandler(nil)
	for _, transport := range transports {
		transport.closeFromEndpoint()
	}
	return nil
}
