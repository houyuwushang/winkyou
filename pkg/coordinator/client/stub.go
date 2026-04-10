package client

import (
	"context"
	"sync"
	"time"
)

type stubClient struct {
	cfg            Config
	mu             sync.RWMutex
	signalHandlers []func(signal *SignalNotification)
	peerHandlers   []func(peer *PeerInfo, event PeerEvent)
	closeMux       sync.Once
}

func newStubClient(cfg *Config) (CoordinatorClient, error) {
	merged := DefaultConfig()
	if cfg != nil {
		merged = *cfg
		if merged.Timeout == 0 {
			merged.Timeout = DefaultConfig().Timeout
		}
		if merged.Retry.MaxAttempts == 0 {
			merged.Retry.MaxAttempts = DefaultConfig().Retry.MaxAttempts
		}
		if merged.Retry.InitialBackoff == 0 {
			merged.Retry.InitialBackoff = DefaultConfig().Retry.InitialBackoff
		}
		if merged.Retry.MaxBackoff == 0 {
			merged.Retry.MaxBackoff = DefaultConfig().Retry.MaxBackoff
		}
	}
	if err := validateConfig(&merged); err != nil {
		return nil, err
	}

	return &stubClient{
		cfg: merged,
	}, nil
}

func (c *stubClient) Connect(ctx context.Context) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return nil
}

func (c *stubClient) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	return nil, contextAwareErr(ctx)
}

func (c *stubClient) StartHeartbeat(ctx context.Context, interval time.Duration) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	if interval <= 0 {
		return nil
	}
	return nil
}

func (c *stubClient) StopHeartbeat() {}

func (c *stubClient) ListPeers(ctx context.Context, opts ...ListOption) ([]*PeerInfo, error) {
	_ = applyListOptions(opts)
	return nil, contextAwareErr(ctx)
}

func (c *stubClient) GetPeer(ctx context.Context, nodeID string) (*PeerInfo, error) {
	_ = nodeID
	return nil, contextAwareErr(ctx)
}

func (c *stubClient) SendSignal(ctx context.Context, to string, signalType SignalType, payload []byte) error {
	_ = to
	_ = signalType
	_ = payload
	return contextAwareErr(ctx)
}

func (c *stubClient) OnSignal(handler func(signal *SignalNotification)) {
	if handler == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signalHandlers = append(c.signalHandlers, handler)
}

func (c *stubClient) OnPeerUpdate(handler func(peer *PeerInfo, event PeerEvent)) {
	if handler == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerHandlers = append(c.peerHandlers, handler)
}

func (c *stubClient) Close() error {
	c.closeMux.Do(func() {
	})
	return nil
}

func contextAwareErr(ctx context.Context) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return ErrNotImplemented
}
