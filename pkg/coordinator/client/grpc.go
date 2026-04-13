package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var dialGRPC = func(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, opts...)
}

type grpcClient struct {
	cfg Config

	mu           sync.RWMutex
	conn         *grpc.ClientConn
	rpc          coordinatorv1.CoordinatorClient
	nodeID       string
	signalStream grpc.BidiStreamingClient[coordinatorv1.SignalEnvelope, coordinatorv1.SignalEnvelope]
	signalCancel context.CancelFunc

	sendMu sync.Mutex

	handlersMu     sync.RWMutex
	signalHandlers []func(signal *SignalNotification)
	peerHandlers   []func(peer *PeerInfo, event PeerEvent)

	heartbeatMu     sync.Mutex
	heartbeatCancel context.CancelFunc

	closeOnce sync.Once
}

func NewClient(cfg *Config) (CoordinatorClient, error) {
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

	return &grpcClient{cfg: merged}, nil
}

func (c *grpcClient) Connect(ctx context.Context) error {
	c.mu.RLock()
	if c.conn != nil && c.rpc != nil {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	target, useTLS := normalizeTarget(c.cfg.URL)
	if target == "" {
		return fmt.Errorf("coordinator client: url is required")
	}

	dialCtx, cancel := c.callContext(ctx)
	defer cancel()

	creds, err := dialTransportCredentials(c.cfg.TLS, useTLS)
	if err != nil {
		return err
	}

	conn, err := dialGRPC(dialCtx, target, grpc.WithBlock(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil && c.rpc != nil {
		_ = conn.Close()
		return nil
	}
	c.conn = conn
	c.rpc = coordinatorv1.NewCoordinatorClient(conn)
	return nil
}

func (c *grpcClient) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("coordinator client: register request is nil")
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	authKey := req.AuthKey
	if authKey == "" {
		authKey = c.cfg.AuthKey
	}

	resp, err := c.rpcClient().Register(callCtx, &coordinatorv1.RegisterRequest{
		PublicKey: req.PublicKey,
		Name:      req.Name,
		AuthKey:   authKey,
		Metadata:  cloneMetadata(req.Metadata),
	})
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.nodeID = resp.GetNodeId()
	c.mu.Unlock()

	if err := c.ensureSignalStream(); err != nil {
		return nil, err
	}

	return &RegisterResponse{
		NodeID:      resp.GetNodeId(),
		VirtualIP:   resp.GetVirtualIp(),
		ExpiresAt:   resp.GetExpiresAt(),
		NetworkCIDR: resp.GetNetworkCidr(),
	}, nil
}

func (c *grpcClient) StartHeartbeat(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("coordinator client: heartbeat interval must be greater than zero")
	}
	if strings.TrimSpace(c.currentNodeID()) == "" {
		return fmt.Errorf("coordinator client: register must be called before starting heartbeat")
	}

	c.heartbeatMu.Lock()
	defer c.heartbeatMu.Unlock()
	if c.heartbeatCancel != nil {
		return nil
	}

	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	heartbeatCtx, cancel := context.WithCancel(baseCtx)
	c.heartbeatCancel = cancel

	go c.heartbeatLoop(heartbeatCtx, interval)
	return nil
}

func (c *grpcClient) StopHeartbeat() {
	c.heartbeatMu.Lock()
	cancel := c.heartbeatCancel
	c.heartbeatCancel = nil
	c.heartbeatMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (c *grpcClient) ListPeers(ctx context.Context, opts ...ListOption) ([]*PeerInfo, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	req := applyListOptions(opts)
	resp, err := c.rpcClient().ListPeers(callCtx, &coordinatorv1.ListPeersRequest{
		OnlineOnly: req.OnlineOnly,
	})
	if err != nil {
		return nil, err
	}

	peers := make([]*PeerInfo, 0, len(resp.GetPeers()))
	for _, peer := range resp.GetPeers() {
		peers = append(peers, peerFromProto(peer))
	}
	return peers, nil
}

func (c *grpcClient) GetPeer(ctx context.Context, nodeID string) (*PeerInfo, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.rpcClient().GetPeer(callCtx, &coordinatorv1.GetPeerRequest{NodeId: nodeID})
	if err != nil {
		return nil, err
	}
	return peerFromProto(resp), nil
}

func (c *grpcClient) SendSignal(ctx context.Context, to string, signalType SignalType, payload []byte) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("coordinator client: signal target is required")
	}
	if err := c.ensureSignalStream(); err != nil {
		return err
	}

	c.mu.RLock()
	nodeID := c.nodeID
	stream := c.signalStream
	c.mu.RUnlock()

	if nodeID == "" {
		return fmt.Errorf("coordinator client: register must be called before signaling")
	}
	if stream == nil {
		return ErrNotImplemented
	}

	envelope := &coordinatorv1.SignalEnvelope{
		FromNode:  nodeID,
		ToNode:    to,
		Type:      signalTypeToProto(signalType),
		Payload:   cloneBytes(payload),
		Timestamp: time.Now().Unix(),
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := stream.Send(envelope); err != nil {
		c.clearSignalStream(stream)
		return err
	}
	return nil
}

func (c *grpcClient) OnSignal(handler func(signal *SignalNotification)) {
	if handler == nil {
		return
	}
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.signalHandlers = append(c.signalHandlers, handler)
}

func (c *grpcClient) OnPeerUpdate(handler func(peer *PeerInfo, event PeerEvent)) {
	if handler == nil {
		return
	}
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.peerHandlers = append(c.peerHandlers, handler)
}

func (c *grpcClient) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		c.StopHeartbeat()

		c.mu.Lock()
		stream := c.signalStream
		cancel := c.signalCancel
		conn := c.conn
		c.signalStream = nil
		c.signalCancel = nil
		c.conn = nil
		c.rpc = nil
		c.nodeID = ""
		c.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if stream != nil {
			_ = stream.CloseSend()
		}
		if conn != nil {
			closeErr = conn.Close()
		}
	})

	return closeErr
}

func (c *grpcClient) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	c.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sendHeartbeat(ctx)
		}
	}
}

func (c *grpcClient) sendHeartbeat(ctx context.Context) {
	nodeID := c.currentNodeID()
	if nodeID == "" {
		return
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.rpcClient().Heartbeat(callCtx, &coordinatorv1.HeartbeatRequest{
		NodeId:    nodeID,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return
	}

	for _, peerID := range resp.GetUpdatedPeers() {
		peer, err := c.GetPeer(ctx, peerID)
		if err != nil {
			if status.Code(err) == codes.NotFound || errors.Is(err, context.Canceled) {
				continue
			}
			continue
		}
		c.dispatchPeer(peer, PeerEventUpsert)
	}
}

func (c *grpcClient) ensureSignalStream() error {
	c.mu.RLock()
	if c.signalStream != nil {
		c.mu.RUnlock()
		return nil
	}
	nodeID := c.nodeID
	rpc := c.rpc
	c.mu.RUnlock()

	if nodeID == "" {
		return fmt.Errorf("coordinator client: register must be called before signaling")
	}
	if rpc == nil {
		return fmt.Errorf("coordinator client: connection is not established")
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	stream, err := rpc.Signal(streamCtx)
	if err != nil {
		cancel()
		return err
	}

	if err := stream.Send(&coordinatorv1.SignalEnvelope{
		FromNode: nodeID,
		Type:     coordinatorv1.SignalType_SIGNAL_TYPE_UNSPECIFIED,
	}); err != nil {
		cancel()
		_ = stream.CloseSend()
		return err
	}

	c.mu.Lock()
	if c.signalStream != nil {
		c.mu.Unlock()
		cancel()
		_ = stream.CloseSend()
		return nil
	}
	c.signalStream = stream
	c.signalCancel = cancel
	c.mu.Unlock()

	go c.receiveSignals(stream)
	return nil
}

func (c *grpcClient) receiveSignals(stream grpc.BidiStreamingClient[coordinatorv1.SignalEnvelope, coordinatorv1.SignalEnvelope]) {
	for {
		envelope, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				c.clearSignalStream(stream)
			} else {
				c.clearSignalStream(stream)
			}
			return
		}

		signal := signalFromProto(envelope)
		c.dispatchSignal(&signal)
	}
}

func (c *grpcClient) clearSignalStream(stream grpc.BidiStreamingClient[coordinatorv1.SignalEnvelope, coordinatorv1.SignalEnvelope]) {
	c.mu.Lock()
	if c.signalStream != stream {
		c.mu.Unlock()
		return
	}
	cancel := c.signalCancel
	c.signalStream = nil
	c.signalCancel = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	_ = stream.CloseSend()
}

func (c *grpcClient) rpcClient() coordinatorv1.CoordinatorClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rpc
}

func (c *grpcClient) currentNodeID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeID
}

func (c *grpcClient) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok || c.cfg.Timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.cfg.Timeout)
}

func (c *grpcClient) dispatchSignal(signal *SignalNotification) {
	c.handlersMu.RLock()
	handlers := append([]func(*SignalNotification){}, c.signalHandlers...)
	c.handlersMu.RUnlock()

	for _, handler := range handlers {
		handler(signal)
	}
}

func (c *grpcClient) dispatchPeer(peer *PeerInfo, event PeerEvent) {
	c.handlersMu.RLock()
	handlers := append([]func(*PeerInfo, PeerEvent){}, c.peerHandlers...)
	c.handlersMu.RUnlock()

	for _, handler := range handlers {
		handler(peer, event)
	}
}

func normalizeTarget(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		return raw, false
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	useTLS := parsed.Scheme == "https" || parsed.Scheme == "grpcs"
	if parsed.Host != "" {
		return parsed.Host, useTLS
	}
	if parsed.Opaque != "" {
		return parsed.Opaque, useTLS
	}
	return strings.TrimPrefix(parsed.Path, "//"), useTLS
}

func dialTransportCredentials(cfg TLSConfig, useTLS bool) (credentials.TransportCredentials, error) {
	if !useTLS {
		return insecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if strings.TrimSpace(cfg.CAFile) != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("coordinator client: read tls ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("coordinator client: append tls ca_file failed")
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}

func peerFromProto(peer *coordinatorv1.PeerInfo) *PeerInfo {
	if peer == nil {
		return nil
	}
	return &PeerInfo{
		NodeID:    peer.GetNodeId(),
		Name:      peer.GetName(),
		PublicKey: peer.GetPublicKey(),
		VirtualIP: peer.GetVirtualIp(),
		Online:    peer.GetOnline(),
		LastSeen:  peer.GetLastSeen(),
		Endpoints: append([]string(nil), peer.GetEndpoints()...),
	}
}

func signalFromProto(envelope *coordinatorv1.SignalEnvelope) SignalNotification {
	return SignalNotification{
		FromNode:  envelope.GetFromNode(),
		ToNode:    envelope.GetToNode(),
		Type:      signalTypeFromProto(envelope.GetType()),
		Payload:   cloneBytes(envelope.GetPayload()),
		Timestamp: envelope.GetTimestamp(),
	}
}

func signalTypeToProto(signalType SignalType) coordinatorv1.SignalType {
	switch signalType {
	case SIGNAL_ICE_CANDIDATE:
		return coordinatorv1.SignalType_SIGNAL_ICE_CANDIDATE
	case SIGNAL_ICE_OFFER:
		return coordinatorv1.SignalType_SIGNAL_ICE_OFFER
	case SIGNAL_ICE_ANSWER:
		return coordinatorv1.SignalType_SIGNAL_ICE_ANSWER
	default:
		return coordinatorv1.SignalType_SIGNAL_TYPE_UNSPECIFIED
	}
}

func signalTypeFromProto(signalType coordinatorv1.SignalType) SignalType {
	switch signalType {
	case coordinatorv1.SignalType_SIGNAL_ICE_CANDIDATE:
		return SIGNAL_ICE_CANDIDATE
	case coordinatorv1.SignalType_SIGNAL_ICE_OFFER:
		return SIGNAL_ICE_OFFER
	case coordinatorv1.SignalType_SIGNAL_ICE_ANSWER:
		return SIGNAL_ICE_ANSWER
	default:
		return SIGNAL_UNSPECIFIED
	}
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

func cloneBytes(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	return out
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
