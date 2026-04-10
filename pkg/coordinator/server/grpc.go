package server

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	clientdto "winkyou/pkg/coordinator/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GRPCService struct {
	coordinatorv1.UnimplementedCoordinatorServer

	domain *Server

	mu       sync.RWMutex
	sessions map[string]*signalSession
}

type signalSession struct {
	nodeID    string
	outbound  chan *coordinatorv1.SignalEnvelope
	done      chan struct{}
	closeOnce sync.Once
}

func NewGRPCService(domain *Server) *GRPCService {
	return &GRPCService{
		domain:   domain,
		sessions: make(map[string]*signalSession),
	}
}

func (s *GRPCService) Register(ctx context.Context, req *coordinatorv1.RegisterRequest) (*coordinatorv1.RegisterResponse, error) {
	resp, err := s.domain.Register(ctx, &clientdto.RegisterRequest{
		PublicKey: req.GetPublicKey(),
		Name:      req.GetName(),
		AuthKey:   req.GetAuthKey(),
		Metadata:  cloneMetadata(req.GetMetadata()),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &coordinatorv1.RegisterResponse{
		NodeId:      resp.NodeID,
		VirtualIp:   resp.VirtualIP,
		ExpiresAt:   resp.ExpiresAt,
		NetworkCidr: resp.NetworkCIDR,
	}, nil
}

func (s *GRPCService) Heartbeat(ctx context.Context, req *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	resp, err := s.domain.Heartbeat(ctx, &clientdto.HeartbeatRequest{
		NodeID:    req.GetNodeId(),
		Timestamp: req.GetTimestamp(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &coordinatorv1.HeartbeatResponse{
		ServerTime:   resp.ServerTime,
		UpdatedPeers: append([]string(nil), resp.UpdatedPeers...),
	}, nil
}

func (s *GRPCService) ListPeers(ctx context.Context, req *coordinatorv1.ListPeersRequest) (*coordinatorv1.ListPeersResponse, error) {
	resp, err := s.domain.ListPeers(ctx, &clientdto.ListPeersRequest{
		OnlineOnly: req.GetOnlineOnly(),
	})
	if err != nil {
		return nil, toStatus(err)
	}

	peers := make([]*coordinatorv1.PeerInfo, 0, len(resp.Peers))
	for i := range resp.Peers {
		peer := resp.Peers[i]
		peers = append(peers, peerToProto(&peer))
	}
	return &coordinatorv1.ListPeersResponse{Peers: peers}, nil
}

func (s *GRPCService) GetPeer(ctx context.Context, req *coordinatorv1.GetPeerRequest) (*coordinatorv1.PeerInfo, error) {
	peer, err := s.domain.GetPeer(ctx, &clientdto.GetPeerRequest{NodeID: req.GetNodeId()})
	if err != nil {
		return nil, toStatus(err)
	}
	return peerToProto(peer), nil
}

func (s *GRPCService) Signal(stream grpc.BidiStreamingServer[coordinatorv1.SignalEnvelope, coordinatorv1.SignalEnvelope]) error {
	first, err := stream.Recv()
	if err == io.EOF {
		return status.Error(codes.InvalidArgument, "signal stream requires bind envelope")
	}
	if err != nil {
		return toStatus(err)
	}
	if !isBindEnvelope(first) {
		return status.Error(codes.InvalidArgument, "first signal envelope must bind node_id")
	}

	nodeID := strings.TrimSpace(first.GetFromNode())
	if nodeID == "" {
		return status.Error(codes.InvalidArgument, "signal bind requires from_node")
	}
	if _, err := s.domain.GetPeer(stream.Context(), &clientdto.GetPeerRequest{NodeID: nodeID}); err != nil {
		return toStatus(err)
	}

	session := newSignalSession(nodeID)
	if prev := s.bindSession(nodeID, session); prev != nil {
		prev.close()
	}
	defer func() {
		s.unbindSession(nodeID, session)
		session.close()
	}()

	sendErr := make(chan error, 1)
	go s.sendLoop(stream, session, sendErr)

	if err := s.flushPending(nodeID); err != nil {
		return toStatus(err)
	}

	for {
		select {
		case err := <-sendErr:
			if err != nil {
				return toStatus(err)
			}
			return nil
		default:
		}

		envelope, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return toStatus(err)
		}
		if isBindEnvelope(envelope) {
			continue
		}

		notification := signalFromProto(envelope)
		if notification.FromNode != "" && notification.FromNode != nodeID {
			return toStatus(ErrUnauthorized)
		}
		notification.FromNode = nodeID

		delivered, err := s.domain.ForwardSignal(stream.Context(), &notification)
		if err != nil {
			return toStatus(err)
		}
		if delivered {
			if err := s.flushPending(notification.ToNode); err != nil {
				return toStatus(err)
			}
		}
	}
}

func (s *GRPCService) sendLoop(stream grpc.BidiStreamingServer[coordinatorv1.SignalEnvelope, coordinatorv1.SignalEnvelope], session *signalSession, errCh chan<- error) {
	for {
		select {
		case <-stream.Context().Done():
			errCh <- stream.Context().Err()
			return
		case <-session.done:
			errCh <- nil
			return
		case envelope := <-session.outbound:
			if envelope == nil {
				continue
			}
			if err := stream.Send(envelope); err != nil {
				errCh <- err
				return
			}
		}
	}
}

func (s *GRPCService) flushPending(nodeID string) error {
	session := s.session(nodeID)
	if session == nil {
		return nil
	}

	queue, err := s.domain.Store().DrainSignals(nodeID)
	if err != nil {
		return err
	}
	for i := range queue {
		signal := queue[i]
		if session.enqueue(signalToProto(&signal)) {
			continue
		}
		_, _ = s.domain.Store().ForwardSignal(&signal)
	}
	return nil
}

func (s *GRPCService) bindSession(nodeID string, session *signalSession) *signalSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.sessions[nodeID]
	s.sessions[nodeID] = session
	return prev
}

func (s *GRPCService) session(nodeID string) *signalSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[nodeID]
}

func (s *GRPCService) unbindSession(nodeID string, session *signalSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if current := s.sessions[nodeID]; current == session {
		delete(s.sessions, nodeID)
	}
}

func newSignalSession(nodeID string) *signalSession {
	return &signalSession{
		nodeID:   nodeID,
		outbound: make(chan *coordinatorv1.SignalEnvelope, 64),
		done:     make(chan struct{}),
	}
}

func (s *signalSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
}

func (s *signalSession) enqueue(envelope *coordinatorv1.SignalEnvelope) bool {
	select {
	case <-s.done:
		return false
	default:
	}

	select {
	case <-s.done:
		return false
	case s.outbound <- envelope:
		return true
	}
}

func isBindEnvelope(envelope *coordinatorv1.SignalEnvelope) bool {
	if envelope == nil {
		return false
	}
	return strings.TrimSpace(envelope.GetFromNode()) != "" &&
		strings.TrimSpace(envelope.GetToNode()) == "" &&
		envelope.GetType() == coordinatorv1.SignalType_SIGNAL_TYPE_UNSPECIFIED &&
		len(envelope.GetPayload()) == 0
}

func peerToProto(peer *clientdto.PeerInfo) *coordinatorv1.PeerInfo {
	if peer == nil {
		return nil
	}
	return &coordinatorv1.PeerInfo{
		NodeId:    peer.NodeID,
		Name:      peer.Name,
		PublicKey: peer.PublicKey,
		VirtualIp: peer.VirtualIP,
		Online:    peer.Online,
		LastSeen:  peer.LastSeen,
		Endpoints: append([]string(nil), peer.Endpoints...),
	}
}

func signalFromProto(envelope *coordinatorv1.SignalEnvelope) clientdto.SignalNotification {
	return clientdto.SignalNotification{
		FromNode:  envelope.GetFromNode(),
		ToNode:    envelope.GetToNode(),
		Type:      signalTypeFromProto(envelope.GetType()),
		Payload:   append([]byte(nil), envelope.GetPayload()...),
		Timestamp: envelope.GetTimestamp(),
	}
}

func signalToProto(notification *clientdto.SignalNotification) *coordinatorv1.SignalEnvelope {
	if notification == nil {
		return nil
	}
	return &coordinatorv1.SignalEnvelope{
		FromNode:  notification.FromNode,
		ToNode:    notification.ToNode,
		Type:      signalTypeToProto(notification.Type),
		Payload:   append([]byte(nil), notification.Payload...),
		Timestamp: notification.Timestamp,
	}
}

func signalTypeToProto(signalType clientdto.SignalType) coordinatorv1.SignalType {
	switch signalType {
	case clientdto.SIGNAL_ICE_CANDIDATE:
		return coordinatorv1.SignalType_SIGNAL_ICE_CANDIDATE
	case clientdto.SIGNAL_ICE_OFFER:
		return coordinatorv1.SignalType_SIGNAL_ICE_OFFER
	case clientdto.SIGNAL_ICE_ANSWER:
		return coordinatorv1.SignalType_SIGNAL_ICE_ANSWER
	default:
		return coordinatorv1.SignalType_SIGNAL_TYPE_UNSPECIFIED
	}
}

func signalTypeFromProto(signalType coordinatorv1.SignalType) clientdto.SignalType {
	switch signalType {
	case coordinatorv1.SignalType_SIGNAL_ICE_CANDIDATE:
		return clientdto.SIGNAL_ICE_CANDIDATE
	case coordinatorv1.SignalType_SIGNAL_ICE_OFFER:
		return clientdto.SIGNAL_ICE_OFFER
	case coordinatorv1.SignalType_SIGNAL_ICE_ANSWER:
		return clientdto.SIGNAL_ICE_ANSWER
	default:
		return clientdto.SIGNAL_UNSPECIFIED
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

func toStatus(err error) error {
	if err == nil {
		return nil
	}
	if code := status.Code(err); code != codes.Unknown {
		return err
	}

	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case errors.Is(err, ErrNodeNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrUnauthorized):
		return status.Error(codes.PermissionDenied, err.Error())
	}

	message := strings.ToLower(err.Error())
	if strings.Contains(message, "required") || strings.Contains(message, "request is nil") || strings.Contains(message, "invalid") {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
