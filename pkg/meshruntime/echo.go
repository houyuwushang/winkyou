package meshruntime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/peercontrol"
)

type echoResult struct {
	ID          string        `json:"id"`
	TargetID    string        `json:"target_id"`
	Payload     string        `json:"payload"`
	RequestPath []string      `json:"request_path"`
	ReplyPath   []string      `json:"reply_path"`
	RTT         time.Duration `json:"rtt"`
}

type echoService struct {
	nodeID string
	node   *mesh.Node
	seq    atomic.Uint64

	mu      sync.Mutex
	pending map[string]chan peercontrol.Message
}

func newEchoService(nodeID string) *echoService {
	return &echoService{nodeID: nodeID, pending: make(map[string]chan peercontrol.Message)}
}

func (s *echoService) setNode(node *mesh.Node) { s.node = node }

func (s *echoService) handle(ctx context.Context, message peercontrol.Message) error {
	switch message.Type {
	case peercontrol.TypeControlEchoRequest:
		if message.ControlEcho == nil || s.node == nil {
			return nil
		}
		reply := peercontrol.NewControlEchoReply(
			s.nodeID,
			message.From,
			message.ControlEcho.ID,
			message.ControlEcho.Payload,
			message.PathVector,
			16,
		)
		return s.node.Send(ctx, reply)
	case peercontrol.TypeControlEchoReply:
		if message.ControlEcho == nil {
			return nil
		}
		s.mu.Lock()
		result := s.pending[message.ControlEcho.ID]
		s.mu.Unlock()
		if result != nil {
			select {
			case result <- message:
			default:
			}
		}
	}
	return nil
}

func (s *echoService) ping(ctx context.Context, targetID string, payload []byte) (echoResult, error) {
	if s == nil || s.node == nil {
		return echoResult{}, mesh.ErrClosed
	}
	id := fmt.Sprintf("%s-%d-%d", s.nodeID, time.Now().UnixNano(), s.seq.Add(1))
	replies := make(chan peercontrol.Message, 1)
	s.mu.Lock()
	s.pending[id] = replies
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	started := time.Now()
	request := peercontrol.NewControlEchoRequest(s.nodeID, targetID, id, payload, 16)
	if err := s.node.Send(ctx, request); err != nil {
		return echoResult{}, err
	}
	select {
	case <-ctx.Done():
		return echoResult{}, ctx.Err()
	case reply := <-replies:
		return echoResult{
			ID:          id,
			TargetID:    targetID,
			Payload:     string(reply.ControlEcho.Payload),
			RequestPath: append([]string(nil), reply.ControlEcho.RequestPath...),
			ReplyPath:   append([]string(nil), reply.PathVector...),
			RTT:         time.Since(started),
		}, nil
	}
}
