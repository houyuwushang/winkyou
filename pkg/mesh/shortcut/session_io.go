package shortcut

import (
	"context"
	"time"

	"winkyou/pkg/solver"
)

type routedSessionIO struct {
	manager  *Manager
	wire     wireMessage
	remoteID string
}

func (s *routedSessionIO) Send(ctx context.Context, message solver.Message) error {
	message.Payload = append([]byte(nil), message.Payload...)
	if message.ReceivedAt.IsZero() {
		message.ReceivedAt = time.Now().UTC()
	}
	wire := s.wire
	wire.SolverMessage = &message
	return s.manager.sendWire(ctx, s.remoteID, typeSolverMessage, wire)
}

func (s *routedSessionIO) ReportObservation(_ context.Context, _ solver.Observation) error {
	return nil
}

var _ solver.SessionIO = (*routedSessionIO)(nil)
