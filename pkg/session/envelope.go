package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

func (s *Session) HandleMessage(ctx context.Context, msg solver.Message) error {
	switch msg.Kind {
	case solver.MessageKindEnvelope:
		if msg.Namespace != "" && msg.Namespace != envelopeNamespace {
			return nil
		}
		return s.handleEnvelopeMessage(msg)
	case solver.MessageKindStrategy:
		target, pending := s.strategyHandler()
		if pending || target == nil {
			s.enqueueStrategyMessage(msg)
			return nil
		}
		return target.HandleMessage(ctx, s.io, msg)
	default:
		return nil
	}
}

func (s *Session) sendCapability(ctx context.Context) error {
	envelope, err := s.newEnvelope(rproto.MsgTypeCapability, s.localCapability())
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	sendCtx, cancel := s.operationContext(ctx)
	defer cancel()
	return s.io.Send(sendCtx, solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       rproto.MsgTypeCapability,
		Payload:    payload,
		ReceivedAt: time.Now(),
	})
}

func (s *Session) sendPathCommit(ctx context.Context, result solver.Result) error {
	envelope, err := s.newEnvelope(rproto.MsgTypePathCommit, rproto.PathCommit{
		Strategy:       s.selectedStrategyName(),
		PathID:         result.Summary.PathID,
		ConnectionType: result.Summary.ConnectionType,
	})
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	sendCtx, cancel := s.operationContext(ctx)
	defer cancel()
	return s.io.Send(sendCtx, solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       rproto.MsgTypePathCommit,
		Payload:    payload,
		ReceivedAt: time.Now(),
	})
}

func (s *Session) handleEnvelopeMessage(msg solver.Message) error {
	envelope, err := rproto.UnmarshalEnvelope(msg.Payload)
	if err != nil {
		return err
	}
	if envelope.SessionID != s.cfg.SessionID {
		return nil
	}

	receivedAt := msg.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}

	s.metaMu.Lock()
	s.meta.LastEnvelopeType = envelope.MsgType
	s.meta.LastEnvelopeAt = receivedAt
	s.metaMu.Unlock()

	switch envelope.MsgType {
	case rproto.MsgTypeCapability:
		var capability rproto.Capability
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &capability); err != nil {
				return fmt.Errorf("session: decode capability: %w", err)
			}
		}
		s.setRemoteCapability(capability, receivedAt)
	case rproto.MsgTypePathCommit:
		var pathCommit rproto.PathCommit
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &pathCommit); err != nil {
				return fmt.Errorf("session: decode path commit: %w", err)
			}
		}
		s.setRemotePathCommit(pathCommit, receivedAt)
	case rproto.MsgTypeObservation:
		var obs rproto.Observation
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &obs); err != nil {
				return fmt.Errorf("session: decode observation: %w", err)
			}
		}
		s.recordRemoteObservation(obs, receivedAt)
	case rproto.MsgTypeProbeScript:
		var script rproto.ProbeScript
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &script); err != nil {
				return fmt.Errorf("session: decode probe_script: %w", err)
			}
		}
		s.handleProbeScript(receivedAt, script)
	case rproto.MsgTypeProbeResult:
		var result rproto.ProbeResult
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &result); err != nil {
				return fmt.Errorf("session: decode probe_result: %w", err)
			}
		}
		s.handleProbeResult(receivedAt, result)
	}
	return nil
}

func (s *Session) localCapability() rproto.Capability {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.LocalCapability)
}

func (s *Session) remoteCapability() rproto.Capability {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.RemoteCapability)
}

func (s *Session) remoteCapabilitySnapshot() (rproto.Capability, bool) {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.RemoteCapability), !s.meta.CapabilityExchangeAt.IsZero()
}

func (s *Session) waitForRemoteCapability(ctx context.Context) (rproto.Capability, error) {
	if capability, received := s.remoteCapabilitySnapshot(); received {
		return capability, nil
	}

	timeout := s.capabilityWaitTimeout()
	if timeout <= 0 {
		return rproto.Capability{}, nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return rproto.Capability{}, ctx.Err()
		case <-timer.C:
			return s.remoteCapability(), nil
		case <-s.capabilityCh:
			if capability, received := s.remoteCapabilitySnapshot(); received {
				return capability, nil
			}
		}
	}
}

func (s *Session) setRemoteCapability(capability rproto.Capability, receivedAt time.Time) {
	normalized := normalizeCapability(capability)

	s.metaMu.Lock()
	s.meta.RemoteCapability = normalized
	if !receivedAt.IsZero() {
		s.meta.CapabilityExchangeAt = receivedAt
	}
	s.metaMu.Unlock()

	select {
	case s.capabilityCh <- struct{}{}:
	default:
	}
}

func (s *Session) setRemotePathCommit(pathCommit rproto.PathCommit, receivedAt time.Time) {
	snapshot := PathCommitSnapshot{
		Strategy:       pathCommit.Strategy,
		PathID:         pathCommit.PathID,
		ConnectionType: pathCommit.ConnectionType,
	}
	s.metaMu.Lock()
	s.meta.LastPathCommit = snapshot
	if !receivedAt.IsZero() {
		s.meta.LastPathCommitAt = receivedAt
	}
	s.metaMu.Unlock()
}

func (s *Session) newEnvelope(msgType string, payload any) (rproto.SessionEnvelope, error) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	s.seq++
	return rproto.SessionEnvelope{
		SessionID: s.cfg.SessionID,
		FromNode:  s.cfg.LocalNodeID,
		ToNode:    s.cfg.PeerID,
		MsgType:   msgType,
		Seq:       s.seq,
		Payload:   rproto.MustPayload(payload),
	}, nil
}

func (io *solverIO) Send(ctx context.Context, msg solver.Message) error {
	return io.cfg.Sender.Send(ctx, io.cfg.PeerID, msg)
}
