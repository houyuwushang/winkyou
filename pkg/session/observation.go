package session

import (
	"context"
	"fmt"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/session/wireadapter"
	"winkyou/pkg/solver"
)

func (s *Session) Observations() []solver.Observation {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return solver.CloneObservations(s.observations)
}

func (s *Session) RemoteObservations() []solver.Observation {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return solver.CloneObservations(s.remoteObs)
}

func (s *Session) localObservationCount() int {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return len(s.observations)
}

func (s *Session) recordRemoteObservation(obs rproto.Observation, receivedAt time.Time) {
	solverObs := wireadapter.ObservationFromWire(obs)
	if solverObs.Timestamp.IsZero() {
		solverObs.Timestamp = receivedAt
	}

	s.obsMu.Lock()
	s.remoteObs = appendObservation(s.remoteObs, solverObs, 100)
	s.obsMu.Unlock()
}

func (io *solverIO) ReportObservation(ctx context.Context, obs solver.Observation) error {
	if io.session == nil {
		return nil
	}
	return io.session.reportObservation(ctx, obs)
}

func (s *Session) reportObservation(ctx context.Context, obs solver.Observation) error {
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}
	obs.Details = annotateObservationDetails(obs.Details, s.cfg.SessionID, s.cfg.LocalNodeID, s.cfg.PeerID, s.cfg.Initiator)

	s.obsMu.Lock()
	s.observations = appendObservation(s.observations, obs, 100)
	s.obsMu.Unlock()
	if s.cfg.ObservationSink != nil {
		if err := s.cfg.ObservationSink.Record(obs); err != nil {
			return err
		}
	}

	envelope, err := s.newEnvelope(rproto.MsgTypeObservation, wireadapter.ObservationToWire(obs))
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
		Kind:      solver.MessageKindEnvelope,
		Namespace: envelopeNamespace,
		Type:      rproto.MsgTypeObservation,
		Payload:   payload,
	})
}

func (s *Session) emitObservation(ctx context.Context, obs solver.Observation) {
	if err := s.reportObservation(ctx, obs); err != nil {
		s.notifyError(err)
	}
}

func appendObservation(list []solver.Observation, obs solver.Observation, limit int) []solver.Observation {
	list = append(list, solver.CloneObservation(obs))
	if limit > 0 && len(list) > limit {
		retained := make([]solver.Observation, limit)
		copy(retained, list[len(list)-limit:])
		return retained
	}
	return list
}

func (s *Session) localObservationHistory() []solver.Observation {
	observations := make([]solver.Observation, 0, 128)
	if s.cfg.ObservationHistory != nil {
		observations = append(observations, solver.CloneObservations(s.cfg.ObservationHistory.Recent(64))...)
	}
	observations = append(observations, s.Observations()...)
	return observations
}

func (s *Session) lastProbeResultSummary() *solver.ProbeResultSummary {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	if s.meta.LastProbeResultAt.IsZero() && s.meta.LastProbeResult.ScriptType == "" {
		return nil
	}
	summary := solver.NormalizeProbeResultSummary(solver.ProbeResultSummary{
		ScriptType: s.meta.LastProbeResult.ScriptType,
		Success:    s.meta.LastProbeResult.Success,
		ErrorClass: s.meta.LastProbeResult.ErrorClass,
		PathID:     s.meta.LastProbeResult.SelectedPathID,
		Details: map[string]string{
			"plan_id":     s.meta.LastProbeResult.PlanID,
			"event_count": fmt.Sprintf("%d", len(s.meta.LastProbeResult.Events)),
		},
		FinishedAt: s.meta.LastProbeResult.FinishedAt,
	})
	return &summary
}
