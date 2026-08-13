package session

import (
	"context"
	"fmt"
	"time"

	pmodel "winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/session/wireadapter"
	"winkyou/pkg/solver"
)

func (s *Session) preflightProbeTimeout() time.Duration {
	if s.cfg.PreflightProbeTimeout > 0 {
		return s.cfg.PreflightProbeTimeout
	}
	return defaultPreflightProbeTimeout
}

func (s *Session) buildProbeInput() solver.ProbeInput {
	solve := s.buildSolveInput()
	return solver.ProbeInput{
		SessionID:          solve.SessionID,
		LocalNodeID:        solve.LocalNodeID,
		RemoteNodeID:       solve.RemoteNodeID,
		Initiator:          solve.Initiator,
		LocalCapability:    solve.LocalCapability,
		RemoteCapability:   solve.RemoteCapability,
		LocalObservations:  solve.LocalObservations,
		RemoteObservations: solve.RemoteObservations,
		LastProbeResult:    solve.LastProbeResult,
	}
}

func (s *Session) runStrategyPreflightProbe(ctx context.Context, strategy solver.Strategy) error {
	planner, ok := strategy.(solver.ProbePlanner)
	if !ok || !s.cfg.Initiator || !s.probeFeaturesNegotiated() {
		s.setPreflightAttempt(false, false)
		return nil
	}

	script, policy, err := planner.BuildPreflightProbe(ctx, s.buildProbeInput())
	if err != nil {
		s.setPreflightAttempt(true, false)
		return err
	}
	if script == nil {
		s.setPreflightAttempt(false, false)
		return nil
	}

	s.transition(StateProbing)
	s.setPreflightAttempt(true, false)
	localScript := solver.NormalizeProbeScript(*script)
	sentAt := time.Now()
	if err := s.sendProbeScript(ctx, localScript); err != nil {
		return err
	}

	if signal, ok := s.latestProbeResult(localScript.ScriptType, sentAt); ok {
		return s.completePreflightProbe(signal)
	}

	timeout := policy.Timeout
	if timeout <= 0 {
		timeout = s.preflightProbeTimeout()
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cachePoll := time.NewTicker(10 * time.Millisecond)
	defer cachePoll.Stop()

	for {
		select {
		case <-waitCtx.Done():
			s.setPreflightAttempt(true, false)
			if policy.Optional {
				return waitCtx.Err()
			}
			return waitCtx.Err()
		case <-cachePoll.C:
			if signal, ok := s.latestProbeResult(localScript.ScriptType, sentAt); ok {
				return s.completePreflightProbe(signal)
			}
		case signal := <-s.probeResultCh:
			if !probeResultMatches(signal, localScript.ScriptType, sentAt) {
				continue
			}
			return s.completePreflightProbe(signal)
		}
	}
}

func (s *Session) latestProbeResult(scriptType string, sentAt time.Time) (probeResultSignal, bool) {
	s.probeResultMu.Lock()
	defer s.probeResultMu.Unlock()
	signal, ok := s.probeResults[scriptType]
	if !ok || !probeResultMatches(signal, scriptType, sentAt) {
		return probeResultSignal{}, false
	}
	return signal, true
}

func probeResultMatches(signal probeResultSignal, scriptType string, sentAt time.Time) bool {
	if signal.result.ScriptType != scriptType {
		return false
	}
	return !signal.at.Before(sentAt) || !signal.result.FinishedAt.Before(sentAt)
}

func (s *Session) completePreflightProbe(signal probeResultSignal) error {
	s.setPreflightAttempt(true, signal.result.Success)
	if !signal.result.Success {
		return fmt.Errorf("session: preflight probe failed: %s", signal.result.ErrorClass)
	}
	return nil
}

func (s *Session) setPreflightAttempt(attempted, succeeded bool) {
	s.metaMu.Lock()
	s.meta.PreflightProbeAttempted = attempted
	s.meta.PreflightProbeSucceeded = succeeded
	s.metaMu.Unlock()
}

func (s *Session) probeFeaturesNegotiated() bool {
	local := s.localCapability()
	remote := s.remoteCapability()
	return capabilityHasFeature(local, rproto.FeatureProbeLabV1) &&
		capabilityHasFeature(local, rproto.FeatureProbeScriptV1) &&
		capabilityHasFeature(remote, rproto.FeatureProbeLabV1) &&
		capabilityHasFeature(remote, rproto.FeatureProbeScriptV1)
}

func (s *Session) sendProbeScript(ctx context.Context, script solver.ProbeScript) error {
	envelope, err := s.newEnvelope(rproto.MsgTypeProbeScript, wireadapter.ProbeScriptToWire(script))
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	s.recordProbeScript(script, time.Now())
	s.emitObservation(ctx, solver.Observation{
		Strategy: pmodel.StrategyName,
		PlanID:   script.PlanID,
		Event:    "probe_script_sent",
		Reason:   script.ScriptType,
		Details: map[string]string{
			"script_type": script.ScriptType,
			"step_count":  fmt.Sprintf("%d", len(script.Steps)),
		},
	})
	sendCtx, cancel := s.operationContext(ctx)
	defer cancel()
	return s.io.Send(sendCtx, solver.Message{
		Kind:      solver.MessageKindEnvelope,
		Namespace: envelopeNamespace,
		Type:      rproto.MsgTypeProbeScript,
		Payload:   payload,
	})
}

func (s *Session) sendProbeResult(ctx context.Context, result solver.ProbeResult) error {
	envelope, err := s.newEnvelope(rproto.MsgTypeProbeResult, wireadapter.ProbeResultToWire(result))
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
		Type:      rproto.MsgTypeProbeResult,
		Payload:   payload,
	})
}

func (s *Session) handleProbeScript(receivedAt time.Time, script rproto.ProbeScript) {
	localScript := wireadapter.ProbeScriptFromWire(script)
	s.recordProbeScript(localScript, receivedAt)
	runCtx := s.runContext()
	s.emitObservation(runCtx, solver.Observation{
		Strategy: pmodel.StrategyName,
		PlanID:   localScript.PlanID,
		Event:    "probe_script_received",
		Reason:   localScript.ScriptType,
		Details: map[string]string{
			"script_type": localScript.ScriptType,
			"step_count":  fmt.Sprintf("%d", len(localScript.Steps)),
		},
	})

	go s.runProbeScript(localScript)
}

func (s *Session) runProbeScript(script solver.ProbeScript) {
	runCtx := s.runContext()
	s.emitObservation(runCtx, solver.Observation{
		Strategy: pmodel.StrategyName,
		PlanID:   script.PlanID,
		Event:    "probe_script_started",
		Reason:   script.ScriptType,
		Details: map[string]string{
			"script_type": script.ScriptType,
		},
	})

	if s.cfg.ProbeRunner == nil {
		result := solver.ProbeResult{
			ScriptType: script.ScriptType,
			PlanID:     script.PlanID,
			Success:    false,
			ErrorClass: "runner_missing",
			FinishedAt: time.Now(),
		}
		s.metaMu.Lock()
		s.meta.LastProbeResult = cloneProbeResult(result)
		s.meta.LastProbeResultAt = result.FinishedAt
		s.metaMu.Unlock()
		s.emitObservation(runCtx, solver.Observation{
			Strategy:   pmodel.StrategyName,
			PlanID:     script.PlanID,
			Event:      "probe_script_failed",
			ErrorClass: result.ErrorClass,
			Reason:     script.ScriptType,
			Details: map[string]string{
				"script_type": script.ScriptType,
			},
		})
		if err := s.sendProbeResult(runCtx, result); err != nil {
			s.notifyError(err)
		}
		return
	}

	if runCtx == nil {
		runCtx = context.Background()
	}
	result, err := s.cfg.ProbeRunner.Run(runCtx, script)
	if result.ScriptType == "" {
		result.ScriptType = script.ScriptType
	}
	if result.PlanID == "" {
		result.PlanID = script.PlanID
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now()
	}
	if err != nil && result.ErrorClass == "" {
		result.ErrorClass = classifyError(err)
	}
	s.metaMu.Lock()
	s.meta.LastProbeResult = cloneProbeResult(result)
	s.meta.LastProbeResultAt = result.FinishedAt
	s.metaMu.Unlock()
	for _, obs := range result.Events {
		s.emitObservation(runCtx, obs)
	}
	if err != nil || !result.Success {
		reason := script.ScriptType
		if err != nil {
			reason = err.Error()
		}
		s.emitObservation(runCtx, solver.Observation{
			Strategy:   pmodel.StrategyName,
			PlanID:     script.PlanID,
			Event:      "probe_script_failed",
			ErrorClass: result.ErrorClass,
			Reason:     reason,
			Details: map[string]string{
				"script_type": script.ScriptType,
			},
		})
	} else {
		s.emitObservation(runCtx, solver.Observation{
			Strategy: pmodel.StrategyName,
			PlanID:   script.PlanID,
			Event:    "probe_script_succeeded",
			Reason:   script.ScriptType,
			Details: map[string]string{
				"script_type": script.ScriptType,
			},
		})
	}
	if err := s.sendProbeResult(runCtx, result); err != nil {
		s.notifyError(err)
	}
}

func (s *Session) handleProbeResult(receivedAt time.Time, result rproto.ProbeResult) {
	localResult := wireadapter.ProbeResultFromWire(result)
	if localResult.FinishedAt.IsZero() {
		localResult.FinishedAt = receivedAt
	}

	s.metaMu.Lock()
	s.meta.LastProbeResult = cloneProbeResult(localResult)
	if !receivedAt.IsZero() {
		s.meta.LastProbeResultAt = receivedAt
	} else {
		s.meta.LastProbeResultAt = localResult.FinishedAt
	}
	s.metaMu.Unlock()

	s.probeResultMu.Lock()
	s.probeResults[localResult.ScriptType] = probeResultSignal{result: localResult, at: receivedAt}
	s.probeResultMu.Unlock()

	s.emitObservation(s.runContext(), solver.Observation{
		Strategy:       pmodel.StrategyName,
		PlanID:         localResult.PlanID,
		Event:          "probe_result_received",
		PathID:         localResult.SelectedPathID,
		ErrorClass:     localResult.ErrorClass,
		ConnectionType: localResultPathType(localResult),
		Reason:         localResult.ScriptType,
		Details: map[string]string{
			"script_type":      localResult.ScriptType,
			"success":          fmt.Sprintf("%t", localResult.Success),
			"event_count":      fmt.Sprintf("%d", len(localResult.Events)),
			"selected_path_id": localResult.SelectedPathID,
		},
	})

	select {
	case s.probeResultCh <- probeResultSignal{result: localResult, at: receivedAt}:
	default:
	}
}

func (s *Session) recordProbeScript(script solver.ProbeScript, at time.Time) {
	s.metaMu.Lock()
	s.meta.LastProbeScriptType = script.ScriptType
	if !at.IsZero() {
		s.meta.LastProbeScriptAt = at
	} else {
		s.meta.LastProbeScriptAt = time.Now()
	}
	s.metaMu.Unlock()
}

func localResultPathType(result solver.ProbeResult) string {
	for i := len(result.Events) - 1; i >= 0; i-- {
		if result.Events[i].ConnectionType != "" {
			return result.Events[i].ConnectionType
		}
	}
	return ""
}
