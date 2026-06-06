package session

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

var planHintSuffixPattern = regexp.MustCompile(`_hint_[0-9]+$`)

func (s *Session) setActiveExecutor(planID string, executor solver.PlanExecutor) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.activePlan = planID
	s.executor = executor
}

func (s *Session) clearActiveExecutor(executor solver.PlanExecutor) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	if s.executor == executor {
		s.executor = nil
		s.activePlan = ""
	}
}

func (s *Session) selectStrategy(ctx context.Context) (solver.Strategy, error) {
	candidates, err := s.resolveStrategyCandidates(ctx)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("session: resolver returned no strategy candidates")
	}
	if err := s.setSelectedStrategyCandidate(candidates[0]); err != nil {
		return nil, err
	}
	return candidates[0].Strategy, nil
}

func (s *Session) resolveStrategyCandidates(ctx context.Context) ([]StrategyCandidate, error) {
	s.transition(StateCapabilityExchange)
	remoteCapability, err := s.waitForRemoteCapability(ctx)
	if err != nil {
		return nil, err
	}

	s.transition(StateSelecting)
	if ordered, ok := s.cfg.Resolver.(OrderedStrategyResolver); ok {
		candidates, err := ordered.ResolveAll(s.buildResolveInput(remoteCapability))
		if err != nil {
			return nil, err
		}
		return validateStrategyCandidates(candidates)
	}

	strategy, selection, err := s.cfg.Resolver.Resolve(remoteCapability, s.cfg.Initiator)
	if err != nil {
		return nil, err
	}
	return validateStrategyCandidates([]StrategyCandidate{{
		Name:      selection.StrategyName,
		Strategy:  strategy,
		Selection: selection,
	}})
}

func (s *Session) buildResolveInput(remoteCapability rproto.Capability) ResolveInput {
	return ResolveInput{
		SessionID:          s.cfg.SessionID,
		LocalNodeID:        s.cfg.LocalNodeID,
		PeerID:             s.cfg.PeerID,
		Initiator:          s.cfg.Initiator,
		LocalCapability:    s.localCapability(),
		RemoteCapability:   normalizeCapability(remoteCapability),
		LocalObservations:  s.localObservationHistory(),
		RemoteObservations: s.RemoteObservations(),
		LastProbeResult:    s.lastProbeResultSummary(),
	}
}

func validateStrategyCandidates(candidates []StrategyCandidate) ([]StrategyCandidate, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("session: resolver returned no strategy candidates")
	}
	validated := make([]StrategyCandidate, 0, len(candidates))
	for i, candidate := range candidates {
		if candidate.Strategy == nil {
			return nil, fmt.Errorf("session: strategy candidate %d returned nil strategy", i)
		}
		name := strings.TrimSpace(candidate.Name)
		if name == "" {
			name = strings.TrimSpace(candidate.Selection.StrategyName)
		}
		if name == "" {
			name = strings.TrimSpace(candidate.Strategy.Name())
		}
		if name == "" {
			return nil, fmt.Errorf("session: strategy candidate %d has empty name", i)
		}
		if strategyName := strings.TrimSpace(candidate.Strategy.Name()); strategyName != name {
			return nil, fmt.Errorf("session: strategy candidate %d name %q does not match strategy name %q", i, name, strategyName)
		}
		selectionName := strings.TrimSpace(candidate.Selection.StrategyName)
		if selectionName == "" {
			candidate.Selection.StrategyName = name
		} else if selectionName != name {
			return nil, fmt.Errorf("session: strategy candidate %d selection name %q does not match strategy name %q", i, selectionName, name)
		}
		candidate.Name = name
		validated = append(validated, candidate)
	}
	return validated, nil
}

func (s *Session) setSelectedStrategyCandidate(candidate StrategyCandidate) error {
	if candidate.Strategy == nil {
		return fmt.Errorf("session: selected strategy candidate %q is nil", candidate.Name)
	}
	s.setSelectedStrategy(candidate.Strategy, candidate.Selection)
	return nil
}

func (s *Session) setSelectedStrategy(strategy solver.Strategy, selection Selection) {
	if strategy == nil {
		return
	}
	s.strategyMu.Lock()
	s.strategy = strategy
	s.strategyMu.Unlock()

	s.metaMu.Lock()
	s.meta.SelectedStrategy = selection.StrategyName
	s.meta.SelectionNegotiated = selection.Negotiated
	s.metaMu.Unlock()
}

func (s *Session) clearSelectedStrategy() {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.strategy = nil
	s.executor = nil
	s.activePlan = ""
}

func (s *Session) selectedStrategyName() string {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.meta.SelectedStrategy
}

func (s *Session) currentStrategy() solver.Strategy {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	return s.strategy
}

func (s *Session) currentExecutor() solver.PlanExecutor {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	return s.executor
}

func (s *Session) strategyHandlerSnapshot() (strategyMessageTarget, string, bool) {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	if s.executor != nil {
		return s.executor, s.activePlan, false
	}
	if s.strategy == nil {
		return nil, "", true
	}
	if _, ok := s.strategy.(solver.ExecutorFactory); ok {
		return nil, "", true
	}
	handler, ok := s.strategy.(solver.MessageHandler)
	if !ok {
		return nil, "", false
	}
	return handler, "", false
}

func (s *Session) enqueueStrategyMessage(msg solver.Message) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.pending = append(s.pending, cloneMessage(msg))
}

func (s *Session) flushPendingStrategyMessages(ctx context.Context, handler strategyMessageTarget, activePlan string) error {
	if handler == nil {
		return nil
	}
	for {
		s.strategyMu.Lock()
		var deliver []solver.Message
		retained := make([]solver.Message, 0, len(s.pending))
		for _, msg := range s.pending {
			if shouldBufferForFuturePlan(msg, activePlan) {
				retained = append(retained, msg)
				continue
			}
			deliver = append(deliver, msg)
		}
		s.pending = retained
		s.strategyMu.Unlock()

		if len(deliver) == 0 {
			return nil
		}
		for _, msg := range deliver {
			if err := handler.HandleMessage(ctx, s.io, msg); err != nil {
				return err
			}
		}
	}
}

func (s *Session) discardPendingStrategyMessages() {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.pending = nil
}

func (s *Session) discardPendingStrategyMessagesForPlan(planID string) {
	if strings.TrimSpace(planID) == "" {
		s.discardPendingStrategyMessages()
		return
	}
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	retained := make([]solver.Message, 0, len(s.pending))
	for _, msg := range s.pending {
		if msgPlanID, ok := strategyMessagePlanID(msg); ok && !strategyPlanIDsMatch(msgPlanID, planID) {
			retained = append(retained, msg)
		}
	}
	s.pending = retained
}

func shouldBufferForFuturePlan(msg solver.Message, activePlan string) bool {
	if strings.TrimSpace(activePlan) == "" {
		return false
	}
	msgPlanID, ok := strategyMessagePlanID(msg)
	return ok && !strategyPlanIDsMatch(msgPlanID, activePlan)
}

func strategyMessagePlanID(msg solver.Message) (string, bool) {
	if len(msg.Payload) == 0 {
		return "", false
	}
	var header struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.Unmarshal(msg.Payload, &header); err != nil {
		return "", false
	}
	planID := strings.TrimSpace(header.PlanID)
	if planID == "" {
		return "", false
	}
	return planID, true
}

func strategyPlanIDsMatch(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return a == b || normalizeStrategyPlanID(a) == normalizeStrategyPlanID(b)
}

func normalizeStrategyPlanID(planID string) string {
	return planHintSuffixPattern.ReplaceAllString(strings.TrimSpace(planID), "")
}
