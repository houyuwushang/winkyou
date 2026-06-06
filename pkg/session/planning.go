package session

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
	"winkyou/pkg/solver/strategy/tcpframed"
)

func (s *Session) selectAndExecute(ctx context.Context) error {
	candidates, err := s.resolveStrategyCandidates(ctx)
	if err != nil {
		return err
	}
	s.recordStrategyOrder(ctx, candidates)
	if s.shouldProtectDirectStandby() {
		return s.selectAndExecuteProtectedDirect(ctx, candidates)
	}

	var lastErr error
	for i, candidate := range candidates {
		if err := s.setSelectedStrategyCandidate(candidate); err != nil {
			return err
		}
		if err := s.executeSelectedStrategy(ctx, candidate.Strategy); err == nil {
			return nil
		} else {
			lastErr = err
			s.emitObservation(ctx, solver.Observation{
				Strategy:   candidate.Name,
				Event:      "strategy_failed",
				ErrorClass: classifyError(err),
				Reason:     err.Error(),
				Details: map[string]string{
					"candidate_index": fmt.Sprintf("%d", i),
					"candidate_total": fmt.Sprintf("%d", len(candidates)),
				},
			})
			s.discardPendingStrategyMessages()
			s.clearSelectedStrategy()
			s.ignoreCleanupError(s.runCleanup(candidate.Strategy.Close))
			if ctx != nil && ctx.Err() != nil {
				return err
			}
		}
	}

	if lastErr != nil {
		s.fail(lastErr)
		return nil
	}
	s.fail(fmt.Errorf("session: no strategy candidates available"))
	return nil
}

func (s *Session) selectAndExecuteProtectedDirect(ctx context.Context, candidates []StrategyCandidate) error {
	var (
		allOutcomes []solver.CandidateOutcome
		lastErr     error
		primaryKey  string
	)

	for i, candidate := range candidates {
		if primaryKey != "" && protectedDirectSearchComplete(allOutcomes, candidates[i:], s.cfg.PathPolicy) {
			break
		}
		if err := s.setSelectedStrategyCandidate(candidate); err != nil {
			return err
		}
		outcomes, err := s.executeStrategyOutcomes(ctx, candidate.Strategy)
		if err != nil {
			lastErr = err
			s.recordStrategyFailure(ctx, candidate.Name, err, i, len(candidates))
			if primaryKey != "" {
				s.recordProtectedDirectAttemptFailure(ctx, candidate.Name, err, primaryKey)
			}
			s.discardPendingStrategyMessages()
			s.clearSelectedStrategy()
			s.ignoreCleanupError(s.runCleanup(candidate.Strategy.Close))
			if ctx != nil && ctx.Err() != nil {
				return err
			}
			continue
		}

		best := selectPrimaryOutcome(outcomes, s.cfg.PathPolicy)
		if best == nil {
			err := noSuccessfulOutcomeError(outcomes)
			lastErr = err
			s.closeOutcomeTransports(outcomes)
			s.recordStrategyFailure(ctx, candidate.Name, err, i, len(candidates))
			if primaryKey != "" {
				s.recordProtectedDirectAttemptFailure(ctx, candidate.Name, err, primaryKey)
			}
			s.discardPendingStrategyMessages()
			s.clearSelectedStrategy()
			s.ignoreCleanupError(s.runCleanup(candidate.Strategy.Close))
			if ctx != nil && ctx.Err() != nil {
				return err
			}
			continue
		}

		allOutcomes = append(allOutcomes, outcomes...)
		if primaryKey == "" {
			primaryKey = outcomeKey(*best)
			if protectedDirectSearchComplete(allOutcomes, candidates[i+1:], s.cfg.PathPolicy) {
				break
			}
			continue
		}
		if protectedDirectSearchComplete(allOutcomes, candidates[i+1:], s.cfg.PathPolicy) {
			break
		}
	}

	if primaryKey != "" {
		best := selectPrimaryOutcome(allOutcomes, s.cfg.PathPolicy)
		if best == nil {
			best = findOutcomeByKey(allOutcomes, primaryKey)
		}
		if selectedCandidate := findStrategyCandidateForOutcome(candidates, best); selectedCandidate != nil {
			if err := s.setSelectedStrategyCandidate(*selectedCandidate); err != nil {
				return err
			}
		}
		return s.bindOutcomeSet(ctx, allOutcomes, best)
	}
	if lastErr != nil {
		s.fail(lastErr)
		return nil
	}
	s.fail(fmt.Errorf("session: no strategy candidates available"))
	return nil
}

func (s *Session) selectAndBindProtectedDirect(ctx context.Context) (bool, error) {
	candidates, err := s.resolveStrategyCandidates(ctx)
	if err != nil {
		return false, err
	}
	s.recordStrategyOrder(ctx, candidates)

	primaryPathID := resultPathID(s.lastRes)
	var lastErr error
	for i, candidate := range candidates {
		if !strategyMayProduceDirect(candidate.Name) {
			continue
		}
		if err := s.setSelectedStrategyCandidate(candidate); err != nil {
			return false, err
		}
		outcomes, err := s.executeStrategyOutcomes(ctx, candidate.Strategy)
		if err != nil {
			lastErr = err
			s.recordStrategyFailure(ctx, candidate.Name, err, i, len(candidates))
			s.recordProtectedDirectAttemptFailure(ctx, candidate.Name, err, primaryPathID)
			s.discardPendingStrategyMessages()
			s.clearSelectedStrategy()
			s.ignoreCleanupError(s.runCleanup(candidate.Strategy.Close))
			if ctx != nil && ctx.Err() != nil {
				return false, err
			}
			continue
		}

		protected := selectProtectedDirectOutcome(outcomes, s.cfg.PathPolicy)
		if protected != nil {
			return true, s.bindProtectedDirectImprovement(ctx, outcomes)
		}

		err = noProtectedDirectOutcomeError(outcomes)
		lastErr = err
		s.closeOutcomeTransports(outcomes)
		s.recordProtectedDirectAttemptFailure(ctx, candidate.Name, err, primaryPathID)
		s.discardPendingStrategyMessages()
		s.clearSelectedStrategy()
		s.ignoreCleanupError(s.runCleanup(candidate.Strategy.Close))
		if ctx != nil && ctx.Err() != nil {
			return false, err
		}
	}

	if lastErr != nil {
		return false, nil
	}
	return false, nil
}

func (s *Session) executeSelectedStrategy(ctx context.Context, strategy solver.Strategy) error {
	outcomes, err := s.executeStrategyOutcomes(ctx, strategy)
	if err != nil {
		return err
	}
	return s.bindOutcomeSet(ctx, outcomes, nil)
}

func (s *Session) executeStrategyOutcomes(ctx context.Context, strategy solver.Strategy) ([]solver.CandidateOutcome, error) {
	if err := s.runStrategyPreflightProbe(ctx, strategy); err != nil {
		s.emitObservation(ctx, solver.Observation{
			Strategy:   strategy.Name(),
			Event:      "probe_failed",
			ErrorClass: classifyError(err),
			Reason:     err.Error(),
			Details: map[string]string{
				"script_type": pmodel.ScriptTypePreflight,
				"source":      "preflight_orchestration",
			},
		})
	}

	s.transition(StatePlanning)
	solveInput := s.buildSolveInput()
	plans, err := strategy.Plan(ctx, solveInput)
	if err != nil {
		return nil, err
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("session: strategy %s returned no plans", strategy.Name())
	}

	plansBefore := planIDs(plans)
	plans, refineReason := s.refinePlans(ctx, strategy, solveInput, plans)
	s.recordPlanRefine(plansBefore, planIDs(plans), refineReason)
	if refineReason != "no_refinement" {
		s.emitObservation(ctx, solver.Observation{
			Strategy: strategy.Name(),
			Event:    "plans_refined",
			Reason:   refineReason,
			Details: map[string]string{
				"before": strings.Join(plansBefore, ","),
				"after":  strings.Join(planIDs(plans), ","),
			},
		})
	}

	if len(plans) == 0 {
		return nil, fmt.Errorf("session: all plans pruned after refinement")
	}

	plans, orderReason := s.rankPlans(ctx, strategy, plans)
	s.recordPlanOrder(plans, orderReason)
	s.emitObservation(ctx, solver.Observation{
		Strategy: strategy.Name(),
		Event:    "plan_ordered",
		Reason:   orderReason,
		Details: map[string]string{
			"order": strings.Join(planIDs(plans), ","),
		},
	})

	if _, usesExecutors := strategy.(solver.ExecutorFactory); !usesExecutors {
		handler, _ := strategy.(solver.MessageHandler)
		if err := s.flushPendingStrategyMessages(ctx, handler, ""); err != nil {
			return nil, err
		}
	}

	budget := s.candidateExecutionBudget(len(plans))
	outcomes := s.executeCandidateLoop(ctx, strategy, plans, budget)
	s.discardPendingStrategyMessages()

	return outcomes, nil
}

func (s *Session) candidateExecutionBudget(planCount int) solver.ExecutionBudget {
	budget := solver.DefaultBudget()
	if planCount <= 0 {
		return budget
	}
	maxCandidates := planCount
	budget.MaxCandidates = maxCandidates
	if timeout := s.executionTimeout(); timeout > 0 && maxCandidates > 0 {
		minBudget := timeout * time.Duration(maxCandidates)
		if budget.TimeBudget < minBudget {
			budget.TimeBudget = minBudget
		}
	}
	return budget
}

func (s *Session) bindOutcomeSet(ctx context.Context, outcomes []solver.CandidateOutcome, best *solver.CandidateOutcome) error {
	// Select best outcome
	if best == nil {
		best = selectPrimaryOutcome(outcomes, s.cfg.PathPolicy)
	}
	if best == nil {
		var lastErr error
		for i := range outcomes {
			o := outcomes[i]
			if o.Result != nil && o.Result.Transport != nil {
				s.ignoreCleanupError(s.runCleanup(o.Result.Transport.Close))
			}
			if o.Err != nil {
				lastErr = o.Err
			}
		}
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("session: no successful candidate from %d plans", len(outcomes))
	}

	// Mark selected
	best.Selected = true
	best.SelectionReason = "highest_score"
	annotatedResult := annotateResultPath(*best.Result, best.Plan)
	best.Result = &annotatedResult
	retained := retainSuccessfulOutcomes(outcomes, best, s.cfg.PathPolicy)
	boundResult, _ := buildResultTransportFromOutcomes(best, outcomes, s.cfg.PathPolicy)
	best.Result = &boundResult
	if isMultipathResult(boundResult) {
		s.setRetainedOutcomes(nil)
	} else {
		s.setRetainedOutcomes(retained)
	}
	s.lastPlan = best.Plan
	s.lastRes = boundResult
	s.emitObservation(ctx, solver.Observation{
		Strategy:       best.Plan.Strategy,
		PlanID:         best.Plan.ID,
		Event:          "path_selected",
		PathID:         best.Result.Summary.PathID,
		ConnectionType: best.Result.Summary.ConnectionType,
		LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
		RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
		Reason:         best.SelectionReason,
		Details: pathSummaryObservationDetails(best.Result.Summary, map[string]string{
			"score": fmt.Sprintf("%d", best.Score),
		}),
	})

	// Clean up transports not needed for the selected path or retained policy paths.
	s.closeUnusedOutcomes(outcomes, best, retained)

	s.transition(StateBinding)

	// Bind the winner
	if s.cfg.Binder != nil {
		bindCtx, cancel := s.operationContext(ctx)
		err := s.cfg.Binder.Bind(bindCtx, s.cfg.PeerID, best.Result.Transport)
		cancel()
		if err != nil {
			s.closeRetainedOutcomes()
			s.ignoreCleanupError(s.runCleanup(best.Result.Transport.Close))
			return err
		}
		s.emitObservation(ctx, solver.Observation{
			Strategy:       best.Plan.Strategy,
			PlanID:         best.Plan.ID,
			Event:          "bind_succeeded",
			PathID:         best.Result.Summary.PathID,
			ConnectionType: best.Result.Summary.ConnectionType,
			LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
			RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
			Reason:         s.cfg.PeerID,
		})
	}

	// Send path commit
	if err := s.sendPathCommit(ctx, *best.Result); err != nil {
		if s.cfg.Binder != nil {
			s.ignoreCleanupError(s.runCleanupWithContext(func(cleanupCtx context.Context) error {
				return s.cfg.Binder.Unbind(cleanupCtx, s.cfg.PeerID)
			}))
		}
		s.closeRetainedOutcomes()
		s.ignoreCleanupError(s.runCleanup(best.Result.Transport.Close))
		s.lastRes.Transport = nil
		return err
	}
	s.emitObservation(ctx, solver.Observation{
		Strategy:       best.Plan.Strategy,
		PlanID:         best.Plan.ID,
		Event:          "path_committed",
		PathID:         best.Result.Summary.PathID,
		ConnectionType: best.Result.Summary.ConnectionType,
		LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
		RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
		Details:        pathSummaryObservationDetails(best.Result.Summary, nil),
	})

	s.transition(StateBound)
	if s.cfg.Hooks.OnBound != nil {
		s.cfg.Hooks.OnBound(*best.Result)
	}
	return nil
}

func (s *Session) shouldProtectDirectStandby() bool {
	policy := s.cfg.PathPolicy
	return policy.MultipathEnabled && policy.ProtectDirect
}

func (s *Session) bindProtectedDirectImprovement(ctx context.Context, outcomes []solver.CandidateOutcome) error {
	if desiredMultipathPathCount(s.cfg.PathPolicy) <= 1 {
		protected := selectProtectedDirectOutcome(outcomes, s.cfg.PathPolicy)
		return s.bindOutcomeSet(ctx, outcomes, protected)
	}
	current := s.currentBoundOutcome()
	if current == nil {
		protected := selectProtectedDirectOutcome(outcomes, s.cfg.PathPolicy)
		return s.bindOutcomeSet(ctx, outcomes, protected)
	}
	combined := prependOutcomeIfMissing(outcomes, *current)
	return s.bindOutcomeSet(ctx, combined, current)
}

func (s *Session) prependCurrentBoundOutcome(outcomes []solver.CandidateOutcome) []solver.CandidateOutcome {
	current := s.currentBoundOutcome()
	if current == nil {
		return outcomes
	}
	return prependOutcomeIfMissing(outcomes, *current)
}

func prependOutcomeIfMissing(outcomes []solver.CandidateOutcome, current solver.CandidateOutcome) []solver.CandidateOutcome {
	currentKey := outcomeKey(current)
	for i := range outcomes {
		if outcomeKey(outcomes[i]) == currentKey {
			return outcomes
		}
	}
	combined := make([]solver.CandidateOutcome, 0, len(outcomes)+1)
	combined = append(combined, current)
	combined = append(combined, outcomes...)
	return combined
}

func (s *Session) currentBoundOutcome() *solver.CandidateOutcome {
	if s.lastRes.Transport == nil {
		return nil
	}
	result := s.lastRes
	result.Summary = solver.ClonePathSummary(s.lastRes.Summary)
	plan := s.lastPlan
	if plan.ID == "" && result.Summary.Details != nil {
		plan.ID = result.Summary.Details["plan_id"]
	}
	if plan.Strategy == "" && result.Summary.Details != nil {
		plan.Strategy = result.Summary.Details["strategy"]
	}
	outcome := solver.CandidateOutcome{
		Plan:              plan,
		PlanID:            plan.ID,
		Result:            &result,
		PathID:            result.Summary.PathID,
		BorrowedTransport: true,
	}
	if s.cfg.PathPolicy.MultipathEnabled {
		outcome.Score = solver.ScoreOutcomeWithPolicy(outcome, s.cfg.PathPolicy)
	} else {
		outcome.Score = solver.ScoreOutcome(outcome)
	}
	return &outcome
}

func strategyMayProduceDirect(name string) bool {
	switch strings.TrimSpace(name) {
	case legacyice.StrategyName, tcpframed.StrategyName:
		return true
	default:
		return false
	}
}

func hasRemainingDirectCandidate(candidates []StrategyCandidate) bool {
	for _, candidate := range candidates {
		if strategyMayProduceDirect(candidate.Name) {
			return true
		}
	}
	return false
}

func hasProtectedDirectOutcome(outcomes []solver.CandidateOutcome, policy solver.PathPolicy) bool {
	return selectProtectedDirectOutcome(outcomes, policy) != nil
}

func protectedDirectSearchComplete(outcomes []solver.CandidateOutcome, remaining []StrategyCandidate, policy solver.PathPolicy) bool {
	if len(outcomes) == 0 {
		return false
	}
	if successfulOutcomeCount(outcomes) < desiredMultipathPathCount(policy) && len(remaining) > 0 {
		return false
	}
	if !hasProtectedDirectOutcome(outcomes, policy) && hasRemainingDirectCandidate(remaining) {
		return false
	}
	return true
}

func desiredMultipathPathCount(policy solver.PathPolicy) int {
	if !policy.MultipathEnabled {
		return 1
	}
	if policy.MaxPaths <= 0 {
		return 1
	}
	return policy.MaxPaths
}

func findOutcomeByKey(outcomes []solver.CandidateOutcome, key string) *solver.CandidateOutcome {
	for i := range outcomes {
		if outcomeKey(outcomes[i]) == key {
			return &outcomes[i]
		}
	}
	return nil
}

func findStrategyCandidateForOutcome(candidates []StrategyCandidate, outcome *solver.CandidateOutcome) *StrategyCandidate {
	if outcome == nil {
		return nil
	}
	strategyName := strings.TrimSpace(outcome.Plan.Strategy)
	if strategyName == "" && outcome.Result != nil && outcome.Result.Summary.Details != nil {
		strategyName = strings.TrimSpace(outcome.Result.Summary.Details["strategy"])
	}
	if strategyName == "" {
		return nil
	}
	for i := range candidates {
		if candidates[i].Name == strategyName {
			return &candidates[i]
		}
	}
	return nil
}

func noSuccessfulOutcomeError(outcomes []solver.CandidateOutcome) error {
	var lastErr error
	for i := range outcomes {
		if outcomes[i].Err != nil {
			lastErr = outcomes[i].Err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("session: no successful candidate from %d plans", len(outcomes))
}

func noProtectedDirectOutcomeError(outcomes []solver.CandidateOutcome) error {
	if len(outcomes) == 0 {
		return fmt.Errorf("session: no protected direct candidate outcomes")
	}
	for i := range outcomes {
		if outcomes[i].Err != nil {
			continue
		}
		if outcomes[i].Result != nil {
			return fmt.Errorf("session: no protected direct path among %d successful candidate(s)", countSuccessfulOutcomes(outcomes))
		}
	}
	return noSuccessfulOutcomeError(outcomes)
}

func countSuccessfulOutcomes(outcomes []solver.CandidateOutcome) int {
	return successfulOutcomeCount(outcomes)
}

func successfulOutcomeCount(outcomes []solver.CandidateOutcome) int {
	count := 0
	seen := make(map[string]struct{}, len(outcomes))
	for i := range outcomes {
		if outcomes[i].Result != nil && outcomes[i].Result.Transport != nil {
			key := outcomeKey(outcomes[i])
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			count++
		}
	}
	return count
}

func (s *Session) closeOutcomeTransports(outcomes []solver.CandidateOutcome) {
	for i := range outcomes {
		if outcomes[i].Result != nil && outcomes[i].Result.Transport != nil {
			s.ignoreCleanupError(s.runCleanup(outcomes[i].Result.Transport.Close))
		}
	}
}

func (s *Session) recordStrategyFailure(ctx context.Context, strategyName string, err error, index, total int) {
	s.emitObservation(ctx, solver.Observation{
		Strategy:   strategyName,
		Event:      "strategy_failed",
		ErrorClass: classifyError(err),
		Reason:     err.Error(),
		Details: map[string]string{
			"candidate_index": fmt.Sprintf("%d", index),
			"candidate_total": fmt.Sprintf("%d", total),
		},
	})
}

func (s *Session) recordProtectedDirectAttemptFailure(ctx context.Context, strategyName string, err error, primaryPathID string) {
	s.emitObservation(ctx, solver.Observation{
		Strategy:   strategyName,
		Event:      "protected_direct_attempt_failed",
		ErrorClass: classifyError(err),
		Reason:     err.Error(),
		Details: map[string]string{
			"primary_path_id": primaryPathID,
		},
	})
}

func (s *Session) executeCandidateLoop(ctx context.Context, strategy solver.Strategy, plans []solver.Plan, budget solver.ExecutionBudget) []solver.CandidateOutcome {
	outcomes := make([]solver.CandidateOutcome, 0, len(plans))
	budgetStart := time.Now()

	maxCandidates := budget.MaxCandidates
	if maxCandidates <= 0 || maxCandidates > len(plans) {
		maxCandidates = len(plans)
	}

	for i := 0; i < maxCandidates; {
		// Check time budget
		if budget.TimeBudget > 0 && time.Since(budgetStart) >= budget.TimeBudget {
			break
		}

		groupEnd := parallelHintPlanGroupEnd(plans, i, maxCandidates)
		if groupEnd > i+1 {
			groupPlans := plans[i:groupEnd]
			for j, plan := range groupPlans {
				s.emitObservation(ctx, solver.Observation{
					Strategy:  plan.Strategy,
					PlanID:    plan.ID,
					Event:     "candidate_planned",
					TimeoutMS: durationMS(s.executionTimeout()),
					Details: map[string]string{
						"candidate_index": fmt.Sprintf("%d", i+j),
						"candidate_total": fmt.Sprintf("%d", maxCandidates),
						"execution_mode":  "parallel_hint_family",
						"plan_family":     normalizeStrategyPlanID(plan.ID),
					},
				})
			}
			outcomes = append(outcomes, s.executeCandidateGroup(ctx, strategy, groupPlans)...)
			i = groupEnd
			continue
		}

		plan := plans[i]
		s.emitObservation(ctx, solver.Observation{
			Strategy:  plan.Strategy,
			PlanID:    plan.ID,
			Event:     "candidate_planned",
			TimeoutMS: durationMS(s.executionTimeout()),
			Details: map[string]string{
				"candidate_index": fmt.Sprintf("%d", i),
				"candidate_total": fmt.Sprintf("%d", maxCandidates),
			},
		})
		outcome := s.executeCandidate(ctx, strategy, plan)
		outcomes = append(outcomes, outcome)
		i++
	}

	// Score all outcomes
	for i := range outcomes {
		if s.cfg.PathPolicy.MultipathEnabled {
			outcomes[i].Score = solver.ScoreOutcomeWithPolicy(outcomes[i], s.cfg.PathPolicy)
		} else {
			outcomes[i].Score = solver.ScoreOutcome(outcomes[i])
		}
	}

	return outcomes
}

func parallelHintPlanGroupEnd(plans []solver.Plan, start, maxCandidates int) int {
	if start < 0 || start >= len(plans) || start >= maxCandidates {
		return start
	}
	first := plans[start]
	family := normalizeStrategyPlanID(first.ID)
	if family == "" {
		return start + 1
	}
	hasHint := isHintPlanID(first.ID)
	end := start + 1
	for end < len(plans) && end < maxCandidates {
		plan := plans[end]
		if plan.Strategy != first.Strategy || normalizeStrategyPlanID(plan.ID) != family {
			break
		}
		hasHint = hasHint || isHintPlanID(plan.ID)
		end++
	}
	if end-start <= 1 || !hasHint {
		return start + 1
	}
	return end
}

func annotateResultPath(result solver.Result, plan solver.Plan) solver.Result {
	details := make(map[string]string, len(result.Summary.Details)+2)
	for key, value := range result.Summary.Details {
		details[key] = value
	}
	if _, ok := details["strategy"]; !ok && plan.Strategy != "" {
		details["strategy"] = plan.Strategy
	}
	if _, ok := details["plan_id"]; !ok && plan.ID != "" {
		details["plan_id"] = plan.ID
	}
	result.Summary.Details = details
	return result
}

func (s *Session) executeCandidate(ctx context.Context, strategy solver.Strategy, plan solver.Plan) solver.CandidateOutcome {
	startTime := time.Now()
	initialObsCount := s.localObservationCount()
	outcome := solver.CandidateOutcome{
		Plan:   plan,
		PlanID: plan.ID,
	}

	s.transition(StateExecuting)
	execCtx := ctx
	if execCtx == nil {
		execCtx = s.runContext()
	}
	if execCtx == nil {
		execCtx = context.Background()
	}
	if timeout := s.executionTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(execCtx, timeout)
		defer cancel()
	}

	result, err := s.executePlan(execCtx, strategy, plan)
	outcome.FinishedAt = time.Now()
	outcome.ExecutionDur = time.Since(startTime)
	outcome.ObservationCount = s.localObservationCount() - initialObsCount

	if err != nil {
		outcome.Err = err
		outcome.ErrorClass = classifyError(err)
		return outcome
	}

	outcome.Result = &result
	outcome.PathID = result.Summary.PathID
	return outcome
}

func (s *Session) executeCandidateGroup(ctx context.Context, strategy solver.Strategy, plans []solver.Plan) []solver.CandidateOutcome {
	if len(plans) == 0 {
		return nil
	}
	factory, ok := strategy.(solver.ExecutorFactory)
	if !ok || len(plans) == 1 {
		outcomes := make([]solver.CandidateOutcome, 0, len(plans))
		for _, plan := range plans {
			outcomes = append(outcomes, s.executeCandidate(ctx, strategy, plan))
		}
		return outcomes
	}

	startTime := time.Now()
	initialObsCount := s.localObservationCount()
	outcomes := make([]solver.CandidateOutcome, len(plans))
	entries := make([]activePlanExecutorEntry, 0, len(plans))
	for i, plan := range plans {
		outcomes[i] = solver.CandidateOutcome{
			Plan:   plan,
			PlanID: plan.ID,
		}
		executor, err := factory.NewExecutor(plan)
		if err != nil {
			outcomes[i].Err = err
			outcomes[i].ErrorClass = classifyError(err)
			outcomes[i].FinishedAt = time.Now()
			outcomes[i].ExecutionDur = time.Since(startTime)
			continue
		}
		entries = append(entries, activePlanExecutorEntry{
			index:    i,
			planID:   plan.ID,
			executor: executor,
		})
	}
	if len(entries) == 0 {
		return outcomes
	}

	familyPlan := normalizeStrategyPlanID(plans[0].ID)
	group := &activePlanExecutorGroup{
		familyPlanID: familyPlan,
		entries:      entries,
	}
	s.transition(StateExecuting)
	s.setActiveExecutor(familyPlan, group)
	defer func() {
		s.clearActiveExecutor(group)
		s.discardPendingStrategyMessagesForPlanFamily(familyPlan)
		s.ignoreCleanupError(s.runCleanup(group.Close))
	}()

	execCtx := ctx
	if execCtx == nil {
		execCtx = s.runContext()
	}
	if execCtx == nil {
		execCtx = context.Background()
	}
	if timeout := s.executionTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(execCtx, timeout)
		defer cancel()
	}
	groupCtx, cancelGroup := context.WithCancel(execCtx)
	defer cancelGroup()

	if err := s.flushPendingStrategyMessages(groupCtx, group, familyPlan); err != nil {
		finished := time.Now()
		for _, entry := range entries {
			outcomes[entry.index].Err = err
			outcomes[entry.index].ErrorClass = classifyError(err)
			outcomes[entry.index].FinishedAt = finished
			outcomes[entry.index].ExecutionDur = finished.Sub(startTime)
			outcomes[entry.index].ObservationCount = s.localObservationCount() - initialObsCount
		}
		return outcomes
	}

	type executorResult struct {
		index      int
		result     solver.Result
		err        error
		finishedAt time.Time
	}
	resultCh := make(chan executorResult, len(entries))
	var wg sync.WaitGroup
	for _, entry := range entries {
		entry := entry
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := entry.executor.Execute(groupCtx, s.io)
			resultCh <- executorResult{
				index:      entry.index,
				result:     result,
				err:        err,
				finishedAt: time.Now(),
			}
		}()
	}
	for remaining := len(entries); remaining > 0; remaining-- {
		item := <-resultCh
		outcome := &outcomes[item.index]
		outcome.FinishedAt = item.finishedAt
		outcome.ExecutionDur = item.finishedAt.Sub(startTime)
		outcome.ObservationCount = s.localObservationCount() - initialObsCount
		if item.err != nil {
			outcome.Err = item.err
			outcome.ErrorClass = classifyError(item.err)
			continue
		}
		outcome.Result = &item.result
		outcome.PathID = item.result.Summary.PathID
		cancelGroup()
	}
	wg.Wait()
	return outcomes
}

func (s *Session) executePlan(ctx context.Context, strategy solver.Strategy, plan solver.Plan) (solver.Result, error) {
	factory, ok := strategy.(solver.ExecutorFactory)
	if !ok {
		return strategy.Execute(ctx, s.io, plan)
	}

	executor, err := factory.NewExecutor(plan)
	if err != nil {
		return solver.Result{}, err
	}
	s.setActiveExecutor(plan.ID, executor)
	defer func() {
		s.clearActiveExecutor(executor)
		s.discardPendingStrategyMessagesForPlan(plan.ID)
		s.ignoreCleanupError(s.runCleanup(executor.Close))
	}()
	if err := s.flushPendingStrategyMessages(ctx, executor, plan.ID); err != nil {
		return solver.Result{}, err
	}
	return executor.Execute(ctx, s.io)
}

func (s *Session) buildSolveInput() solver.SolveInput {
	return solver.SolveInput{
		SessionID:          s.cfg.SessionID,
		LocalNodeID:        s.cfg.LocalNodeID,
		RemoteNodeID:       s.cfg.PeerID,
		Initiator:          s.cfg.Initiator,
		LocalCapability:    s.localCapability(),
		RemoteCapability:   s.remoteCapability(),
		LocalObservations:  s.localObservationHistory(),
		RemoteObservations: s.RemoteObservations(),
		LastProbeResult:    s.lastProbeResultSummary(),
	}
}

func (s *Session) refinePlans(ctx context.Context, strategy solver.Strategy, input solver.SolveInput, plans []solver.Plan) ([]solver.Plan, string) {
	refined := append([]solver.Plan(nil), plans...)
	refiner, ok := strategy.(solver.PlanRefiner)
	if !ok {
		return refined, "no_refinement"
	}
	result, err := refiner.RefinePlans(ctx, input, refined)
	if err != nil {
		return refined, fmt.Sprintf("refiner_error:%s", err.Error())
	}
	if len(result.Plans) == 0 {
		return result.Plans, strings.TrimSpace(result.Reason)
	}
	if !isPlanSubset(plans, result.Plans) {
		return refined, "refiner_invalid_set"
	}
	reason := strings.TrimSpace(result.Reason)
	if reason == "" {
		reason = "strategy_refined"
	}
	return append([]solver.Plan(nil), result.Plans...), reason
}

func (s *Session) rankPlans(ctx context.Context, strategy solver.Strategy, plans []solver.Plan) ([]solver.Plan, string) {
	ordered := append([]solver.Plan(nil), plans...)
	ranker, ok := strategy.(solver.PlanRanker)
	if !ok {
		return ordered, "strategy_default"
	}

	ranked, err := ranker.RankPlans(ctx, solver.RankInput{
		SessionID:          s.cfg.SessionID,
		LocalNodeID:        s.cfg.LocalNodeID,
		RemoteNodeID:       s.cfg.PeerID,
		Initiator:          s.cfg.Initiator,
		RemoteCapability:   s.remoteCapability(),
		LocalObservations:  s.localObservationHistory(),
		RemoteObservations: s.RemoteObservations(),
		LastProbeResult:    s.lastProbeResultSummary(),
	}, ordered)
	if err != nil {
		return ordered, fmt.Sprintf("ranker_error:%s", err.Error())
	}
	if len(ranked.Plans) != len(plans) {
		return ordered, "ranker_invalid_length"
	}
	if !samePlanSet(plans, ranked.Plans) {
		return ordered, "ranker_invalid_set"
	}
	reason := strings.TrimSpace(ranked.Reason)
	if reason == "" {
		reason = "strategy_ranked"
	}
	return append([]solver.Plan(nil), ranked.Plans...), reason
}

func (s *Session) recordPlanOrder(plans []solver.Plan, reason string) {
	s.metaMu.Lock()
	s.meta.LastPlanOrder = planIDs(plans)
	s.meta.LastPlanOrderReason = reason
	s.metaMu.Unlock()
}

func (s *Session) recordStrategyOrder(ctx context.Context, candidates []StrategyCandidate) {
	names := strategyCandidateNames(candidates)
	reason := strategyCandidateOrderReason(candidates)
	s.metaMu.Lock()
	s.meta.LastStrategyOrder = names
	s.meta.LastStrategyOrderReason = reason
	s.metaMu.Unlock()

	strategy := ""
	if len(names) > 0 {
		strategy = names[0]
	}
	s.emitObservation(ctx, solver.Observation{
		Strategy: strategy,
		Event:    "strategy_ordered",
		Reason:   reason,
		Details: map[string]string{
			"order": strings.Join(names, ","),
		},
	})
}

func (s *Session) recordPlanRefine(before, after []string, reason string) {
	s.metaMu.Lock()
	s.meta.LastPlanSetBeforeRefine = append([]string(nil), before...)
	s.meta.LastPlanSetAfterRefine = append([]string(nil), after...)
	s.meta.LastPlanRefineReason = reason
	s.metaMu.Unlock()
}

func planIDs(plans []solver.Plan) []string {
	out := make([]string, 0, len(plans))
	for _, plan := range plans {
		out = append(out, plan.ID)
	}
	return out
}

func strategyCandidateNames(candidates []StrategyCandidate) []string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.Name)
	}
	return out
}

func strategyCandidateOrderReason(candidates []StrategyCandidate) string {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Reason) != "" {
			return candidate.Reason
		}
	}
	return "resolver_order"
}

func samePlanSet(left, right []solver.Plan) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, plan := range left {
		counts[plan.ID]++
	}
	for _, plan := range right {
		counts[plan.ID]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func isPlanSubset(original, refined []solver.Plan) bool {
	counts := make(map[string]int, len(original))
	for _, plan := range original {
		counts[plan.ID]++
	}
	for _, plan := range refined {
		counts[plan.ID]--
		if counts[plan.ID] < 0 {
			return false
		}
	}
	return true
}
