package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

func (s *Session) selectAndExecute(ctx context.Context) error {
	strategy, err := s.selectStrategy(ctx)
	if err != nil {
		return err
	}

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
		return err
	}
	if len(plans) == 0 {
		return fmt.Errorf("session: strategy %s returned no plans", strategy.Name())
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
		return fmt.Errorf("session: all plans pruned after refinement")
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
		if err := s.flushPendingStrategyMessages(ctx, handler); err != nil {
			return err
		}
	}

	// Execute candidate loop with budget
	budget := solver.DefaultBudget()
	outcomes := s.executeCandidateLoop(ctx, strategy, plans, budget)

	// Select best outcome
	best := solver.SelectBestOutcome(outcomes)
	if best == nil {
		// Collect error info from all outcomes
		var lastErr error
		for _, o := range outcomes {
			if o.Err != nil {
				lastErr = o.Err
			}
		}
		if lastErr != nil {
			s.fail(lastErr)
		} else {
			s.fail(fmt.Errorf("session: no successful candidate from %d plans", len(plans)))
		}
		return nil
	}

	// Mark selected
	best.Selected = true
	best.SelectionReason = "highest_score"
	s.lastPlan = best.Plan
	s.lastRes = *best.Result
	s.emitObservation(ctx, solver.Observation{
		Strategy:       best.Plan.Strategy,
		PlanID:         best.Plan.ID,
		Event:          "path_selected",
		PathID:         best.Result.Summary.PathID,
		ConnectionType: best.Result.Summary.ConnectionType,
		LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
		RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
		Reason:         best.SelectionReason,
		Details: map[string]string{
			"score": fmt.Sprintf("%d", best.Score),
		},
	})

	// Clean up non-selected transports
	for i := range outcomes {
		if !outcomes[i].Selected && outcomes[i].Result != nil && outcomes[i].Result.Transport != nil {
			s.ignoreCleanupError(s.runCleanup(outcomes[i].Result.Transport.Close))
		}
	}

	s.transition(StateBinding)

	// Bind the winner
	if s.cfg.Binder != nil {
		bindCtx, cancel := s.operationContext(ctx)
		err := s.cfg.Binder.Bind(bindCtx, s.cfg.PeerID, best.Result.Transport)
		cancel()
		if err != nil {
			s.ignoreCleanupError(s.runCleanup(best.Result.Transport.Close))
			s.fail(err)
			return nil
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
		s.ignoreCleanupError(s.runCleanup(best.Result.Transport.Close))
		s.lastRes.Transport = nil
		s.fail(err)
		return nil
	}
	s.emitObservation(ctx, solver.Observation{
		Strategy:       best.Plan.Strategy,
		PlanID:         best.Plan.ID,
		Event:          "path_committed",
		PathID:         best.Result.Summary.PathID,
		ConnectionType: best.Result.Summary.ConnectionType,
		LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
		RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
	})

	s.transition(StateBound)
	if s.cfg.Hooks.OnBound != nil {
		s.cfg.Hooks.OnBound(*best.Result)
	}
	return nil
}

func (s *Session) executeCandidateLoop(ctx context.Context, strategy solver.Strategy, plans []solver.Plan, budget solver.ExecutionBudget) []solver.CandidateOutcome {
	outcomes := make([]solver.CandidateOutcome, 0, len(plans))
	budgetStart := time.Now()

	maxCandidates := budget.MaxCandidates
	if maxCandidates <= 0 || maxCandidates > len(plans) {
		maxCandidates = len(plans)
	}

	for i := 0; i < maxCandidates; i++ {
		plan := plans[i]

		// Check time budget
		if budget.TimeBudget > 0 && time.Since(budgetStart) >= budget.TimeBudget {
			break
		}

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
	}

	// Score all outcomes
	for i := range outcomes {
		outcomes[i].Score = solver.ScoreOutcome(outcomes[i])
	}

	return outcomes
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
		s.discardPendingStrategyMessages()
		s.ignoreCleanupError(s.runCleanup(executor.Close))
	}()
	if err := s.flushPendingStrategyMessages(ctx, executor); err != nil {
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
