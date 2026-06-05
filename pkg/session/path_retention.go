package session

import "winkyou/pkg/solver"

func selectPrimaryOutcome(outcomes []solver.CandidateOutcome, policy solver.PathPolicy) *solver.CandidateOutcome {
	_ = policy
	return solver.SelectBestOutcome(outcomes)
}

func selectProtectedDirectOutcome(outcomes []solver.CandidateOutcome, policy solver.PathPolicy) *solver.CandidateOutcome {
	if !policy.MultipathEnabled || !policy.ProtectDirect {
		return nil
	}
	var selected *solver.CandidateOutcome
	for i := range outcomes {
		outcome := &outcomes[i]
		if !isSuccessfulOutcome(*outcome) || !solver.IsDirectPath(outcome.Result.Summary) {
			continue
		}
		if selected == nil || outcome.Score > selected.Score {
			selected = outcome
		}
	}
	return selected
}

func retainSuccessfulOutcomes(outcomes []solver.CandidateOutcome, selected *solver.CandidateOutcome, policy solver.PathPolicy) []solver.CandidateOutcome {
	if !policy.MultipathEnabled || selected == nil {
		return nil
	}
	maxPaths := policy.MaxPaths
	if maxPaths <= 0 {
		maxPaths = 1
	}
	if maxPaths <= 1 {
		return nil
	}

	retained := make([]solver.CandidateOutcome, 0, maxPaths-1)
	add := func(outcome *solver.CandidateOutcome) {
		if outcome == nil || outcome == selected || !isSuccessfulOutcome(*outcome) {
			return
		}
		for i := range retained {
			if outcomeKey(retained[i]) == outcomeKey(*outcome) {
				return
			}
		}
		retained = append(retained, *outcome)
	}

	add(selectProtectedDirectOutcome(outcomes, policy))
	for i := range outcomes {
		if len(retained) >= maxPaths-1 {
			break
		}
		add(&outcomes[i])
	}
	if len(retained) == 0 {
		return nil
	}
	return retained
}

func (s *Session) setRetainedOutcomes(outcomes []solver.CandidateOutcome) {
	s.closeRetainedOutcomes()
	if len(outcomes) == 0 {
		return
	}
	s.retained = append([]solver.CandidateOutcome(nil), outcomes...)
}

func (s *Session) closeUnusedOutcomes(outcomes []solver.CandidateOutcome, selected *solver.CandidateOutcome, retained []solver.CandidateOutcome) {
	retainedKeys := make(map[string]struct{}, len(retained))
	for i := range retained {
		retainedKeys[outcomeKey(retained[i])] = struct{}{}
	}
	for i := range outcomes {
		outcome := &outcomes[i]
		if outcome == selected {
			continue
		}
		if _, ok := retainedKeys[outcomeKey(*outcome)]; ok {
			continue
		}
		if outcome.Result != nil && outcome.Result.Transport != nil {
			s.ignoreCleanupError(s.runCleanup(outcome.Result.Transport.Close))
		}
	}
}

func (s *Session) closeRetainedOutcomes() {
	if len(s.retained) == 0 {
		return
	}
	retained := s.retained
	s.retained = nil
	for i := range retained {
		if retained[i].Result != nil && retained[i].Result.Transport != nil {
			s.ignoreCleanupError(s.runCleanup(retained[i].Result.Transport.Close))
		}
	}
}

func isSuccessfulOutcome(outcome solver.CandidateOutcome) bool {
	return outcome.Err == nil && outcome.Result != nil && outcome.Result.Transport != nil
}

func outcomeKey(outcome solver.CandidateOutcome) string {
	if outcome.PathID != "" {
		return outcome.PathID
	}
	if outcome.Result != nil && outcome.Result.Summary.PathID != "" {
		return outcome.Result.Summary.PathID
	}
	if outcome.PlanID != "" {
		return outcome.PlanID
	}
	return outcome.Plan.ID
}
