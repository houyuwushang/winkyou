package session

import (
	"fmt"
	"strings"

	"winkyou/pkg/solver"
	"winkyou/pkg/transport/multipath"
)

func buildResultTransportFromOutcomes(best *solver.CandidateOutcome, outcomes []solver.CandidateOutcome, policy solver.PathPolicy) (solver.Result, []func() error) {
	if best == nil || best.Result == nil || !policy.MultipathEnabled {
		if best != nil && best.Result != nil {
			return *best.Result, nil
		}
		return solver.Result{}, nil
	}

	retained := retainSuccessfulOutcomes(outcomes, best, policy)
	if len(retained) == 0 {
		return *best.Result, nil
	}

	children := make([]solver.CandidateOutcome, 0, len(retained)+1)
	children = append(children, *best)
	children = append(children, retained...)
	paths := make([]multipath.Path, 0, len(children))
	primaryKey := outcomeKey(*best)
	for i := range children {
		outcome := children[i]
		if !isSuccessfulOutcome(outcome) {
			continue
		}
		priority := 100 - i
		if outcomeKey(outcome) == primaryKey {
			priority = 100
		}
		paths = append(paths, multipath.Path{
			ID:        resultPathID(*outcome.Result),
			Role:      outcome.Result.Summary.Role,
			Summary:   solver.ClonePathSummary(outcome.Result.Summary),
			Transport: outcome.Result.Transport,
			Priority:  priority,
			Borrowed:  outcome.BorrowedTransport,
		})
	}
	if len(paths) <= 1 {
		return *best.Result, nil
	}

	wrapper, err := multipath.New(paths, policy)
	if err != nil {
		return *best.Result, nil
	}

	result := *best.Result
	result.Transport = wrapper
	result.Summary = multipathSummary(best.Result.Summary, paths)
	return result, nil
}

func multipathSummary(primary solver.PathSummary, paths []multipath.Path) solver.PathSummary {
	summary := solver.ClonePathSummary(primary)
	primaryPathID := summary.PathID
	if primaryPathID == "" {
		primaryPathID = paths[0].ID
	}
	summary.PathID = "multipath:" + primaryPathID
	details := cloneStringMap(summary.Details)
	if details == nil {
		details = map[string]string{}
	}
	details["multipath"] = "true"
	details["primary_path_id"] = primaryPathID
	details["child_path_count"] = fmt.Sprintf("%d", len(paths))

	standbyIDs := make([]string, 0, len(paths)-1)
	childSummaries := make([]string, 0, len(paths))
	for i := range paths {
		childSummaries = append(childSummaries, compactPathSummary(paths[i]))
		pathSummary := paths[i].Summary
		if pathSummary.Role == "" {
			pathSummary.Role = paths[i].Role
		}
		if solver.IsProtectedDirectPath(pathSummary) && details["protected_direct_path_id"] == "" {
			details["protected_direct_path_id"] = paths[i].ID
		}
		if i > 0 {
			standbyIDs = append(standbyIDs, paths[i].ID)
		}
	}
	if len(standbyIDs) > 0 {
		details["standby_path_ids"] = strings.Join(standbyIDs, ",")
	}
	if len(childSummaries) > 0 {
		details["child_paths"] = strings.Join(childSummaries, ";")
	}
	summary.Details = details
	return summary
}

func compactPathSummary(path multipath.Path) string {
	summary := solver.ClonePathSummary(path.Summary)
	if summary.Role == "" {
		summary.Role = path.Role
	}
	parts := []string{"id=" + path.ID}
	if summary.Role != "" {
		parts = append(parts, "role="+string(summary.Role))
	}
	if len(summary.Dependencies) == 0 {
		parts = append(parts, "deps=none")
	} else {
		deps := make([]string, 0, len(summary.Dependencies))
		for _, dependency := range summary.Dependencies {
			if dependency.Kind == "" {
				continue
			}
			value := string(dependency.Kind)
			if dependency.Reason != "" {
				value += ":" + dependency.Reason
			}
			deps = append(deps, value)
		}
		if len(deps) > 0 {
			parts = append(parts, "deps="+strings.Join(deps, "|"))
		}
	}
	return strings.Join(parts, ",")
}

func resultPathID(result solver.Result) string {
	if result.Summary.PathID != "" {
		return result.Summary.PathID
	}
	return addrString(result.Summary.RemoteAddr)
}

func isMultipathResult(result solver.Result) bool {
	return result.Summary.Details != nil && result.Summary.Details["multipath"] == "true"
}
