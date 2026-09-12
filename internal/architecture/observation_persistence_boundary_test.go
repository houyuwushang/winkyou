package architecture

import (
	"strings"
	"testing"
)

func observationPersistenceViolations(sources map[string]string) []string {
	var violations []string
	init := selectionFunction(sources["pkg/client/engine.go"], "initObservationStore")
	if !strings.Contains(init, "solverstore.NewBufferedObservationStore(e.observationStorePath(), e.removeObservationState)") || strings.Contains(init, "solverstore.NewObservationStore(") {
		violations = append(violations, "client observation sink must opt into bounded persistence")
	}
	return violations
}

func TestObservationPersistenceProductionBoundary(t *testing.T) {
	if violations := observationPersistenceViolations(selectionProductionSources(t)); len(violations) != 0 {
		t.Fatal(strings.Join(violations, "\n"))
	}
}
