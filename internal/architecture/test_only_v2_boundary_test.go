package architecture

import (
	"sort"
	"strings"
	"testing"
)

func TestSimulationOnlyV2PackagesStayOutOfProductionPaths(t *testing.T) {
	result, err := scanRepository(repositoryRoot(t))
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}

	violations := simulationOnlyV2DependencyViolations(result)
	if len(violations) > 0 {
		t.Fatalf("simulation-only v2 dependency escaped into a production path:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestSimulationOnlyV2BoundaryDetectsNewProductionImporter(t *testing.T) {
	punchSim := modulePath + "/internal/v2/punchsim"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/pkg/runtime": {imports: map[string]struct{}{punchSim: {}}},
	}}
	violations := simulationOnlyV2DependencyViolations(result)
	want := modulePath + "/pkg/runtime imports simulation-only " + punchSim
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestSimulationOnlyV2BoundaryDetectsPunchSimCapabilityDependency(t *testing.T) {
	punchSim := modulePath + "/internal/v2/punchsim"
	probeIO := modulePath + "/internal/probeio"
	result := scanResult{packages: map[string]*packageInfo{
		punchSim: {imports: map[string]struct{}{probeIO: {}}},
	}}
	violations := simulationOnlyV2DependencyViolations(result)
	want := punchSim + " imports forbidden simulation dependency " + probeIO
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func simulationOnlyV2DependencyViolations(result scanResult) []string {
	testPairing := modulePath + "/internal/v2/testpairing"
	punchSim := modulePath + "/internal/v2/punchsim"
	forbiddenPunchSimImports := map[string]struct{}{
		modulePath + "/internal/natsim":         {},
		modulePath + "/internal/probeio":        {},
		modulePath + "/internal/v2/testpairing": {},
	}
	var violations []string
	for importer, info := range result.packages {
		for imported := range info.imports {
			switch {
			case importer == punchSim && containsImportOrChild(forbiddenPunchSimImports, imported):
				violations = append(violations, importer+" imports forbidden simulation dependency "+imported)
			case imported == punchSim && importer != punchSim:
				violations = append(violations, importer+" imports simulation-only "+imported)
			case imported == testPairing && importer != testPairing:
				violations = append(violations, importer+" imports simulation-only "+imported)
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func containsImportOrChild(roots map[string]struct{}, imported string) bool {
	for root := range roots {
		if imported == root || strings.HasPrefix(imported, root+"/") {
			return true
		}
	}
	return false
}
