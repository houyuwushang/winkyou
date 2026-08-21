package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

func TestSimulationOnlyV2BoundaryDetectsNoiseCoreProductionImporter(t *testing.T) {
	noiseCore := modulePath + "/internal/v2/noisecore"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/cmd/wink": {imports: map[string]struct{}{noiseCore: {}}},
	}}
	violations := simulationOnlyV2DependencyViolations(result)
	want := modulePath + "/cmd/wink imports simulation-only " + noiseCore
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestSimulationOnlyV2BoundaryAllowsPunchSimToUseNoiseCore(t *testing.T) {
	punchSim := modulePath + "/internal/v2/punchsim"
	noiseCore := modulePath + "/internal/v2/noisecore"
	result := scanResult{packages: map[string]*packageInfo{
		punchSim: {imports: map[string]struct{}{noiseCore: {}}},
	}}
	if violations := simulationOnlyV2DependencyViolations(result); len(violations) != 0 {
		t.Fatalf("simulation-only dependency produced violations: %v", violations)
	}
}

func TestSimulationOnlyV2BoundaryKeepsNoiseCoreIndependent(t *testing.T) {
	noiseCore := modulePath + "/internal/v2/noisecore"
	testPairing := modulePath + "/internal/v2/testpairing"
	result := scanResult{packages: map[string]*packageInfo{
		noiseCore: {imports: map[string]struct{}{testPairing: {}}},
	}}
	violations := simulationOnlyV2DependencyViolations(result)
	want := noiseCore + " imports forbidden WinkYou dependency " + testPairing
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestNoiseCoreDoesNotImportNetworkPackages(t *testing.T) {
	directory := filepath.Join(repositoryRoot(t), "internal", "v2", "noisecore")
	violations, err := noiseCoreNetworkImportViolations(directory)
	if err != nil {
		t.Fatalf("scan noisecore imports: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("noisecore gained a network import:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestNoiseCoreNetworkImportGateDetectsNet(t *testing.T) {
	directory := t.TempDir()
	source := []byte("package noisecore\nimport \"net\"\nvar _ net.Conn\n")
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatalf("write injected source: %v", err)
	}
	violations, err := noiseCoreNetworkImportViolations(directory)
	if err != nil {
		t.Fatalf("scan injected imports: %v", err)
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "imports net") {
		t.Fatalf("violations = %v, want injected net import", violations)
	}
}

func simulationOnlyV2DependencyViolations(result scanResult) []string {
	testPairing := modulePath + "/internal/v2/testpairing"
	punchSim := modulePath + "/internal/v2/punchsim"
	noiseCore := modulePath + "/internal/v2/noisecore"
	simulationOnlyPackages := map[string]struct{}{
		testPairing: {},
		punchSim:    {},
		noiseCore:   {},
	}
	forbiddenPunchSimImports := map[string]struct{}{
		modulePath + "/internal/natsim":         {},
		modulePath + "/internal/probeio":        {},
		modulePath + "/internal/v2/testpairing": {},
	}
	var violations []string
	for importer, info := range result.packages {
		for imported := range info.imports {
			switch {
			case importer == noiseCore && strings.HasPrefix(imported, modulePath+"/"):
				violations = append(violations, importer+" imports forbidden WinkYou dependency "+imported)
			case importer == punchSim && containsImportOrChild(forbiddenPunchSimImports, imported):
				violations = append(violations, importer+" imports forbidden simulation dependency "+imported)
			case containsImportOrChild(simulationOnlyPackages, imported) && !containsImportOrChild(simulationOnlyPackages, importer):
				violations = append(violations, importer+" imports simulation-only "+imported)
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func noiseCoreNetworkImportViolations(directory string) ([]string, error) {
	var violations []string
	err := filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if path == "net" || strings.HasPrefix(path, "net/") {
				violations = append(violations, filepath.ToSlash(filename)+" imports "+path)
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func containsImportOrChild(roots map[string]struct{}, imported string) bool {
	for root := range roots {
		if imported == root || strings.HasPrefix(imported, root+"/") {
			return true
		}
	}
	return false
}
