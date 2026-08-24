package architecture

import (
	"go/ast"
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

	violations := v2RestrictedDependencyViolations(result)
	if len(violations) > 0 {
		t.Fatalf("simulation-only v2 dependency escaped into a production path:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestSimulationOnlyV2BoundaryDetectsNewProductionImporter(t *testing.T) {
	punchSim := modulePath + "/internal/v2/punchsim"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/pkg/runtime": {imports: map[string]struct{}{punchSim: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := modulePath + "/pkg/runtime imports simulation-only " + punchSim
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestN1IntegrationHarnessStaysOutOfProductionPaths(t *testing.T) {
	result, err := scanRepository(repositoryRoot(t))
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}

	violations := n1IntegrationBoundaryViolations(result)
	if len(violations) > 0 {
		t.Fatalf("N1 integration-only dependency escaped into a production path:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestN1IntegrationBoundaryDetectsProductionImporter(t *testing.T) {
	natlab := modulePath + "/test/natlab"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/cmd/wink": {imports: map[string]struct{}{natlab: {}}},
	}}
	violations := n1IntegrationBoundaryViolations(result)
	want := modulePath + "/cmd/wink imports integration-only " + natlab
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestN1HarnessImplementationFilesAreTestsOnly(t *testing.T) {
	directory := filepath.Join(repositoryRoot(t), "test", "natlab")
	violations, err := n1HarnessSourceViolations(directory)
	if err != nil {
		t.Fatalf("scan N1 harness sources: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("N1 harness gained a product-importable source:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestN1HarnessTestsOnlyGateDetectsProductionSource(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "n1_escape.go"), []byte("package natlab\n"), 0o600); err != nil {
		t.Fatalf("write injected N1 source: %v", err)
	}
	violations, err := n1HarnessSourceViolations(directory)
	if err != nil {
		t.Fatalf("scan injected N1 source: %v", err)
	}
	if len(violations) != 1 || violations[0] != "n1_escape.go is not test-only" {
		t.Fatalf("violations = %v, want injected production source", violations)
	}
}

func TestN1NatlabGovernorHelperStaysOutOfProductionSources(t *testing.T) {
	root := repositoryRoot(t)
	helperPath := filepath.Join(root, "internal", "governor", "n1_natlab_linux.go")
	payload, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatalf("read N1 governor helper: %v", err)
	}
	normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
	if !strings.HasPrefix(normalized, "//go:build linux && natlab\n") {
		t.Fatal("N1 governor helper lost its exact linux && natlab build constraint")
	}
	violations, err := n1GovernorHelperUseViolations(root)
	if err != nil {
		t.Fatalf("scan N1 governor helper uses: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("N1 governor helper escaped into production sources:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestN1NatlabGovernorHelperGateDetectsProductionUse(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cmd", "wink")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create injected production directory: %v", err)
	}
	source := []byte("package main\nimport gov \"winkyou/internal/governor\"\nfunc bypass() { _, _ = gov.PrepareN1TestNamespace(\"x\", time.Time{}) }\n")
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatalf("write injected governor helper use: %v", err)
	}
	violations, err := n1GovernorHelperUseViolations(root)
	if err != nil {
		t.Fatalf("scan injected governor helper use: %v", err)
	}
	if len(violations) != 1 || violations[0] != "cmd/wink/bypass.go uses N1 natlab governor helper" {
		t.Fatalf("violations = %v, want injected N1 helper use", violations)
	}
}

func TestSimulationOnlyV2BoundaryDetectsPunchSimCapabilityDependency(t *testing.T) {
	punchSim := modulePath + "/internal/v2/punchsim"
	probeIO := modulePath + "/internal/probeio"
	result := scanResult{packages: map[string]*packageInfo{
		punchSim: {imports: map[string]struct{}{probeIO: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := punchSim + " imports forbidden simulation dependency " + probeIO
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestLoopbackCarrierBoundaryDetectsNoiseCoreProductionImporter(t *testing.T) {
	noiseCore := modulePath + "/internal/v2/noisecore"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/cmd/wink": {imports: map[string]struct{}{noiseCore: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := modulePath + "/cmd/wink imports loopback-carrier-approved " + noiseCore + " without approval"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestDirectAttemptBoundaryDetectsProductionImporter(t *testing.T) {
	directAttempt := modulePath + "/internal/v2/directattempt"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/cmd/wink": {imports: map[string]struct{}{directAttempt: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := modulePath + "/cmd/wink imports zero-network direct-attempt " + directAttempt + " without approval"
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
	if violations := v2RestrictedDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("simulation-only dependency produced violations: %v", violations)
	}
}

func TestSimulationOnlyV2BoundaryKeepsNoiseCoreIndependent(t *testing.T) {
	noiseCore := modulePath + "/internal/v2/noisecore"
	testPairing := modulePath + "/internal/v2/testpairing"
	result := scanResult{packages: map[string]*packageInfo{
		noiseCore: {imports: map[string]struct{}{testPairing: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
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

func TestPunchProtoDoesNotImportNetworkPackages(t *testing.T) {
	directory := filepath.Join(repositoryRoot(t), "internal", "v2", "punchproto")
	violations, err := noiseCoreNetworkImportViolations(directory)
	if err != nil {
		t.Fatalf("scan punchproto imports: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("punchproto gained a network import:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestDirectAttemptOwnsNoNetworkCapability(t *testing.T) {
	directory := filepath.Join(repositoryRoot(t), "internal", "v2", "directattempt")
	violations, err := directAttemptImportViolations(directory)
	if err != nil {
		t.Fatalf("scan directattempt imports: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("directattempt gained a network-capable import:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestDirectAttemptNetworkGateDetectsRawNet(t *testing.T) {
	directory := t.TempDir()
	source := []byte("package directattempt\nimport \"net\"\nvar _ net.Conn\n")
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatalf("write injected source: %v", err)
	}
	violations, err := directAttemptImportViolations(directory)
	if err != nil {
		t.Fatalf("scan injected imports: %v", err)
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "imports net") {
		t.Fatalf("violations = %v, want injected net import", violations)
	}
}

func TestLoopbackCarrierApprovalIsExactAndBidirectional(t *testing.T) {
	carrier := modulePath + "/internal/v2/loopbackcarrier"
	punchSim := modulePath + "/internal/v2/punchsim"
	punchProto := modulePath + "/internal/v2/punchproto"
	noiseCore := modulePath + "/internal/v2/noisecore"
	pairingContext := modulePath + "/internal/v2/pairingcontext"
	directAttempt := modulePath + "/internal/v2/directattempt"

	checks := []struct {
		importer string
		imported string
		allowed  bool
	}{
		{carrier, punchProto, true},
		{carrier, noiseCore, true},
		{carrier, pairingContext, true},
		{modulePath + "/internal/v2/testpairing", pairingContext, true},
		{punchSim, punchProto, true},
		{punchSim, noiseCore, true},
		{punchProto, noiseCore, true},
		{directAttempt, noiseCore, true},
		{directAttempt, pairingContext, true},
		{carrier + "/child", punchProto, false},
		{carrier + "/child", pairingContext, false},
		{modulePath + "/cmd/wink", punchProto, false},
		{carrier, punchSim, false},
		{modulePath + "/cmd/wink", directAttempt, false},
	}
	for _, check := range checks {
		if actual := approvedLoopbackPrimitiveImporter(check.importer, check.imported); actual != check.allowed {
			t.Errorf("approvedLoopbackPrimitiveImporter(%q, %q) = %t, want %t", check.importer, check.imported, actual, check.allowed)
		}
	}

	result := scanResult{packages: map[string]*packageInfo{
		carrier: {imports: map[string]struct{}{punchProto: {}, noiseCore: {}, pairingContext: {}}},
	}}
	if violations := v2RestrictedDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("exact carrier approval produced violations: %v", violations)
	}
}

func TestLoopbackCarrierBoundaryDetectsNewUnauthorizedImporter(t *testing.T) {
	punchProto := modulePath + "/internal/v2/punchproto"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/pkg/runtime": {imports: map[string]struct{}{punchProto: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := modulePath + "/pkg/runtime imports loopback-carrier-approved " + punchProto + " without approval"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestLoopbackCarrierCannotImportPunchSim(t *testing.T) {
	carrier := modulePath + "/internal/v2/loopbackcarrier"
	punchSim := modulePath + "/internal/v2/punchsim"
	result := scanResult{packages: map[string]*packageInfo{
		carrier: {imports: map[string]struct{}{punchSim: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := carrier + " imports simulation-only " + punchSim
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
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

func v2RestrictedDependencyViolations(result scanResult) []string {
	testPairing := modulePath + "/internal/v2/testpairing"
	punchSim := modulePath + "/internal/v2/punchsim"
	noiseCore := modulePath + "/internal/v2/noisecore"
	punchProto := modulePath + "/internal/v2/punchproto"
	pairingContext := modulePath + "/internal/v2/pairingcontext"
	directAttempt := modulePath + "/internal/v2/directattempt"
	simulationOnlyPackages := map[string]struct{}{
		testPairing: {},
		punchSim:    {},
	}
	loopbackPrimitives := map[string]struct{}{
		noiseCore:      {},
		punchProto:     {},
		pairingContext: {},
	}
	directAttemptPrimitives := map[string]struct{}{
		directAttempt: {},
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
			case importer == punchProto && strings.HasPrefix(imported, modulePath+"/") && imported != noiseCore:
				violations = append(violations, importer+" imports forbidden WinkYou dependency "+imported)
			case importer == directAttempt && strings.HasPrefix(imported, modulePath+"/") && imported != noiseCore && imported != pairingContext:
				violations = append(violations, importer+" imports forbidden WinkYou dependency "+imported)
			case importer == punchSim && containsImportOrChild(forbiddenPunchSimImports, imported):
				violations = append(violations, importer+" imports forbidden simulation dependency "+imported)
			case containsImportOrChild(simulationOnlyPackages, imported) && !containsImportOrChild(simulationOnlyPackages, importer):
				violations = append(violations, importer+" imports simulation-only "+imported)
			case containsImportOrChild(directAttemptPrimitives, imported) && !approvedDirectAttemptImporter(importer, imported):
				violations = append(violations, importer+" imports zero-network direct-attempt "+imported+" without approval")
			case containsImportOrChild(loopbackPrimitives, imported) && !approvedLoopbackPrimitiveImporter(importer, imported):
				violations = append(violations, importer+" imports loopback-carrier-approved "+imported+" without approval")
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func n1IntegrationBoundaryViolations(result scanResult) []string {
	natlab := modulePath + "/test/natlab"
	var violations []string
	for importer, info := range result.packages {
		for imported := range info.imports {
			if (imported == natlab || strings.HasPrefix(imported, natlab+"/")) &&
				importer != natlab && !strings.HasPrefix(importer, natlab+"/") {
				violations = append(violations, importer+" imports integration-only "+imported)
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func n1HarnessSourceViolations(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "n1_") || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			violations = append(violations, entry.Name()+" is not test-only")
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func n1GovernorHelperUseViolations(root string) ([]string, error) {
	const helperName = "PrepareN1TestNamespace"
	var violations []string
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "internal/governor/n1_natlab_linux.go" {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return err
		}
		used := false
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifier.Name == helperName {
				used = true
				return false
			}
			return !used
		})
		if used {
			violations = append(violations, relative+" uses N1 natlab governor helper")
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func approvedLoopbackPrimitiveImporter(importer, imported string) bool {
	punchSim := modulePath + "/internal/v2/punchsim"
	punchProto := modulePath + "/internal/v2/punchproto"
	noiseCore := modulePath + "/internal/v2/noisecore"
	pairingContext := modulePath + "/internal/v2/pairingcontext"
	testPairing := modulePath + "/internal/v2/testpairing"
	carrier := modulePath + "/internal/v2/loopbackcarrier"
	directAttempt := modulePath + "/internal/v2/directattempt"

	switch imported {
	case noiseCore:
		return importer == punchProto || importer == punchSim || importer == carrier || importer == directAttempt
	case punchProto:
		return importer == punchSim || importer == carrier
	case pairingContext:
		return importer == testPairing || importer == carrier || importer == directAttempt
	default:
		return false
	}
}

func approvedDirectAttemptImporter(_, _ string) bool {
	// N2a freezes only a zero-I/O primitive. N2b adds one exact simulation-only
	// consumer; production and carrier paths remain deliberately absent here.
	return false
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

func directAttemptImportViolations(directory string) ([]string, error) {
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
			if path == "net" || strings.HasPrefix(path, "net/") && path != "net/netip" {
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
