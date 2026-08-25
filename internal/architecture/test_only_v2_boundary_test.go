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

func TestDirectSimulationBoundaryDetectsNewProductionImporter(t *testing.T) {
	directSim := modulePath + "/internal/v2/directsim"
	result := scanResult{packages: map[string]*packageInfo{
		modulePath + "/pkg/runtime": {imports: map[string]struct{}{directSim: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := modulePath + "/pkg/runtime imports simulation-only " + directSim
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

func TestN2DNatlabHarnessAndHelpersStayTestOnly(t *testing.T) {
	root := repositoryRoot(t)
	directory := filepath.Join(root, "test", "natlab")
	violations, err := n2dHarnessSourceViolations(directory)
	if err != nil {
		t.Fatalf("scan N2d harness sources: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("N2d harness gained a product-importable source:\n  %s", strings.Join(violations, "\n  "))
	}

	for _, relative := range []string{
		"internal/governor/n2d_natlab_linux.go",
		"internal/v2/rendezvouscarrier/n2d_testserver_linux.go",
	} {
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read N2d helper %s: %v", relative, err)
		}
		normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
		if !strings.HasPrefix(normalized, "//go:build linux && natlab\n") {
			t.Fatalf("N2d helper %s lost its exact linux && natlab build constraint", relative)
		}
	}

	helperViolations, err := n2dHelperUseViolations(root)
	if err != nil {
		t.Fatalf("scan N2d helper uses: %v", err)
	}
	if len(helperViolations) != 0 {
		t.Fatalf("N2d helper escaped its exact natlab allowlist:\n  %s", strings.Join(helperViolations, "\n  "))
	}
	capabilityViolations, err := n2dIsolatedCapabilityUseViolations(root)
	if err != nil {
		t.Fatalf("scan N2d isolated capability uses: %v", err)
	}
	if len(capabilityViolations) != 0 {
		t.Fatalf("N2d isolated-unicast capability escaped its exact natlab allowlist:\n  %s", strings.Join(capabilityViolations, "\n  "))
	}
}

func TestN2DNatlabGateDetectsProductionMutations(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cmd", "wink")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := []byte(`package main
import (
  gov "winkyou/internal/governor"
  obs "winkyou/internal/stunobserve"
  carrier "winkyou/internal/v2/rendezvouscarrier"
)
func bypass() {
  _ = gov.PrepareN2DTestNamespace
  _ = carrier.StartN2DTestServer
  _ = obs.SameSocketConfig{AllowNonLoopback: true}
  _ = carrier.AllowedTargetIsolatedUnicast
}
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	helperViolations, err := n2dHelperUseViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(helperViolations) != 1 || helperViolations[0] != "cmd/wink/bypass.go uses N2d natlab-only helper" {
		t.Fatalf("helper violations = %v, want injected production use", helperViolations)
	}
	capabilityViolations, err := n2dIsolatedCapabilityUseViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cmd/wink/bypass.go uses N2d isolated capability AllowNonLoopback",
		"cmd/wink/bypass.go uses N2d isolated capability AllowedTargetIsolatedUnicast",
	}
	if len(capabilityViolations) != len(want) || strings.Join(capabilityViolations, "\n") != strings.Join(want, "\n") {
		t.Fatalf("capability violations = %v, want %v", capabilityViolations, want)
	}
}

func TestN2DHarnessTestsOnlyGateDetectsProductionSource(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "n2d_escape.go"), []byte("package natlab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := n2dHarnessSourceViolations(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 || violations[0] != "n2d_escape.go is not test-only" {
		t.Fatalf("violations = %v, want injected N2d production source", violations)
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

func TestN2CRendezvousCarrierStaysDisconnectedFromProduction(t *testing.T) {
	result, err := scanRepository(repositoryRoot(t))
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}
	if violations := v2RestrictedDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("N2c carrier escaped its disconnected boundary:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestN2CRendezvousCarrierBoundaryDetectsEveryProductEntry(t *testing.T) {
	carrier := modulePath + "/internal/v2/rendezvouscarrier"
	for _, importer := range []string{
		modulePath + "/cmd/wink",
		modulePath + "/cmd/wink-signal",
		modulePath + "/internal/stdioapi",
		modulePath + "/pkg/runtime",
		modulePath + "/pkg/meshruntime",
		modulePath + "/pkg/nat",
	} {
		result := scanResult{packages: map[string]*packageInfo{
			importer: {imports: map[string]struct{}{carrier: {}}},
		}}
		violations := v2RestrictedDependencyViolations(result)
		want := importer + " imports disconnected N2c carrier " + carrier
		if len(violations) != 1 || violations[0] != want {
			t.Errorf("%s violations = %v, want %q", importer, violations, want)
		}
	}
}

func TestN2CRendezvousCarrierRejectsUnreviewedWinkYouDependency(t *testing.T) {
	carrier := modulePath + "/internal/v2/rendezvouscarrier"
	forbidden := modulePath + "/pkg/nat"
	result := scanResult{packages: map[string]*packageInfo{
		carrier: {imports: map[string]struct{}{forbidden: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := carrier + " imports forbidden disconnected-carrier dependency " + forbidden
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestN2CSameSocketEntrypointsStayDisconnected(t *testing.T) {
	violations, err := n2cSameSocketUseViolations(repositoryRoot(t))
	if err != nil {
		t.Fatalf("scan N2c same-socket uses: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("N2c same-socket entrypoint escaped into production:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestN2CSameSocketGateDetectsProductMutation(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cmd", "wink")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := []byte("package main\nimport obs \"winkyou/internal/stunobserve\"\nfunc bypass() { _ = obs.N2SameSocketCost() }\n")
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := n2cSameSocketUseViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "cmd/wink/bypass.go uses disconnected N2c stunobserve entry N2SameSocketCost"
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

func TestDirectSimulationOwnsNoRawNetworkCapability(t *testing.T) {
	directory := filepath.Join(repositoryRoot(t), "internal", "v2", "directsim")
	violations, err := directAttemptImportViolations(directory)
	if err != nil {
		t.Fatalf("scan directsim imports: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("directsim gained a raw network import:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestDirectSimulationNetworkGateDetectsRawNet(t *testing.T) {
	directory := t.TempDir()
	source := []byte("package directsim\nimport \"net\"\nvar _ net.Conn\n")
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatalf("write injected directsim import: %v", err)
	}
	violations, err := directAttemptImportViolations(directory)
	if err != nil {
		t.Fatalf("scan injected directsim import: %v", err)
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "imports net") {
		t.Fatalf("violations = %v, want injected net import", violations)
	}
}

func TestDirectSimulationDependencyGateDetectsProbeIO(t *testing.T) {
	directSim := modulePath + "/internal/v2/directsim"
	probeIO := modulePath + "/internal/probeio"
	result := scanResult{packages: map[string]*packageInfo{
		directSim: {imports: map[string]struct{}{probeIO: {}}},
	}}
	violations := v2RestrictedDependencyViolations(result)
	want := directSim + " imports forbidden simulation dependency " + probeIO
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}

func TestLoopbackCarrierApprovalIsExactAndBidirectional(t *testing.T) {
	carrier := modulePath + "/internal/v2/loopbackcarrier"
	punchSim := modulePath + "/internal/v2/punchsim"
	punchProto := modulePath + "/internal/v2/punchproto"
	noiseCore := modulePath + "/internal/v2/noisecore"
	pairingContext := modulePath + "/internal/v2/pairingcontext"
	directAttempt := modulePath + "/internal/v2/directattempt"
	directSim := modulePath + "/internal/v2/directsim"
	rendezvousCarrier := modulePath + "/internal/v2/rendezvouscarrier"

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
		{directSim, noiseCore, true},
		{directSim, pairingContext, true},
		{rendezvousCarrier, noiseCore, true},
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
	if !approvedDirectAttemptImporter(directSim, directAttempt) || !approvedDirectAttemptImporter(rendezvousCarrier, directAttempt) || approvedDirectAttemptImporter(modulePath+"/cmd/wink", directAttempt) || approvedDirectAttemptImporter(directSim+"/child", directAttempt) {
		t.Fatal("direct-attempt approval is not exact and bidirectional")
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
	directSim := modulePath + "/internal/v2/directsim"
	rendezvousCarrier := modulePath + "/internal/v2/rendezvouscarrier"
	simulationOnlyPackages := map[string]struct{}{
		testPairing: {},
		punchSim:    {},
		directSim:   {},
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
	allowedDirectSimImports := map[string]struct{}{
		modulePath + "/internal/natsim":            {},
		modulePath + "/internal/v2/directattempt":  {},
		modulePath + "/internal/v2/noisecore":      {},
		modulePath + "/internal/v2/pairingcontext": {},
	}
	allowedRendezvousCarrierImports := map[string]struct{}{
		modulePath + "/internal/governor":         {},
		modulePath + "/internal/v2/directattempt": {},
		modulePath + "/internal/v2/noisecore":     {},
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
			case importer == directSim && strings.HasPrefix(imported, modulePath+"/") && !containsImportOrChild(allowedDirectSimImports, imported):
				violations = append(violations, importer+" imports forbidden simulation dependency "+imported)
			case importer == rendezvousCarrier && strings.HasPrefix(imported, modulePath+"/") && !containsImportOrChild(allowedRendezvousCarrierImports, imported):
				violations = append(violations, importer+" imports forbidden disconnected-carrier dependency "+imported)
			case (imported == rendezvousCarrier || strings.HasPrefix(imported, rendezvousCarrier+"/")) && importer != rendezvousCarrier:
				violations = append(violations, importer+" imports disconnected N2c carrier "+imported)
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

func n2dHarnessSourceViolations(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "n2d_") || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			violations = append(violations, entry.Name()+" is not test-only")
			continue
		}
		payload, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
		if !strings.HasPrefix(normalized, "//go:build linux && natlab\n") {
			violations = append(violations, entry.Name()+" lacks exact linux && natlab constraint")
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func n2dHelperUseViolations(root string) ([]string, error) {
	restricted := map[string]struct{}{
		"PrepareN2DTestNamespace": {},
		"N2DTestPairingLedger":    {},
		"StartN2DTestServer":      {},
		"N2DTestServer":           {},
		"N2DTestServerStats":      {},
	}
	definitions := map[string]struct{}{
		"internal/governor/n2d_natlab_linux.go":                 {},
		"internal/v2/rendezvouscarrier/n2d_testserver_linux.go": {},
	}
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
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, definition := definitions[relative]; definition ||
			(strings.HasPrefix(relative, "test/natlab/n2d_") && strings.HasSuffix(relative, "_test.go")) {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return err
		}
		used := false
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok {
				_, used = restricted[identifier.Name]
			}
			return !used
		})
		if used {
			violations = append(violations, relative+" uses N2d natlab-only helper")
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func n2dIsolatedCapabilityUseViolations(root string) ([]string, error) {
	definitions := map[string]struct{}{
		"internal/stunobserve/same_socket.go":      {},
		"internal/v2/rendezvouscarrier/carrier.go": {},
	}
	stunobservePath := modulePath + "/internal/stunobserve"
	carrierPath := modulePath + "/internal/v2/rendezvouscarrier"
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
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, definition := definitions[relative]; definition ||
			(strings.HasPrefix(relative, "test/natlab/n2d_") && strings.HasSuffix(relative, "_test.go")) {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return err
		}
		stunAliases := make(map[string]struct{})
		carrierAliases := make(map[string]struct{})
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil {
				return err
			}
			alias := filepath.Base(imported)
			if specification.Name != nil {
				alias = specification.Name.Name
			}
			switch imported {
			case stunobservePath:
				stunAliases[alias] = struct{}{}
			case carrierPath:
				carrierAliases[alias] = struct{}{}
			}
		}
		insideStunobserve := strings.HasPrefix(relative, "internal/stunobserve/")
		insideCarrier := strings.HasPrefix(relative, "internal/v2/rendezvouscarrier/")
		seen := make(map[string]struct{})
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CompositeLit:
				isSameSocket := false
				switch typeName := value.Type.(type) {
				case *ast.Ident:
					_, dotImport := stunAliases["."]
					isSameSocket = typeName.Name == "SameSocketConfig" && (insideStunobserve || dotImport)
				case *ast.SelectorExpr:
					alias, ok := typeName.X.(*ast.Ident)
					if ok {
						_, imported := stunAliases[alias.Name]
						isSameSocket = imported && typeName.Sel.Name == "SameSocketConfig"
					}
				}
				if isSameSocket {
					for _, element := range value.Elts {
						field, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := field.Key.(*ast.Ident)
						if ok && key.Name == "AllowNonLoopback" {
							seen["AllowNonLoopback"] = struct{}{}
						}
					}
				}
			case *ast.SelectorExpr:
				alias, ok := value.X.(*ast.Ident)
				if ok {
					_, imported := carrierAliases[alias.Name]
					if imported && value.Sel.Name == "AllowedTargetIsolatedUnicast" {
						seen["AllowedTargetIsolatedUnicast"] = struct{}{}
					}
				}
			case *ast.Ident:
				if insideCarrier && value.Name == "AllowedTargetIsolatedUnicast" {
					seen["AllowedTargetIsolatedUnicast"] = struct{}{}
				}
			}
			return true
		})
		for name := range seen {
			violations = append(violations, relative+" uses N2d isolated capability "+name)
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
	directSim := modulePath + "/internal/v2/directsim"
	rendezvousCarrier := modulePath + "/internal/v2/rendezvouscarrier"

	switch imported {
	case noiseCore:
		return importer == punchProto || importer == punchSim || importer == carrier || importer == directAttempt || importer == directSim || importer == rendezvousCarrier
	case punchProto:
		return importer == punchSim || importer == carrier
	case pairingContext:
		return importer == testPairing || importer == carrier || importer == directAttempt || importer == directSim
	default:
		return false
	}
}

func approvedDirectAttemptImporter(importer, imported string) bool {
	// N2b has one exact simulation consumer. N2c adds the exact disconnected
	// carrier; all product and legacy paths remain absent.
	return (importer == modulePath+"/internal/v2/directsim" || importer == modulePath+"/internal/v2/rendezvouscarrier") &&
		imported == modulePath+"/internal/v2/directattempt"
}

func n2cSameSocketUseViolations(root string) ([]string, error) {
	stunobservePath := modulePath + "/internal/stunobserve"
	restricted := map[string]struct{}{
		"NewSameSocket":         {},
		"N2SameSocketCost":      {},
		"SameSocketConfig":      {},
		"SameSocketClient":      {},
		"SameSocketObservation": {},
	}
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
		if !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "internal/stunobserve/same_socket.go" {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return err
		}
		aliases := make(map[string]struct{})
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil || imported != stunobservePath {
				continue
			}
			alias := "stunobserve"
			if specification.Name != nil {
				alias = specification.Name.Name
			}
			if alias == "." {
				violations = append(violations, relative+" dot-imports stunobserve across the N2c boundary")
				continue
			}
			aliases[alias] = struct{}{}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, found := aliases[identifier.Name]; !found {
				return true
			}
			if _, found := restricted[selector.Sel.Name]; found {
				violations = append(violations, relative+" uses disconnected N2c stunobserve entry "+selector.Sel.Name)
			}
			return true
		})
		return nil
	})
	sort.Strings(violations)
	return violations, err
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
