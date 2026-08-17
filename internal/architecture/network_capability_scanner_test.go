package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCapabilityScannerDetectsAliasReferenceAndReceiverDial(t *testing.T) {
	findings := scanSource(t, `
package sample

import (
	"context"
	stdnet "net"
)

var open = stdnet.Listen
var dialContext = (*stdnet.Dialer).DialContext

func connect(ctx context.Context, dialer *stdnet.Dialer) {
	_, _ = dialer.DialContext(ctx, "udp4", "192.0.2.10:9")
}
`)
	actual := aggregateFindings(findings)
	expected := []string{
		"sample.go | <init> | reference:method.DialContext | count=1",
		"sample.go | <init> | reference:net.Listen | count=1",
		"sample.go | connect | call:method.DialContext | count=1",
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("findings = %#v, want %#v", actual, expected)
	}
}

func TestDotCapabilityImportsCannotHideUnqualifiedCalls(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "dot.go", `package sample; import . "net"`, 0)
	if err != nil {
		t.Fatalf("parse dot import: %v", err)
	}
	actual := dotCapabilityImports(parsed)
	if !reflect.DeepEqual(actual, []string{"net"}) {
		t.Fatalf("dot imports = %#v, want net", actual)
	}
}

func TestGovernedPackageCannotReachCapabilityTransitively(t *testing.T) {
	result := scanResult{
		findings: []finding{{
			file:       "pkg/nat/open.go",
			function:   "open",
			capability: "reference:net.ListenUDP",
			pkg:        "winkyou/pkg/nat",
		}},
		packages: map[string]*packageInfo{
			"winkyou/internal/v2/connect": {
				imports: map[string]struct{}{"winkyou/pkg/wrapper": {}},
			},
			"winkyou/pkg/wrapper": {
				imports: map[string]struct{}{"winkyou/pkg/nat": {}},
			},
			"winkyou/pkg/nat": {imports: map[string]struct{}{}},
		},
	}
	violations := governedCapabilityViolations(result)
	expected := "winkyou/internal/v2/connect -> winkyou/pkg/wrapper -> winkyou/pkg/nat -> [raw network capability]"
	if len(violations) != 1 || violations[0] != expected {
		t.Fatalf("violations = %#v, want %q", violations, expected)
	}
}

func TestProbeIOApprovalIsExactAndDirectBypassStillFails(t *testing.T) {
	approved := finding{
		file:       "internal/probeio/udp_factory.go",
		function:   "openGovernedUDP",
		capability: "reference:net.ListenUDP",
		pkg:        "winkyou/internal/probeio",
	}
	bypass := finding{
		file:       "internal/probeio/bypass.go",
		function:   "openUnaccountedSocket",
		capability: "reference:net.ListenUDP",
		pkg:        "winkyou/internal/probeio",
	}
	result := scanResult{
		findings: []finding{approved, bypass},
		packages: map[string]*packageInfo{
			"winkyou/internal/probeio": {imports: map[string]struct{}{}},
		},
	}

	violations := governedCapabilityViolations(result)
	want := "winkyou/internal/probeio directly owns reference:net.ListenUDP in internal/probeio/bypass.go (openUnaccountedSocket)"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %#v, want only %q", violations, want)
	}
	if !approvedGovernedCapability(approved) {
		t.Fatal("reviewed governor-owned adapter was not recognized")
	}
	approved.function = "anotherOpener"
	if approvedGovernedCapability(approved) {
		t.Fatal("approval widened beyond the exact reviewed function")
	}
}

func TestProbeIOCapabilityApprovalHasGovernorOwner(t *testing.T) {
	if len(governedCapabilityApprovals) != 1 {
		t.Fatalf("governed approvals = %d, want exactly 1", len(governedCapabilityApprovals))
	}
	if owner := governedCapabilityApprovals[0].owner; owner != "governor" {
		t.Fatalf("probeio capability owner = %q, want governor", owner)
	}
}

func TestInventoryDifferenceRejectsAdditionAndStaleDebt(t *testing.T) {
	unexpected, stale := inventoryDifference(
		[]string{"capability-a", "capability-b"},
		[]string{"capability-b", "capability-c"},
	)
	if !reflect.DeepEqual(unexpected, []string{"capability-a"}) {
		t.Fatalf("unexpected = %#v, want capability-a", unexpected)
	}
	if !reflect.DeepEqual(stale, []string{"capability-c"}) {
		t.Fatalf("stale = %#v, want capability-c", stale)
	}
}

func TestRepositoryScannerSkipsHiddenWorktreeCopies(t *testing.T) {
	root := t.TempDir()
	visible := filepath.Join(root, "live.go")
	hiddenDirectory := filepath.Join(root, ".stability-run", "worktree-copy")
	if err := os.MkdirAll(hiddenDirectory, 0o755); err != nil {
		t.Fatalf("create hidden worktree: %v", err)
	}
	source := []byte("package sample\nimport \"net\"\nvar open = net.Listen\n")
	if err := os.WriteFile(visible, source, 0o600); err != nil {
		t.Fatalf("write visible source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDirectory, "copied.go"), source, 0o600); err != nil {
		t.Fatalf("write hidden source: %v", err)
	}

	result, err := scanRepository(root)
	if err != nil {
		t.Fatalf("scan repository: %v", err)
	}
	actual := aggregateFindings(result.findings)
	expected := []string{"live.go | <init> | reference:net.Listen | count=1"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("findings = %#v, want %#v", actual, expected)
	}
}

func scanSource(t *testing.T, source string) []finding {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), "sample.go", source, 0)
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}
	imports, _, err := sourceImports(parsed)
	if err != nil {
		t.Fatalf("parse imports: %v", err)
	}
	var findings []finding
	visitor := &capabilityVisitor{
		imports:  imports,
		file:     "sample.go",
		function: "<init>",
		pkg:      "winkyou/internal/v2/sample",
		findings: &findings,
	}
	ast.Walk(visitor, parsed)
	return findings
}

func TestThirdPartyCapabilityPrefixesAreNarrowAndExplicit(t *testing.T) {
	checks := map[string]bool{
		"github.com/pion/ice/v2":          true,
		"github.com/pion/turn/v2":         true,
		"github.com/quic-go/quic-go":      true,
		"github.com/example/pion-wrapper": false,
		"net":                             false,
	}
	for imported, expected := range checks {
		if actual := isThirdPartyCapability(imported); actual != expected {
			t.Errorf("isThirdPartyCapability(%q) = %t, want %t", imported, actual, expected)
		}
	}
	for _, prefix := range thirdPartyCapabilityPrefixes {
		if strings.TrimSpace(prefix) != prefix || !strings.HasSuffix(prefix, "/") {
			t.Errorf("capability prefix %q must be canonical and end in slash", prefix)
		}
	}
}

func TestGovernedPackageZonesIncludeProbeIOChildrenAndV2Roots(t *testing.T) {
	checks := map[string]bool{
		"winkyou/internal/probeio":        true,
		"winkyou/internal/probeio/osudp":  true,
		"winkyou/internal/stunobserve":    true,
		"winkyou/internal/stunobserve/v4": true,
		"winkyou/internal/natsim":         true,
		"winkyou/internal/natsim/model":   true,
		"winkyou/internal/v2":             true,
		"winkyou/internal/v2/connect":     true,
		"winkyou/pkg/v2":                  true,
		"winkyou/pkg/v2/session":          true,
		"winkyou/pkg/nat":                 false,
		"winkyou/pkg/transport":           false,
	}
	for pkg, expected := range checks {
		if actual := isGovernedPackage(pkg); actual != expected {
			t.Errorf("isGovernedPackage(%q) = %t, want %t", pkg, actual, expected)
		}
	}
}

func TestSTUNObserverCannotAcquireNetworkCapability(t *testing.T) {
	result := scanResult{
		findings: []finding{{
			file:       "internal/stunobserve/bypass.go",
			function:   "openUnaccountedSocket",
			capability: "reference:net.ListenUDP",
			pkg:        "winkyou/internal/stunobserve",
		}},
		packages: map[string]*packageInfo{
			"winkyou/internal/stunobserve": {imports: map[string]struct{}{}},
		},
	}
	violations := governedCapabilityViolations(result)
	want := "winkyou/internal/stunobserve directly owns reference:net.ListenUDP in internal/stunobserve/bypass.go (openUnaccountedSocket)"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %#v, want %q", violations, want)
	}
}

func TestNATSimulatorCannotAcquireNetworkCapability(t *testing.T) {
	result := scanResult{
		findings: []finding{{
			file:       "internal/natsim/bypass.go",
			function:   "openRealSocket",
			capability: "reference:net.ListenUDP",
			pkg:        "winkyou/internal/natsim",
		}},
		packages: map[string]*packageInfo{
			"winkyou/internal/natsim": {imports: map[string]struct{}{}},
		},
	}
	violations := governedCapabilityViolations(result)
	want := "winkyou/internal/natsim directly owns reference:net.ListenUDP in internal/natsim/bypass.go (openRealSocket)"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %#v, want %q", violations, want)
	}
}
