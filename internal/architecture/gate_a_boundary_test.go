package architecture

import (
	"fmt"
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

func TestGateABoundaryIsExactAndZeroCapability(t *testing.T) {
	root := repositoryRoot(t)
	result, err := scanRepository(root)
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}
	if violations := v2RestrictedDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("Gate A escaped its test-only package boundary:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateAForbiddenImportViolations(filepath.Join(root, "internal", "v2", "oobcarrier")); err != nil {
		t.Fatalf("scan OOB carrier imports: %v", err)
	} else if len(violations) != 0 {
		t.Fatalf("OOB carrier gained a network/process capability:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateAConstructionViolations(root); err != nil {
		t.Fatalf("scan OOB carrier construction: %v", err)
	} else if len(violations) != 0 {
		t.Fatalf("OOB carrier construction escaped the Gate A adapter:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := transportLeaseUseViolations(root); err != nil {
		t.Fatalf("scan TransportLease uses: %v", err)
	} else if len(violations) != 0 {
		t.Fatalf("TransportLease escaped its exact Gate A consumer:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateACallShapeViolations(root); err != nil {
		t.Fatalf("scan Gate A capability shape: %v", err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate A socket/target/handoff shape drifted:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestGateABoundaryDetectsProductAndDependencyMutations(t *testing.T) {
	gateA := modulePath + "/internal/v2/directconnect/gatea"
	oobCarrier := modulePath + "/internal/v2/oobcarrier"
	for _, mutation := range []struct {
		importer string
		imported string
		want     string
	}{
		{modulePath + "/cmd/wink", gateA, modulePath + "/cmd/wink imports Gate A test-only boundary " + gateA},
		{modulePath + "/internal/solverstdio", gateA, modulePath + "/internal/solverstdio imports Gate A test-only boundary " + gateA},
		{modulePath + "/pkg/runtime", oobCarrier, modulePath + "/pkg/runtime imports Gate A bounded carrier " + oobCarrier + " without approval"},
		{oobCarrier, modulePath + "/pkg/nat", oobCarrier + " imports forbidden Gate A carrier dependency " + modulePath + "/pkg/nat"},
		{gateA, modulePath + "/pkg/nat", gateA + " imports forbidden Gate A harness dependency " + modulePath + "/pkg/nat"},
	} {
		result := scanResult{packages: map[string]*packageInfo{
			mutation.importer: {imports: map[string]struct{}{mutation.imported: {}}},
		}}
		violations := v2RestrictedDependencyViolations(result)
		if len(violations) != 1 || violations[0] != mutation.want {
			t.Errorf("%s -> %s violations = %v, want %q", mutation.importer, mutation.imported, violations, mutation.want)
		}
	}
}

func TestGateAZeroCapabilityGateDetectsNetworkProcessAndSDKImports(t *testing.T) {
	directory := t.TempDir()
	source := []byte(`package oobcarrier
import (
  "net"
  "os/exec"
  "tailscale.com/tsnet"
)
var _ net.Conn
var _ = exec.Command
var _ tsnet.Server
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateAForbiddenImportViolations(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 3 {
		t.Fatalf("violations = %v, want net, os/exec, and Tailscale SDK mutations", violations)
	}
}

func TestGateAConstructionGateDetectsProductMutation(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cmd", "wink")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := []byte(`package main
import carrier "winkyou/internal/v2/oobcarrier"
func bypass(config carrier.Config) { _, _ = carrier.Adopt(config) }
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateAConstructionViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cmd/wink/bypass.go constructs Gate A carrier with Adopt",
		"cmd/wink/bypass.go consumes Gate A carrier type Config",
	}
	if strings.Join(violations, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations = %v, want %v", violations, want)
	}
}

func TestTransportLeaseGateDetectsUnreviewedConsumerMutation(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "pkg", "solver", "strategy", "bypass")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := []byte(`package bypass
import probe "winkyou/internal/probeio"
func acquire(socket *probe.ProbeSocket, attempt *governor.AttemptLease) {
  binding := probe.TransportLeaseBinding{ConsumerKind: probe.GateATestConsumer}
  lease, _ := probe.IssueTransportLease(attempt, binding)
  _ = socket.PromoteToLease(binding.Target, binding.PathID, lease)
}
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := transportLeaseUseViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"GateATestConsumer", "IssueTransportLease", "PromoteToLease", "TransportLeaseBinding"} {
		if !containsLineSuffix(violations, "uses Gate A TransportLease authority "+name) {
			t.Errorf("TransportLease mutation %s was not detected: %v", name, violations)
		}
	}
}

func TestGateACallShapeGateDetectsSecondSocketTargetAndRawPromote(t *testing.T) {
	root := t.TempDir()
	gateDirectory := filepath.Join(root, "internal", "v2", "directconnect", "gatea")
	observeDirectory := filepath.Join(root, "internal", "stunobserve")
	if err := os.MkdirAll(gateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(observeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	gateSource := []byte(`package gatea
func shape() {
  _ = probeio.NewUDPFactory
  _ = stunobserve.NewGateASameSocket
  _ = probeio.IssueTransportLease
  _, _ = controller.OpenProbeSocket(ctx)
  _, _ = controller.OpenProbeSocket(ctx)
  _ = socket.PromoteToLease(target, path, lease)
  _, _ = socket.Promote(target, path)
}
`)
	observeSource := []byte(`package stunobserve
func shape() {
  _ = socket.RegisterTarget(first)
  _ = socket.RegisterTarget(second)
  _ = socket.RegisterTarget(third)
}
`)
	if err := os.WriteFile(filepath.Join(gateDirectory, "connect.go"), gateSource, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(observeDirectory, "gate_a_same_socket.go"), observeSource, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateACallShapeViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"OpenProbeSocket count=2 want=1",
		"RegisterTarget count=3 want=2",
		"legacy Promote count=1 want=0",
	} {
		if !containsLineFragment(violations, fragment) {
			t.Errorf("mutation %q was not detected: %v", fragment, violations)
		}
	}
}

func gateAForbiddenImportViolations(directory string) ([]string, error) {
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
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil {
				return err
			}
			if imported == "net" || strings.HasPrefix(imported, "net/") ||
				imported == "os/exec" || imported == "syscall" ||
				strings.HasPrefix(imported, "golang.org/x/sys/") ||
				strings.HasPrefix(imported, "golang.org/x/crypto/ssh") ||
				strings.HasPrefix(imported, "tailscale.com/") {
				violations = append(violations, filepath.ToSlash(filename)+" imports "+imported)
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateAConstructionViolations(root string) ([]string, error) {
	const carrierPath = modulePath + "/internal/v2/oobcarrier"
	allowed := filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go"))
	return importedSelectorUseViolations(root, carrierPath, map[string]string{
		"Adopt":  "constructs Gate A carrier with Adopt",
		"Config": "consumes Gate A carrier type Config",
	}, map[string]struct{}{allowed: {}})
}

func transportLeaseUseViolations(root string) ([]string, error) {
	restricted := map[string]struct{}{
		"GateATestConsumer":     {},
		"GateB2TestConsumer":    {},
		"IssueTransportLease":   {},
		"TransportLease":        {},
		"TransportLeaseBinding": {},
		"PromoteToLease":        {},
		"PromoteToHardNATLease": {},
		"MarkStandby":           {},
		"MarkChallengePassed":   {},
		"DetachAfterFinish":     {},
	}
	allowed := map[string]struct{}{
		filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")): {},
		filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gateb", "connect.go")): {},
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
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasPrefix(relative, "internal/probeio/") {
			return nil
		}
		if _, ok := allowed[relative]; ok {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return err
		}
		seen := make(map[string]struct{})
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok {
				if _, watched := restricted[identifier.Name]; watched {
					seen[identifier.Name] = struct{}{}
				}
			}
			return true
		})
		for name := range seen {
			violations = append(violations, relative+" uses Gate A TransportLease authority "+name)
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func importedSelectorUseViolations(root, importedPath string, watched map[string]string, allowed map[string]struct{}) ([]string, error) {
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
		if _, ok := allowed[relative]; ok {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return err
		}
		aliases := make(map[string]struct{})
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil || imported != importedPath {
				continue
			}
			alias := filepath.Base(imported)
			if specification.Name != nil {
				alias = specification.Name.Name
			}
			if alias == "." {
				for name, message := range watched {
					violations = append(violations, relative+" dot-imports "+name+": "+message)
				}
				continue
			}
			aliases[alias] = struct{}{}
		}
		seen := make(map[string]struct{})
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, imported := aliases[identifier.Name]; !imported {
				return true
			}
			if _, watchedName := watched[selector.Sel.Name]; watchedName {
				seen[selector.Sel.Name] = struct{}{}
			}
			return true
		})
		for name := range seen {
			violations = append(violations, relative+" "+watched[name])
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateACallShapeViolations(root string) ([]string, error) {
	type expectedCall struct {
		file  string
		name  string
		count int
	}
	expected := []expectedCall{
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "NewUDPFactory", 1},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "OpenProbeSocket", 1},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "NewGateASameSocket", 1},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "IssueTransportLease", 1},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "PromoteToLease", 1},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "Promote", 0},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "PromoteTerminal", 0},
		{filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go")), "RegisterTarget", 0},
		{filepath.ToSlash(filepath.Join("internal", "stunobserve", "gate_a_same_socket.go")), "RegisterTarget", 2},
	}
	cache := make(map[string]map[string]int)
	for _, item := range expected {
		if cache[item.file] != nil {
			continue
		}
		filename := filepath.Join(root, filepath.FromSlash(item.file))
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return nil, err
		}
		counts := make(map[string]int)
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok {
				counts[selector.Sel.Name]++
			}
			return true
		})
		cache[item.file] = counts
	}
	var violations []string
	for _, item := range expected {
		actual := cache[item.file][item.name]
		if actual != item.count {
			label := item.name
			if item.name == "Promote" || item.name == "PromoteTerminal" {
				label = "legacy " + item.name
			}
			violations = append(violations, fmt.Sprintf("%s %s count=%d want=%d", item.file, label, actual, item.count))
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func containsLineSuffix(lines []string, suffix string) bool {
	for _, line := range lines {
		if strings.HasSuffix(line, suffix) {
			return true
		}
	}
	return false
}

func containsLineFragment(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
