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

func TestGateB2BoundaryIsDisconnectedAndCapabilityNarrow(t *testing.T) {
	root := repositoryRoot(t)
	result, err := scanRepository(root)
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}
	if violations := v2RestrictedDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("Gate B2 escaped its disconnected boundary:\n  %s", strings.Join(violations, "\n  "))
	}
	for _, directory := range []string{
		"internal/v2/hardnatbudget",
		"internal/v2/hardnatattempt",
		"internal/v2/hardnatcontrol",
		"internal/v2/hardnatobserve",
		"internal/v2/directconnect/gateb",
	} {
		violations, scanErr := gateB2CapabilityImportViolations(filepath.Join(root, filepath.FromSlash(directory)))
		if scanErr != nil {
			t.Fatalf("scan %s: %v", directory, scanErr)
		}
		if len(violations) != 0 {
			t.Errorf("%s gained an unreviewed capability:\n  %s", directory, strings.Join(violations, "\n  "))
		}
	}
	if violations, err := gateB2ObservationAuthorityViolations(filepath.Join(root, "internal", "v2", "hardnatobserve")); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("hardnatobserve gained factory/socket ownership:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB2CallShapeViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B2 governed call shape drifted:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB2ManualTraversalAuthorityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B2 manual-traversal authority escaped its reviewed files:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB2NonLoopbackAuthorityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B2 non-loopback authority escaped linux+natlab:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestGateB2BoundaryDetectsNonLoopbackCapabilityMutation(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "bypass.go")
	source := []byte(`package gateb
func bypass() {
  _ = Config{AllowNonLoopback: true}
  _ = probeio.AllowedTargetScopeUnicast
}
`)
	if err := os.WriteFile(filename, source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB2DefaultFactoryViolations(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AllowNonLoopback", "AllowedTargetScopeUnicast"} {
		if !containsLineFragment(violations, name) {
			t.Errorf("non-loopback mutation %s was not detected: %v", name, violations)
		}
	}
}

func TestGateB2BoundaryDetectsProductDependencyAndCapabilityMutations(t *testing.T) {
	gateB := modulePath + "/internal/v2/directconnect/gateb"
	control := modulePath + "/internal/v2/hardnatcontrol"
	for _, mutation := range []struct {
		importer string
		imported string
		want     string
	}{
		{modulePath + "/cmd/wink", gateB, modulePath + "/cmd/wink imports disconnected Gate B2 executor " + gateB},
		{modulePath + "/internal/solverstdio", gateB, modulePath + "/internal/solverstdio imports disconnected Gate B2 executor " + gateB},
		{modulePath + "/pkg/runtime", control, modulePath + "/pkg/runtime imports Gate B2 restricted primitive " + control + " without approval"},
		{gateB, modulePath + "/pkg/nat", gateB + " imports forbidden Gate B2 executor dependency " + modulePath + "/pkg/nat"},
	} {
		result := scanResult{packages: map[string]*packageInfo{
			mutation.importer: {imports: map[string]struct{}{mutation.imported: {}}},
		}}
		violations := v2RestrictedDependencyViolations(result)
		if len(violations) != 1 || violations[0] != mutation.want {
			t.Errorf("%s -> %s violations=%v, want %q", mutation.importer, mutation.imported, violations, mutation.want)
		}
	}

	directory := t.TempDir()
	source := []byte(`package gateb
import (
  "net"
  "os/exec"
  "github.com/pion/ice/v4"
)
var _ = net.ListenUDP
var _ = exec.Command
var _ ice.Agent{}
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB2CapabilityImportViolations(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 3 {
		t.Fatalf("capability mutation violations=%v, want net, os/exec, and Pion", violations)
	}
}

func TestGateB2ObservationGateDetectsFactoryAndSecondSocketMutation(t *testing.T) {
	directory := t.TempDir()
	source := []byte(`package hardnatobserve
func bypass(controller *probeio.Controller) {
  _ = probeio.NewUDPFactory
  _ = probeio.Factory(nil)
  _, _ = controller.OpenProbeSocket(context.Background())
}
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB2ObservationAuthorityViolations(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Factory", "NewUDPFactory", "OpenProbeSocket"} {
		if !containsLineFragment(violations, name) {
			t.Errorf("mutation %s was not detected: %v", name, violations)
		}
	}
}

func TestGateB2ManualTraversalAuthorityGateDetectsProductMutation(t *testing.T) {
	directory := t.TempDir()
	source := []byte(`package product
func bypass(owner *governor.Owner) {
  machine, _ := governor.New(owner, governor.ProfilePhase1ManualTraversal, nil)
  _, _ = machine.AcquireAttempt(governor.AttemptRequest{Operation: governor.OperationBirthday})
}
`)
	if err := os.WriteFile(filepath.Join(directory, "product.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB2ManualTraversalAuthorityViolations(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ProfilePhase1ManualTraversal", "OperationBirthday"} {
		if !containsLineFragment(violations, name) {
			t.Errorf("manual-traversal mutation %s was not detected: %v", name, violations)
		}
	}
}

func gateB2CapabilityImportViolations(directory string) ([]string, error) {
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
			if imported == "net/netip" {
				continue
			}
			if imported == "net" || strings.HasPrefix(imported, "net/") || imported == "os/exec" ||
				imported == "syscall" || strings.HasPrefix(imported, "golang.org/x/sys/") ||
				strings.Contains(imported, "pion") || strings.Contains(imported, "legacyice") ||
				strings.Contains(imported, "birthdaypunch") {
				violations = append(violations, filepath.ToSlash(filename)+" imports "+imported)
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateB2ObservationAuthorityViolations(directory string) ([]string, error) {
	restricted := map[string]struct{}{"Factory": {}, "NewUDPFactory": {}, "OpenProbeSocket": {}}
	var violations []string
	err := filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
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
				if _, restrictedName := restricted[identifier.Name]; restrictedName {
					seen[identifier.Name] = struct{}{}
				}
			}
			return true
		})
		for name := range seen {
			violations = append(violations, filepath.ToSlash(filename)+" uses forbidden observation authority "+name)
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateB2CallShapeViolations(root string) ([]string, error) {
	type call struct {
		file, imported, selector string
		count                    int
	}
	expected := []call{
		{"internal/v2/directconnect/gateb/connect.go", modulePath + "/internal/probeio", "New", 1},
		{"internal/v2/directconnect/gateb/connect.go", modulePath + "/internal/probeio", "NewUDPFactory", 1},
		{"internal/v2/directconnect/gateb/connect.go", modulePath + "/internal/probeio", "IssueTransportLease", 1},
		{"internal/v2/directconnect/gateb/connect.go", modulePath + "/internal/probeio", "GateB2TestConsumer", 1},
		{"internal/v2/directconnect/gateb/connect.go", modulePath + "/internal/probeio", "GateATestConsumer", 0},
	}
	var violations []string
	for _, item := range expected {
		filename := filepath.Join(root, filepath.FromSlash(item.file))
		actual, err := importedSelectorCount(filename, item.imported, item.selector)
		if err != nil {
			return nil, err
		}
		if actual != item.count {
			violations = append(violations, fmt.Sprintf("%s %s.%s count=%d want=%d", item.file, item.imported, item.selector, actual, item.count))
		}
	}
	return violations, nil
}

func gateB2ManualTraversalAuthorityViolations(root string) ([]string, error) {
	identifiers := map[string]struct{}{
		"ProfilePhase1ManualTraversal": {},
		"OperationPrediction":          {},
		"OperationBirthday":            {},
	}
	allowed := map[string]map[string]struct{}{
		"internal/governor/limits.go": {
			"ProfilePhase1ManualTraversal": {}, "OperationPrediction": {}, "OperationBirthday": {},
		},
		"internal/governor/governor.go": {
			"ProfilePhase1ManualTraversal": {},
		},
		"internal/governor/pairing_gate.go": {
			"ProfilePhase1ManualTraversal": {}, "OperationPrediction": {}, "OperationBirthday": {},
		},
		"internal/governor/pairing_ledger.go": {
			"ProfilePhase1ManualTraversal": {},
		},
		"internal/probeio/probeio.go": {
			"OperationPrediction": {}, "OperationBirthday": {},
		},
		"internal/probeio/transport_lease.go": {
			"OperationPrediction": {}, "OperationBirthday": {},
		},
		"internal/v2/hardnatbudget/budget.go": {
			"OperationPrediction": {}, "OperationBirthday": {},
		},
		"internal/v2/directconnect/gateb/connect.go": {
			"ProfilePhase1ManualTraversal": {},
		},
	}
	var violations []string
	fset := token.NewFileSet()
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
		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if _, watched := identifiers[identifier.Name]; !watched {
				return true
			}
			if names, approved := allowed[relative]; approved {
				if _, approved = names[identifier.Name]; approved {
					return true
				}
			}
			position := fset.Position(identifier.Pos())
			violations = append(violations, fmt.Sprintf("%s:%d references %s", relative, position.Line, identifier.Name))
			return true
		})
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateB2NonLoopbackAuthorityViolations(root string) ([]string, error) {
	var violations []string
	gateBFile := filepath.Join(root, "internal", "v2", "directconnect", "gateb", "connect.go")
	defaultViolations, err := gateB2DefaultFactoryViolations(gateBFile)
	if err != nil {
		return nil, err
	}
	violations = append(violations, defaultViolations...)

	natLabFile := filepath.Join(root, "internal", "probeio", "gate_b2_natlab_linux.go")
	payload, err := os.ReadFile(natLabFile)
	if err != nil {
		return nil, err
	}
	// Git may materialize the source with CRLF on Windows. Normalize only for
	// this exact first-line capability check so the gate has identical meaning
	// on every CI runner.
	normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
	if !strings.HasPrefix(normalized, "//go:build linux && natlab\n") {
		violations = append(violations, "internal/probeio/gate_b2_natlab_linux.go lacks exact linux+natlab build constraint")
	}

	allowedConsumer := "test/natlab/gate_b2_endpoint_linux_test.go"
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
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
		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.SelectorExpr:
				if value.Sel.Name == "NewGateB2NATLabFactory" && relative != allowedConsumer {
					violations = append(violations, relative+" constructs sealed Gate B2 natlab factory")
				}
			case *ast.KeyValueExpr:
				key, ok := value.Key.(*ast.Ident)
				if ok && key.Name == "NATLabFactory" && relative != allowedConsumer {
					violations = append(violations, relative+" injects Gate B2 natlab factory")
				}
				if ok && key.Name == "ProbeFactory" && !strings.HasSuffix(relative, "_test.go") {
					violations = append(violations, relative+" injects Gate B2 simulation factory from production code")
				}
			}
			return true
		})
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateB2DefaultFactoryViolations(filename string) ([]string, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		return nil, err
	}
	var violations []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok || (identifier.Name != "AllowNonLoopback" && identifier.Name != "AllowedTargetScopeUnicast") {
			return true
		}
		position := fset.Position(identifier.Pos())
		violations = append(violations, fmt.Sprintf("%s:%d uses forbidden %s", filepath.ToSlash(filename), position.Line, identifier.Name))
		return true
	})
	sort.Strings(violations)
	return violations, nil
}

func importedSelectorCount(filename, importedPath, selectorName string) (int, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		return 0, err
	}
	aliases := make(map[string]struct{})
	for _, specification := range parsed.Imports {
		imported, err := strconv.Unquote(specification.Path.Value)
		if err != nil {
			return 0, err
		}
		if imported != importedPath {
			continue
		}
		alias := filepath.Base(importedPath)
		if specification.Name != nil {
			alias = specification.Name.Name
		}
		aliases[alias] = struct{}{}
	}
	count := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != selectorName {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok {
			if _, imported := aliases[identifier.Name]; imported {
				count++
			}
		}
		return true
	})
	return count, nil
}
