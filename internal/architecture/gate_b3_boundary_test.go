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
	"strings"
	"testing"
)

func TestGateB3BoundaryIsSealedAndDisconnected(t *testing.T) {
	root := repositoryRoot(t)
	result, err := scanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if violations := v2RestrictedDependencyViolations(result); len(violations) != 0 {
		t.Fatalf("Gate B3 escaped the disconnected Gate B boundary:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB3AuthorityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B3 authority escaped reviewed files:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB3NATLabAuthorityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B3 non-loopback authority escaped sealed natlab:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB3CallShapeViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B3 governed call shape drifted:\n  %s", strings.Join(violations, "\n  "))
	}
	if violations, err := gateB3ConntrackAuthorityViolations(root); err != nil {
		t.Fatal(err)
	} else if len(violations) != 0 {
		t.Fatalf("Gate B3 conntrack authority escaped the disposable harness:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestGateB3BoundaryDetectsAuthorityMutations(t *testing.T) {
	directory := t.TempDir()
	mutant := filepath.Join(directory, "product.go")
	source := []byte(`package product
func bypass(config gateb.Config) {
  _ = governor.ProfilePhase1HardNATCampaign
  _ = governor.PairingRecordClassHardNATCampaign
  _ = probeio.GateB3TestConsumer
  _ = config.HardNATLabFactory
  _ = probeio.NewGateB3NATLabFactory
  _ = probeio.NewGateB3ENOBUFSNATLabFactory
}
`)
	if err := os.WriteFile(mutant, source, 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB3AuthorityViolations(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{
		"ProfilePhase1HardNATCampaign", "PairingRecordClassHardNATCampaign",
		"GateB3TestConsumer", "HardNATLabFactory", "NewGateB3NATLabFactory", "NewGateB3ENOBUFSNATLabFactory",
	} {
		if !containsLineFragment(violations, identifier) {
			t.Errorf("Gate B3 mutation %s was not detected: %v", identifier, violations)
		}
	}
}

func TestGateB3BoundaryDetectsNATLabConstructorMutation(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "wrong_test.go")
	if err := os.WriteFile(filename, []byte(`//go:build linux && natlab
package wrong
func bypass() {
  _, _ = probeio.NewGateB3NATLabFactory("wy-n2d-a", 1, [4]netip.AddrPort{})
  _, _ = probeio.NewGateB3ENOBUFSNATLabFactory("wy-n2d-a", 1, [4]netip.AddrPort{})
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB3NATLabAuthorityViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	if !containsLineFragment(violations, "constructs sealed Gate B3 natlab factory") {
		t.Fatalf("Gate B3 constructor mutation was not detected: %v", violations)
	}
}

func TestGateB3BoundaryDetectsConntrackAuthorityMutation(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "product.go")
	if err := os.WriteFile(filename, []byte(`package product
const forbiddenKernelControl = "net.netfilter.nf_conntrack_max"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := gateB3ConntrackAuthorityViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	if !containsLineFragment(violations, "product.go controls the Gate B3 host conntrack ceiling") {
		t.Fatalf("Gate B3 conntrack authority mutation was not detected: %v", violations)
	}
}

func gateB3AuthorityViolations(root string) ([]string, error) {
	identifiers := map[string]struct{}{
		"ProfilePhase1HardNATCampaign":      {},
		"PairingRecordClassHardNATCampaign": {},
		"HardNATCampaignNATLabFactory":      {},
		"NewGateB3NATLabFactory":            {},
		"NewGateB3ENOBUFSNATLabFactory":     {},
		"GateB3TestConsumer":                {},
		"PromoteToHardNATCampaignLease":     {},
		"HardNATLabFactory":                 {},
	}
	allowed := map[string]map[string]struct{}{
		"internal/governor/limits.go": {
			"ProfilePhase1HardNATCampaign": {},
		},
		"internal/governor/governor.go": {
			"ProfilePhase1HardNATCampaign": {},
		},
		"internal/governor/hard_nat_campaign_ledger.go": {
			"PairingRecordClassHardNATCampaign": {},
		},
		"internal/governor/pairing_gate.go": {
			"ProfilePhase1HardNATCampaign": {},
		},
		"internal/governor/pairing_ledger.go": {
			"PairingRecordClassHardNATCampaign": {},
		},
		"internal/governor/pairing_ledger_format.go": {
			"PairingRecordClassHardNATCampaign": {},
		},
		"internal/probeio/probeio.go": {
			"HardNATCampaignNATLabFactory": {}, "GateB3TestConsumer": {}, "PromoteToHardNATCampaignLease": {},
		},
		"internal/probeio/transport_lease.go": {
			"GateB3TestConsumer": {},
		},
		"internal/probeio/gate_b3_natlab_linux.go": {
			"HardNATCampaignNATLabFactory": {}, "NewGateB3NATLabFactory": {}, "NewGateB3ENOBUFSNATLabFactory": {},
		},
		"internal/v2/hardnatbudget/budget.go": {
			"ProfilePhase1HardNATCampaign": {},
		},
		"internal/v2/directconnect/gateb/types.go": {
			"HardNATCampaignNATLabFactory": {}, "HardNATLabFactory": {},
		},
		"internal/v2/directconnect/gateb/connect.go": {
			"PairingRecordClassHardNATCampaign": {}, "GateB3TestConsumer": {},
			"PromoteToHardNATCampaignLease": {}, "HardNATLabFactory": {},
		},
		// The sole OS-capable constructor consumer is added by the required
		// linux+natlab endpoint harness. All other tests use capability-free fakes.
		"test/natlab/gate_b3_endpoint_linux_test.go": {
			"NewGateB3NATLabFactory": {}, "NewGateB3ENOBUFSNATLabFactory": {},
			"HardNATCampaignNATLabFactory": {}, "HardNATLabFactory": {}, "ProfilePhase1HardNATCampaign": {},
		},
	}
	return scanGateB3Identifiers(root, identifiers, allowed)
}

func scanGateB3Identifiers(root string, identifiers map[string]struct{}, allowed map[string]map[string]struct{}) ([]string, error) {
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
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		// Unit and integration tests may inspect the capability, but only the
		// exact natlab endpoint may construct the OS-capable factory.
		if strings.HasSuffix(relative, "_test.go") && relative != "test/natlab/gate_b3_endpoint_linux_test.go" {
			return nil
		}
		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if _, watched := identifiers[identifier.Name]; !watched {
				return true
			}
			if approvedGateC1bNATLabAdapter(root, relative) &&
				(identifier.Name == "NewGateB3NATLabFactory" || identifier.Name == "HardNATLabFactory") {
				return true
			}
			if names := allowed[relative]; names != nil {
				if _, approved := names[identifier.Name]; approved {
					return true
				}
			}
			position := fset.Position(identifier.Pos())
			violations = append(violations, fmt.Sprintf("%s:%d references Gate B3 authority %s", relative, position.Line, identifier.Name))
			return true
		})
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateB3NATLabAuthorityViolations(root string) ([]string, error) {
	filename := filepath.Join(root, "internal", "probeio", "gate_b3_natlab_linux.go")
	if payload, err := os.ReadFile(filename); err == nil {
		normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
		if !strings.HasPrefix(normalized, "//go:build linux && natlab\n") {
			return []string{"internal/probeio/gate_b3_natlab_linux.go lacks exact linux+natlab build constraint"}, nil
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	const allowedConsumer = "test/natlab/gate_b3_endpoint_linux_test.go"
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
			selector, ok := node.(*ast.SelectorExpr)
			constructor := ok && (selector.Sel.Name == "NewGateB3NATLabFactory" || selector.Sel.Name == "NewGateB3ENOBUFSNATLabFactory")
			if constructor && relative != allowedConsumer && relative != "internal/probeio/gate_b3_natlab_linux.go" &&
				!(selector.Sel.Name == "NewGateB3NATLabFactory" && approvedGateC1bNATLabAdapter(root, relative)) {
				violations = append(violations, relative+" constructs sealed Gate B3 natlab factory")
			}
			return true
		})
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func gateB3CallShapeViolations(root string) ([]string, error) {
	type call struct {
		selector string
		want     int
	}
	filename := filepath.Join(root, "internal", "v2", "directconnect", "gateb", "connect.go")
	var violations []string
	for _, item := range []call{
		{selector: "GateB3TestConsumer", want: 1},
		{selector: "PromoteToHardNATCampaignLease", want: 1},
		{selector: "NewGateB3NATLabFactory", want: 0},
		{selector: "NewGateB3ENOBUFSNATLabFactory", want: 0},
	} {
		actual, err := gateB3SelectorCount(filename, item.selector)
		if err != nil {
			return nil, err
		}
		if actual != item.want {
			violations = append(violations, fmt.Sprintf("internal/v2/directconnect/gateb/connect.go probeio.%s count=%d want=%d", item.selector, actual, item.want))
		}
	}
	return violations, nil
}

func gateB3ConntrackAuthorityViolations(root string) ([]string, error) {
	const key = "net.netfilter.nf_conntrack_max"
	allowed := map[string]struct{}{
		"internal/architecture/gate_b3_boundary_test.go": {},
		"test/natlab/gate_b3_netns_linux_test.go":        {},
		"test/natlab/run_gate_b3_required_linux.sh":      {},
	}
	var violations []string
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "docs") {
				return filepath.SkipDir
			}
			return nil
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".go" && extension != ".sh" && extension != ".yml" && extension != ".yaml" {
			return nil
		}
		payload, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		if !strings.Contains(string(payload), key) {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, ok := allowed[relative]; !ok {
			violations = append(violations, relative+" controls the Gate B3 host conntrack ceiling")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	script := filepath.Join(root, "test", "natlab", "run_gate_b3_required_linux.sh")
	if payload, err := os.ReadFile(script); err == nil {
		text := strings.ReplaceAll(string(payload), "\r\n", "\n")
		for _, required := range []string{
			"WINKYOU_GATE_B3_DISPOSABLE_RUNNER", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT",
			"/proc/self/ns/net", "/proc/1/ns/net", "flock -n 9",
			"restore_gate_b3_conntrack_cap", "stop_gate_b3_child_group", "setsid --wait",
			"trap finish_gate_b3_guard EXIT",
			"original_cap < gate_b3_cap",
		} {
			if !strings.Contains(text, required) {
				violations = append(violations, "test/natlab/run_gate_b3_required_linux.sh lacks guard "+required)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	sort.Strings(violations)
	return violations, nil
}

func gateB3SelectorCount(filename, selectorName string) (int, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		return 0, err
	}
	count := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == selectorName {
			count++
		}
		return true
	})
	return count, nil
}
