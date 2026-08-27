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

var unconnectedPairingGateIdentifiers = map[string]struct{}{
	"NewPairingAdmissionGate":       {},
	"CommittedAttempt":              {},
	"CommittedCarrierAuthorization": {},
	"ConsumeForCarrier":             {},
	"BeforeFirstEmission":           {},
}

func TestPairingAdmissionGateHasOnlyReviewedCarrierConsumer(t *testing.T) {
	root := repositoryRoot(t)
	gateFile := filepath.ToSlash(filepath.Join("internal", "governor", "pairing_gate.go"))
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
		if relative == gateFile {
			return nil
		}
		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if _, watched := unconnectedPairingGateIdentifiers[identifier.Name]; !watched {
				return true
			}
			if approvedPairingGateReference(relative, identifier.Name) {
				return true
			}
			position := fset.Position(identifier.Pos())
			violations = append(violations, fmt.Sprintf("%s:%d references %s", relative, position.Line, identifier.Name))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan pairing gate consumers: %v", err)
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("pairing admission gate escaped the exact reviewed carrier:\n%s", strings.Join(violations, "\n"))
	}
}

func TestPairingAdmissionGateApprovalIsExact(t *testing.T) {
	loopback := filepath.ToSlash(filepath.Join("internal", "v2", "loopbackcarrier", "carrier.go"))
	rendezvous := filepath.ToSlash(filepath.Join("internal", "v2", "rendezvouscarrier", "carrier.go"))
	directConnect := filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "connect.go"))
	gateA := filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go"))
	oobCarrier := filepath.ToSlash(filepath.Join("internal", "v2", "oobcarrier", "carrier.go"))
	checks := []struct {
		path       string
		identifier string
		wanted     bool
	}{
		{loopback, "NewPairingAdmissionGate", true},
		{loopback, "BeforeFirstEmission", true},
		{rendezvous, "BeforeFirstEmission", true},
		{rendezvous, "CommittedCarrierAuthorization", true},
		{rendezvous, "NewPairingAdmissionGate", false},
		{directConnect, "NewPairingAdmissionGate", true},
		{directConnect, "ConsumeForCarrier", true},
		{directConnect, "CommittedCarrierAuthorization", true},
		{directConnect, "BeforeFirstEmission", false},
		{gateA, "NewPairingAdmissionGate", true},
		{gateA, "ConsumeForCarrier", true},
		{gateA, "CommittedCarrierAuthorization", true},
		{gateA, "BeforeFirstEmission", false},
		{oobCarrier, "BeforeFirstEmission", true},
		{oobCarrier, "CommittedCarrierAuthorization", true},
		{oobCarrier, "NewPairingAdmissionGate", false},
		{oobCarrier, "ConsumeForCarrier", false},
		{filepath.ToSlash(filepath.Join("internal", "v2", "rendezvouscarrier", "child.go")), "BeforeFirstEmission", false},
		{filepath.ToSlash(filepath.Join("internal", "solverstdio", "handler.go")), "BeforeFirstEmission", false},
		{filepath.ToSlash(filepath.Join("cmd", "wink", "main.go")), "BeforeFirstEmission", false},
	}
	for _, check := range checks {
		if actual := approvedPairingGateReference(check.path, check.identifier); actual != check.wanted {
			t.Errorf("pairing gate approval for %q/%q = %t, want %t", check.path, check.identifier, actual, check.wanted)
		}
	}

	payload, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(loopback)))
	if err != nil {
		t.Fatalf("read reviewed carrier: %v", err)
	}
	for identifier := range unconnectedPairingGateIdentifiers {
		if !strings.Contains(string(payload), identifier) {
			t.Errorf("reviewed carrier no longer consumes required gate step %s", identifier)
		}
	}
	rendezvousPayload, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(rendezvous)))
	if err != nil {
		t.Fatalf("read disconnected rendezvous carrier: %v", err)
	}
	if !strings.Contains(string(rendezvousPayload), "BeforeFirstEmission") {
		t.Fatal("rendezvous carrier lost the final post-burn emission check")
	}
	if !strings.Contains(string(rendezvousPayload), "CommittedCarrierAuthorization") {
		t.Fatal("rendezvous carrier lost its concrete post-burn authorization boundary")
	}
	for _, forbidden := range []string{"NewPairingAdmissionGate", "ConsumeForCarrier", "CommittedAttempt"} {
		if strings.Contains(string(rendezvousPayload), forbidden) {
			t.Errorf("rendezvous carrier must not acquire or consume gate capability %s", forbidden)
		}
	}
	oobPayload, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(oobCarrier)))
	if err != nil {
		t.Fatalf("read Gate A bounded carrier: %v", err)
	}
	for _, required := range []string{"BeforeFirstEmission", "CommittedCarrierAuthorization"} {
		if !strings.Contains(string(oobPayload), required) {
			t.Errorf("Gate A bounded carrier lost required post-burn boundary %s", required)
		}
	}
	for _, forbidden := range []string{"NewPairingAdmissionGate", "ConsumeForCarrier", "CommittedAttempt"} {
		if strings.Contains(string(oobPayload), forbidden) {
			t.Errorf("Gate A bounded carrier must not acquire or consume gate capability %s", forbidden)
		}
	}
}

func approvedPairingGateReference(relative, identifier string) bool {
	loopback := filepath.ToSlash(filepath.Join("internal", "v2", "loopbackcarrier", "carrier.go"))
	if relative == loopback {
		_, approved := unconnectedPairingGateIdentifiers[identifier]
		return approved
	}
	rendezvous := filepath.ToSlash(filepath.Join("internal", "v2", "rendezvouscarrier", "carrier.go"))
	if relative == rendezvous {
		return identifier == "BeforeFirstEmission" || identifier == "CommittedCarrierAuthorization"
	}
	directConnect := filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "connect.go"))
	if relative == directConnect {
		return identifier == "NewPairingAdmissionGate" || identifier == "ConsumeForCarrier" ||
			identifier == "CommittedCarrierAuthorization"
	}
	gateA := filepath.ToSlash(filepath.Join("internal", "v2", "directconnect", "gatea", "connect.go"))
	if relative == gateA {
		return identifier == "NewPairingAdmissionGate" || identifier == "ConsumeForCarrier" ||
			identifier == "CommittedCarrierAuthorization"
	}
	oobCarrier := filepath.ToSlash(filepath.Join("internal", "v2", "oobcarrier", "carrier.go"))
	return relative == oobCarrier && (identifier == "BeforeFirstEmission" ||
		identifier == "CommittedCarrierAuthorization")
}
