package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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

func TestPairingAdmissionGateHasNoProductionConsumer(t *testing.T) {
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
		t.Fatalf("pairing admission gate gained a production consumer before carrier review:\n%s", strings.Join(violations, "\n"))
	}
}
