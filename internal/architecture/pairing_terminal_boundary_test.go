package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const pairingTerminalProducer = "internal/governor/pairing_gate.go"
const pairingTerminalConsumer = "internal/v2/directconnect/gateb/connect.go"

func TestPairingTerminalWitnessHasOnlyExactConsumer(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, violation := range pairingTerminalReferences(filepath.ToSlash(relative), parsed) {
			t.Error(violation)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func pairingTerminalReferences(path string, parsed *ast.File) []string {
	var violations []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		switch identifier.Name {
		case "PairingTerminalRecordedForAttempt":
			if path != pairingTerminalProducer && path != pairingTerminalConsumer {
				violations = append(violations, fmt.Sprintf("%s gained terminal witness consumption", path))
			}
		case "pairingFailureAfterFinish", "durablePairingTerminalError":
			if path != pairingTerminalProducer {
				violations = append(violations, fmt.Sprintf("%s gained terminal witness construction", path))
			}
		}
		return true
	})
	return violations
}

func TestPairingTerminalWitnessBoundaryMutations(t *testing.T) {
	for _, path := range []string{"cmd/wink/main.go", "internal/solverstdio/server.go", "pkg/client/peer_session.go",
		"internal/v2/loopbackcarrier/carrier.go", "internal/v2/directconnect/gatea/connect.go", "internal/governor/other.go"} {
		for _, name := range []string{"PairingTerminalRecordedForAttempt", "durablePairingTerminalError", "pairingFailureAfterFinish"} {
			parsed, err := parser.ParseFile(token.NewFileSet(), "mutation.go", "package mutation; var _ = governor."+name, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(pairingTerminalReferences(path, parsed)) != 1 {
				t.Errorf("mutation escaped: %s / %s", path, name)
			}
		}
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "approved.go", "package gateb; var _ = governor.PairingTerminalRecordedForAttempt", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairingTerminalReferences(pairingTerminalConsumer, parsed)) != 0 {
		t.Fatal("exact consumer rejected")
	}
}
