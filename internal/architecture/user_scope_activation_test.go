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

func TestUserScopeActivationScannerDetectsAliasedCapabilityReferences(t *testing.T) {
	root := t.TempDir()
	source := `package remote
import safety "winkyou/internal/governor"
var acquire = safety.AcquireRestrictedUserGovernor
var construct = safety.NewRestrictedUserGovernor
`
	if err := os.WriteFile(filepath.Join(root, "remote.go"), []byte(source), 0o600); err != nil {
		t.Fatalf("write scanner fixture: %v", err)
	}
	findings, err := scanGovernorCapabilityReferences(root)
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	want := []string{
		"remote.go | AcquireRestrictedUserGovernor",
		"remote.go | NewRestrictedUserGovernor",
	}
	if strings.Join(findings, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings = %#v, want %#v", findings, want)
	}
}

func TestUserAcknowledgedAuthorityHasOneProductionActivationLayer(t *testing.T) {
	root := repositoryRoot(t)
	findings, err := scanGovernorCapabilityReferences(root)
	if err != nil {
		t.Fatalf("scan user authority references: %v", err)
	}
	want := []string{"internal/diagnose/report.go | AcquireRestrictedUserGovernor"}
	if strings.Join(findings, "\n") != strings.Join(want, "\n") {
		t.Fatalf(
			"user-acknowledged authority activation boundary changed\n\ngot:\n%s\n\nwant:\n%s",
			strings.Join(findings, "\n"),
			strings.Join(want, "\n"),
		)
	}
}

func scanGovernorCapabilityReferences(root string) ([]string, error) {
	var findings []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return err
		}
		aliases := make(map[string]struct{})
		for _, declaration := range parsed.Imports {
			if declaration.Path == nil || strings.Trim(declaration.Path.Value, `"`) != modulePath+"/internal/governor" {
				continue
			}
			alias := "governor"
			if declaration.Name != nil {
				alias = declaration.Name.Name
			}
			if alias == "." {
				return fmt.Errorf("%s uses a dot import for internal/governor", filename)
			}
			aliases[alias] = struct{}{}
		}
		if len(aliases) == 0 {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, ok := aliases[qualifier.Name]; !ok {
				return true
			}
			switch selector.Sel.Name {
			case "AcquireRestrictedUserGovernor", "NewRestrictedUserGovernor":
				findings = append(findings, relative+" | "+selector.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(findings)
	return findings, nil
}
