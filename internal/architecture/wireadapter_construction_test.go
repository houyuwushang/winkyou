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

const rendezvousWirePackage = modulePath + "/pkg/rendezvous/proto"

var solverWireDTOs = map[string]struct{}{
	"Observation": {},
	"ProbeResult": {},
	"ProbeScript": {},
	"ProbeStep":   {},
}

func TestWireAdapterIsOnlyProductionConstructorForSolverWireDTOs(t *testing.T) {
	violations, err := wireDTOCompositeLiteralViolations(repositoryRoot(t))
	if err != nil {
		t.Fatalf("scan rendezvous DTO construction: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("rendezvous solver DTOs must be constructed only in pkg/session/wireadapter:\n%s", strings.Join(violations, "\n"))
	}
}

func TestWireDTOCompositeLiteralScannerDetectsAliasDotAndTypeAlias(t *testing.T) {
	root := t.TempDir()
	writeArchitectureFixture(t, root, "alias.go", `package sample
import wire "winkyou/pkg/rendezvous/proto"
var observation = wire.Observation{}
var result = &wire.ProbeResult{}
type ScriptAlias = wire.ProbeScript
var script = ScriptAlias{}
`)
	writeArchitectureFixture(t, root, "dot.go", `package sample
import . "winkyou/pkg/rendezvous/proto"
var step = ProbeStep{}
`)
	writeArchitectureFixture(t, root, "ignored_test.go", `package sample
import wire "winkyou/pkg/rendezvous/proto"
var ignored = wire.Observation{}
`)
	writeArchitectureFixture(t, root, filepath.Join("pkg", "session", "wireadapter", "adapter.go"), `package wireadapter
import wire "winkyou/pkg/rendezvous/proto"
var allowed = wire.Observation{}
`)

	violations, err := wireDTOCompositeLiteralViolations(root)
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	want := []string{
		"alias.go:3 constructs rendezvous Observation",
		"alias.go:4 constructs rendezvous ProbeResult",
		"alias.go:6 constructs rendezvous ProbeScript",
		"dot.go:3 constructs rendezvous ProbeStep",
	}
	if strings.Join(violations, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations = %#v, want %#v", violations, want)
	}
}

func wireDTOCompositeLiteralViolations(root string) ([]string, error) {
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
		if strings.HasPrefix(relative, "pkg/session/wireadapter/") {
			return nil
		}

		parsed, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			return err
		}
		aliases, dotImport, err := rendezvousImportAliases(parsed)
		if err != nil {
			return fmt.Errorf("parse imports in %s: %w", relative, err)
		}
		if len(aliases) == 0 && !dotImport {
			return nil
		}

		typeAliases := rendezvousTypeAliases(parsed, aliases, dotImport)
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			name := rendezvousDTOTypeName(literal.Type, aliases, dotImport, typeAliases)
			if name == "" {
				return true
			}
			line := fset.Position(literal.Lbrace).Line
			violations = append(violations, fmt.Sprintf("%s:%d constructs rendezvous %s", relative, line, name))
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(violations)
	return violations, nil
}

func rendezvousImportAliases(file *ast.File) (map[string]struct{}, bool, error) {
	aliases := make(map[string]struct{})
	dotImport := false
	for _, declaration := range file.Imports {
		imported, err := strconv.Unquote(declaration.Path.Value)
		if err != nil {
			return nil, false, err
		}
		if imported != rendezvousWirePackage {
			continue
		}
		if declaration.Name != nil {
			switch declaration.Name.Name {
			case ".":
				dotImport = true
			case "_":
				continue
			default:
				aliases[declaration.Name.Name] = struct{}{}
			}
			continue
		}
		aliases[filepath.Base(imported)] = struct{}{}
	}
	return aliases, dotImport, nil
}

func rendezvousTypeAliases(file *ast.File, imports map[string]struct{}, dotImport bool) map[string]string {
	aliases := make(map[string]string)
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || !typeSpec.Assign.IsValid() {
				continue
			}
			if name := rendezvousDTOTypeName(typeSpec.Type, imports, dotImport, nil); name != "" {
				aliases[typeSpec.Name.Name] = name
			}
		}
	}
	return aliases
}

func rendezvousDTOTypeName(expression ast.Expr, imports map[string]struct{}, dotImport bool, typeAliases map[string]string) string {
	switch typed := expression.(type) {
	case *ast.ParenExpr:
		return rendezvousDTOTypeName(typed.X, imports, dotImport, typeAliases)
	case *ast.StarExpr:
		return rendezvousDTOTypeName(typed.X, imports, dotImport, typeAliases)
	case *ast.SelectorExpr:
		qualifier, ok := typed.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if _, imported := imports[qualifier.Name]; !imported {
			return ""
		}
		if _, watched := solverWireDTOs[typed.Sel.Name]; watched {
			return typed.Sel.Name
		}
	case *ast.Ident:
		if name := typeAliases[typed.Name]; name != "" {
			return name
		}
		if dotImport {
			if _, watched := solverWireDTOs[typed.Name]; watched {
				return typed.Name
			}
		}
	}
	return ""
}

func writeArchitectureFixture(t *testing.T, root, relative, source string) {
	t.Helper()
	filename := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(filename, []byte(source), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", relative, err)
	}
}
