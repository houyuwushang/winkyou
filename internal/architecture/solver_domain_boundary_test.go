package architecture

import (
	"fmt"
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

func TestSolverDomainDoesNotImportWireDTOs(t *testing.T) {
	root := repositoryRoot(t)
	violations, err := solverWireImportViolations(filepath.Join(root, "pkg", "solver"))
	if err != nil {
		t.Fatalf("scan solver imports: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("solver domain imports wire DTOs:\n%s", strings.Join(violations, "\n"))
	}

	repository, err := scanRepository(root)
	if err != nil {
		t.Fatalf("scan repository dependency graph: %v", err)
	}
	if path := solverWireDependencyPath(modulePath+"/pkg/solver", repository.packages); len(path) > 0 {
		t.Fatalf("solver domain transitively depends on wire DTOs:\n%s", strings.Join(path, " -> "))
	}
}

func TestSolverWireImportScannerDetectsAliasedImports(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "types.go")
	source := []byte("package solver\nimport wire \"winkyou/pkg/rendezvous/proto\"\nvar _ wire.Capability\n")
	if err := os.WriteFile(file, source, 0o600); err != nil {
		t.Fatalf("write scanner fixture: %v", err)
	}
	violations, err := solverWireImportViolations(root)
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	want := "types.go imports winkyou/pkg/rendezvous/proto"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %#v, want %q", violations, want)
	}
}

func TestSolverWireDependencyScannerDetectsWrapper(t *testing.T) {
	packages := map[string]*packageInfo{
		modulePath + "/pkg/solver": {
			imports: map[string]struct{}{modulePath + "/pkg/wrapper": {}},
		},
		modulePath + "/pkg/wrapper": {
			imports: map[string]struct{}{modulePath + "/pkg/rendezvous/proto": {}},
		},
	}
	want := []string{
		modulePath + "/pkg/solver",
		modulePath + "/pkg/wrapper",
		modulePath + "/pkg/rendezvous/proto",
	}
	if got := solverWireDependencyPath(modulePath+"/pkg/solver", packages); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("dependency path = %#v, want %#v", got, want)
	}
}

func solverWireImportViolations(root string) ([]string, error) {
	var violations []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		parsed, err := parser.ParseFile(fset, filename, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, declaration := range parsed.Imports {
			if declaration.Path == nil {
				continue
			}
			imported, err := strconv.Unquote(declaration.Path.Value)
			if err != nil {
				return fmt.Errorf("parse import in %s: %w", filename, err)
			}
			if !isSolverWirePackage(imported) {
				continue
			}
			relative, err := filepath.Rel(root, filename)
			if err != nil {
				return err
			}
			violations = append(violations, filepath.ToSlash(relative)+" imports "+imported)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(violations)
	return violations, nil
}

func solverWireDependencyPath(start string, packages map[string]*packageInfo) []string {
	wirePackages := make(map[string]struct{})
	for _, info := range packages {
		for imported := range info.imports {
			if isSolverWirePackage(imported) {
				wirePackages[imported] = struct{}{}
			}
		}
	}
	path := capabilityDependencyPath(start, packages, wirePackages)
	if len(path) > 0 && path[len(path)-1] == "[raw network capability]" {
		path = path[:len(path)-1]
	}
	return path
}

func isSolverWirePackage(imported string) bool {
	return imported == modulePath+"/pkg/rendezvous/proto" ||
		strings.HasPrefix(imported, modulePath+"/api/proto/")
}
