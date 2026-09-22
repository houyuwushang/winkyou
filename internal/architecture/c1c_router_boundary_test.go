package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func routerBoundaryViolations(root string) ([]string, error) {
	var bad []string
	e := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		source := strings.ReplaceAll(string(b), "\r\n", "\n")
		f, e := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if e != nil {
			return e
		}
		inside := strings.HasPrefix(rel, "internal/c1crouter/") || strings.HasPrefix(rel, "cmd/c1crouter/")
		if inside {
			constraint := "//go:build linux && fieldc1c\n"
			if rel == "internal/c1crouter/model.go" {
				constraint = "//go:build fieldc1c\n"
			}
			if !strings.HasPrefix(source, constraint) {
				bad = append(bad, rel+": missing sealed tag")
			}
		}
		aliases := map[string]string{}
		for _, imported := range f.Imports {
			name, _ := strconv.Unquote(imported.Path.Value)
			alias := filepath.Base(name)
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			aliases[alias] = name
			if name == modulePath+"/internal/c1crouter" && rel != "cmd/c1crouter/main.go" {
				bad = append(bad, rel+": router consumed outside standalone command")
			}
			if inside && strings.HasPrefix(name, modulePath+"/") && name != modulePath+"/internal/c1crouter" && name != modulePath+"/internal/v2/fieldc1c" && !(rel == "internal/c1crouter/observer_linux.go" && name == modulePath+"/internal/v2/hardnatplan") {
				bad = append(bad, rel+": unapproved protocol/endpoint import")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				return true
			}
			owner := ""
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Pos() <= n.Pos() && n.End() <= fn.End() {
					owner = fn.Name.Name
				}
			}
			if selector, ok := n.(*ast.SelectorExpr); ok {
				id, _ := selector.X.(*ast.Ident)
				if id != nil && aliases[id.Name] == modulePath+"/internal/v2/hardnatplan" && inside {
					allowed := map[string]bool{"ParseBehaviorBindingRequest": true, "BuildBehaviorBindingSuccess": true, "BehaviorAttributes": true, "AddressPort": true, "Address4": true}
					if !allowed[selector.Sel.Name] {
						bad = append(bad, rel+": planner executor not authorized")
					}
				}
				if selector.Sel.Name == "LoadRouter" || selector.Sel.Name == "LoadRouterForTeardown" {
					if rel != "internal/c1crouter/command_linux.go" {
						bad = append(bad, rel+": unapproved router issuer consumer")
					}
				}
				if inside {
					switch selector.Sel.Name {
					case "Syscall", "Syscall6", "RawSyscall", "RawSyscall6":
						bad = append(bad, rel+": raw syscall escape")
					}
					if id != nil && aliases[id.Name] == "os/exec" && (selector.Sel.Name == "Command" || selector.Sel.Name == "CommandContext") {
						if !(rel == "internal/c1crouter/namespace_linux.go" && owner == "runCommand" || rel == "internal/c1crouter/command_linux.go" && owner == "runGuardian") {
							bad = append(bad, rel+": unapproved child construction")
						}
					}
				}
			}
			if id, ok := n.(*ast.Ident); ok && inside && id.Name == "writeSysctl" {
				if rel != "internal/c1crouter/guardian_linux.go" || !(owner == "acquireCeiling" || owner == "writeSysctl" || owner == "restore" || owner == "restoreInterruptedCeiling") {
					bad = append(bad, rel+": unapproved shared ceiling write")
				}
			}
			if literal, ok := n.(*ast.CompositeLit); ok && len(literal.Elts) > 0 {
				if name, ok := literal.Type.(*ast.Ident); ok && name.Name == "RouterAuthority" {
					owner := ""
					for _, decl := range f.Decls {
						if fn, ok := decl.(*ast.FuncDecl); ok && fn.Pos() <= literal.Pos() && literal.End() <= fn.End() {
							owner = fn.Name.Name
						}
					}
					if rel != "internal/v2/fieldc1c/router_v2.go" || owner != "loadRouter" {
						bad = append(bad, rel+": unapproved router token construction")
					}
				}
			}
			return true
		})
		return nil
	})
	return bad, e
}

func TestC1cRouterCeilingAuthorizationDominatesMutation(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "internal/c1crouter/guardian_linux.go")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	valid := func(data []byte) bool {
		file, e := parser.ParseFile(token.NewFileSet(), "guardian.go", data, 0)
		if e != nil {
			return false
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "acquireCeiling" {
				continue
			}
			if len(fn.Body.List) < 2 {
				return false
			}
			gate, ok := fn.Body.List[1].(*ast.IfStmt)
			if !ok {
				return false
			}
			unary, ok := gate.Cond.(*ast.UnaryExpr)
			if !ok || unary.Op != token.NOT {
				return false
			}
			field, ok := unary.X.(*ast.SelectorExpr)
			if !ok || field.Sel.Name != "AllowGlobalConntrackCeiling" || len(gate.Body.List) != 1 {
				return false
			}
			_, ok = gate.Body.List[0].(*ast.ReturnStmt)
			return ok
		}
		return false
	}
	if !valid(b) {
		t.Fatal("shared ceiling permission no longer dominates")
	}
	for _, replacement := range []string{"if snapshot.Configuration.AllowGlobalConntrackCeiling {", "if false {", "if true {"} {
		mutated := strings.Replace(string(b), "if !snapshot.Configuration.AllowGlobalConntrackCeiling {", replacement, 1)
		if valid([]byte(mutated)) {
			t.Fatal("ceiling authorization mutant escaped")
		}
	}
}
func TestC1cRouterAuthorityBoundary(t *testing.T) {
	bad, e := routerBoundaryViolations(repositoryRoot(t))
	if e != nil || len(bad) > 0 {
		t.Fatalf("router boundary: %v %v", bad, e)
	}
}
func TestC1cRouterAuthorityMutations(t *testing.T) {
	for _, mutant := range []struct{ path, source string }{
		{"cmd/wink/router.go", "package main\nimport _ \"winkyou/internal/c1crouter\""},
		{"internal/c1crouter/bypass.go", "package c1crouter"},
		{"internal/c1crouter/bypass.go", "//go:build linux && fieldc1c\n\npackage c1crouter\nimport _ \"winkyou/internal/probeio\""},
		{"internal/c1crouter/observer_linux.go", "//go:build linux && fieldc1c\n\npackage c1crouter\nimport \"winkyou/internal/v2/hardnatplan\"\nvar _ hardnatplan.Plan"},
		{"pkg/client/router.go", "package client\nvar _ = fieldc1c.LoadRouter"},
		{"internal/v2/fieldc1c/bypass.go", "//go:build fieldc1c\n\npackage fieldc1c\nfunc f(){_=RouterAuthority{value:nil}}"},
	} {
		root := t.TempDir()
		writeArchitectureMutation(t, root, mutant.path, mutant.source)
		bad, e := routerBoundaryViolations(root)
		if e != nil || len(bad) == 0 {
			t.Fatalf("router mutation escaped: %v %v", bad, e)
		}
	}
}

func routerCleanupContract(source string) bool {
	for _, fragment := range []string{"current != t.journal.value.Namespaces[i]", "\"ss\"", "\"conntrack\"", "\"-F\"", "\"-C\"", "\"netns\", \"pids\"", "\"delete\", \"table\", \"ip\", \"wycrouter\"", "unix.Unmount(path, 0)", "os.Remove(path)", "!onlyLoopback(data)", "result == nil"} {
		if !strings.Contains(source, fragment) {
			return false
		}
	}
	return true
}
func TestC1cRouterCleanupMutationContract(t *testing.T) {
	b, e := os.ReadFile(filepath.Join(repositoryRoot(t), "internal/c1crouter/cleanup_linux.go"))
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if !routerCleanupContract(s) {
		t.Fatal("router cleanup contract missing")
	}
	for _, fragment := range []string{"\"ss\"", "\"-F\"", "\"netns\", \"pids\"", "unix.Unmount(path, 0)", "os.Remove(path)", "!onlyLoopback(data)"} {
		if routerCleanupContract(strings.ReplaceAll(s, fragment, "omitted")) {
			t.Fatalf("cleanup omission escaped: %s", fragment)
		}
	}
}
