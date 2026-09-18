package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureTimingCaptureValid(source []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		return false
	}
	registrations, captures := 0, 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runGateC1bMemoryProductProfile" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "persistTiming" {
					captures++
				}
			}
			return true
		})
		for _, stmt := range fn.Body.List {
			expr, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expr.X.(*ast.CallExpr)
			if !ok || !fixtureTimingSelector(call.Fun, "t", "Cleanup") || len(call.Args) != 1 {
				continue
			}
			callback, ok := call.Args[0].(*ast.FuncLit)
			if !ok || len(callback.Body.List) != 1 {
				continue
			}
			statement, ok := callback.Body.List[0].(*ast.ExprStmt)
			if !ok {
				continue
			}
			capture, ok := statement.X.(*ast.CallExpr)
			if !ok || !fixtureTimingSelector(capture.Fun, "phases", "persistTiming") || len(capture.Args) != 3 {
				continue
			}
			valid := true
			for i, want := range []string{"t", "test", "windows"} {
				name, ok := capture.Args[i].(*ast.Ident)
				valid = valid && ok && name.Name == want
			}
			if valid {
				registrations++
			}
		}
	}
	return registrations == 1 && captures == 1
}

func fixtureTimingSelector(expr ast.Expr, owner, method string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	name, ok := sel.X.(*ast.Ident)
	return ok && name.Name == owner && sel.Sel.Name == method
}

func TestGateC1bFixtureTimingCaptureContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "internal", "governor", "gate_c1b_product_pipeline_c1bproof_test.go"))
	if err != nil || !fixtureTimingCaptureValid(data) {
		t.Fatal("common memory entry must capture success and failure once at unconditional test cleanup")
	}
}

func TestGateC1bFixtureTimingCaptureMutations(t *testing.T) {
	const registration = "t.Cleanup(func() { phases.persistTiming(t, test, windows) })"
	const source = "package fixture; func runGateC1bMemoryProductProfile() { " + registration + " }"
	if !fixtureTimingCaptureValid([]byte(source)) {
		t.Fatal("valid capture contract rejected")
	}
	for _, mutation := range []string{
		"", "if t.Failed() { " + registration + " }",
		"t.Cleanup(func() { if t.Failed() { phases.persistTiming(t, test, windows) } })",
		"defer phases.persistTiming(t, test, windows)",
		"t.Cleanup(func() { phases.persistTiming(t, test, replacement) })",
		registration + "; " + registration,
	} {
		if fixtureTimingCaptureValid([]byte(strings.Replace(source, registration, mutation, 1))) {
			t.Fatal("conditional, duplicate, early or wrong-source capture accepted")
		}
	}
}
