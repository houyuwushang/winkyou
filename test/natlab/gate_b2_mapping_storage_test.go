package natlab

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// APDM creates one mapping per target, not one 512-target map per socket.
// Start sparse for both modes; an EIM mapping still grows without a new limit.
// This is storage only: admission, expiry/clear and source filtering stay with
// the single router owner. No socket or goroutine is constructed here.
func newGateB2AllowedSources() map[netip.AddrPort]struct{} {
	return make(map[netip.AddrPort]struct{})
}

func TestGateB3MappingSparseSourceSemantics(t *testing.T) {
	left, right := newGateB2AllowedSources(), newGateB2AllowedSources()
	address := netip.MustParseAddr("192.0.2.1")
	for port := uint16(1); port <= 1024; port++ {
		left[netip.AddrPortFrom(address, port)] = struct{}{}
	}
	if len(left) != 1024 || len(right) != 0 {
		t.Fatal("sparse storage added a target cap or shared ownership")
	}
	if _, ok := left[netip.AddrPortFrom(address, 1025)]; ok {
		t.Fatal("unregistered source became allowed")
	}
	clear(left)
	if len(left) != 0 {
		t.Fatal("expiry did not clear all allowed sources")
	}
	left[netip.AddrPortFrom(address, 1025)] = struct{}{}
	if len(left) != 1 || len(right) != 0 {
		t.Fatal("storage cannot be reused after expiry")
	}
}

func TestGateB3MappingSparseConstructorRegression(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			data, err = os.ReadFile(filepath.Join("test", "natlab", name))
		}
		if err != nil {
			t.Fatal("actual NAT fixture source unavailable")
		}
		return string(data)
	}
	constructor := read("gate_b2_mapping_storage_test.go")
	sparse := func(source string) bool {
		file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
		if err != nil {
			return false
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "newGateB2AllowedSources" || fn.Body == nil || len(fn.Body.List) != 1 {
				continue
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return false
			}
			call, ok := ret.Results[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return false
			}
			name, ok := call.Fun.(*ast.Ident)
			_, mapType := call.Args[0].(*ast.MapType)
			return ok && name.Name == "make" && mapType
		}
		return false
	}
	if !sparse(constructor) {
		t.Fatal("mapping storage eagerly reserves unrelated targets")
	}
	old := strings.Replace(constructor, "return make(map[netip.AddrPort]struct{})", "return make(map[netip.AddrPort]struct{}, 512)", 1)
	if old == constructor || sparse(old) {
		t.Fatal("512-entry-per-mapping regression was not rejected")
	}
	fixture := read("gate_b2_nat_linux_test.go")
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", fixture, 0)
	if err != nil {
		t.Fatal("NAT fixture did not parse")
	}
	count, bad := 0, false
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		name, ok := literal.Type.(*ast.Ident)
		if !ok || name.Name != "gateB2NATMapping" {
			return true
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			if !ok || key.Name != "allowed" {
				continue
			}
			count++
			call, ok := field.Value.(*ast.CallExpr)
			if !ok || len(call.Args) != 0 {
				bad = true
				continue
			}
			function, ok := call.Fun.(*ast.Ident)
			bad = bad || !ok || function.Name != "newGateB2AllowedSources"
		}
		return true
	})
	if count != 1 || bad {
		t.Fatal("real NAT mapping bypasses sparse storage")
	}
}

var gateB2AllowedSourcesBenchmarkSink map[netip.AddrPort]struct{}

// Fixed-iteration -benchmem measures the real constructor against the old
// allocation expression; it does not infer CI memory pressure from a PASS.
func BenchmarkGateB3AllowedSourceStorage(b *testing.B) {
	for _, test := range []struct {
		name string
		make func() map[netip.AddrPort]struct{}
	}{
		{"old_512_hint", func() map[netip.AddrPort]struct{} { return make(map[netip.AddrPort]struct{}, 512) }},
		{"sparse", newGateB2AllowedSources},
	} {
		b.Run(test.name, func(b *testing.B) {
			target := netip.MustParseAddrPort("192.0.2.1:1")
			b.ReportAllocs()
			for range b.N {
				allowed := test.make()
				allowed[target] = struct{}{}
				gateB2AllowedSourcesBenchmarkSink = allowed
			}
			gateB2AllowedSourcesBenchmarkSink = nil
		})
	}
}
