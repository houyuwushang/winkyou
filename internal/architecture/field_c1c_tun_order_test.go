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

func fieldTUNNetpollOrder(source string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "field_tun.go", source, 0)
	if err != nil {
		return false
	}
	var opened, configured, nonblocking, wrapped token.Pos
	var calls int
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "NewFieldInterface" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch owner.Name + "." + selector.Sel.Name {
			case "unix.Open":
				opened = call.Pos()
				calls++
			case "unix.Syscall":
				configured = call.Pos()
				calls++
			case "unix.SetNonblock":
				if len(call.Args) != 2 {
					return true
				}
				fd, first := call.Args[0].(*ast.Ident)
				enabled, second := call.Args[1].(*ast.Ident)
				if first && second && fd.Name == "fd" && enabled.Name == "true" {
					nonblocking = call.Pos()
					calls++
				}
			case "os.NewFile":
				wrapped = call.Pos()
				calls++
			}
			return true
		})
	}
	return calls == 4 && opened.IsValid() && opened < configured && configured < nonblocking && nonblocking < wrapped
}

func TestFieldC1cTUNConfiguredBeforeNetpoll(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "pkg", "netif", "field_tun_linux.go"))
	if err != nil {
		t.Fatal("field source unavailable")
	}
	if !fieldTUNNetpollOrder(string(source)) {
		t.Fatal("TUN must complete open, exclusive ioctl and nonblock before os.NewFile")
	}
	statement := "file = os.NewFile(uintptr(fd), \"owned-field-tun\")"
	if strings.Count(string(source), statement) != 1 {
		t.Fatal("TUN netpoll ownership seam changed")
	}
	mutant := strings.Replace(string(source), statement, "", 1)
	mutant = strings.Replace(mutant, "request, err := unix.NewIfreq", statement+"\nrequest, err := unix.NewIfreq", 1)
	if fieldTUNNetpollOrder(mutant) {
		t.Fatal("early netpoll wrapping mutant accepted")
	}
}
