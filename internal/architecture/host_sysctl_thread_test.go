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

func hostSysctlCall(node ast.Node, receiver, name string) bool {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	owner, ok := selector.X.(*ast.Ident)
	return ok && owner.Name == receiver
}

func hostSysctlReturns(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if _, ok := node.(*ast.ReturnStmt); ok {
			found = true
		}
		return true
	})
	return found
}

func hostSysctlThreadValid(source string) bool {
	if !strings.HasPrefix(source, "//go:build linux && natlab\n") {
		return false
	}
	file, err := parser.ParseFile(token.NewFileSet(), "host_sysctl_linux.go", source, 0)
	if err != nil {
		return false
	}
	var worker *ast.FuncLit
	for _, declaration := range file.Decls {
		method, ok := declaration.(*ast.FuncDecl)
		if !ok || method.Name.Name != "request" || method.Recv == nil {
			continue
		}
		ast.Inspect(method.Body, func(node ast.Node) bool {
			if launch, ok := node.(*ast.GoStmt); ok {
				worker, _ = launch.Call.Fun.(*ast.FuncLit)
			}
			return true
		})
	}
	if worker == nil {
		return false
	}
	var lock, setns, identity token.Pos
	locks, unlocks := 0, 0
	exitDeferred, initialOpen, setnsGuard, identityGuard := false, false, false, false
	var ioCalls []token.Pos
	ast.Inspect(worker, func(node ast.Node) bool {
		switch {
		case hostSysctlCall(node, "runtime", "LockOSThread"):
			locks++
			lock = node.Pos()
		case hostSysctlCall(node, "runtime", "UnlockOSThread"):
			unlocks++
		case hostSysctlCall(node, "unix", "Setns"):
			setns = node.Pos()
		case hostSysctlCall(node, "os", "ReadFile"), hostSysctlCall(node, "os", "WriteFile"):
			ioCalls = append(ioCalls, node.Pos())
		}
		if deferred, ok := node.(*ast.DeferStmt); ok && hostSysctlCall(deferred.Call, "runtime", "Goexit") {
			exitDeferred = true
		}
		if hostSysctlCall(node, "os", "Open") {
			call := node.(*ast.CallExpr)
			if len(call.Args) == 1 {
				if text, ok := call.Args[0].(*ast.BasicLit); ok {
					initialOpen = text.Value == `"/proc/1/ns/net"`
				}
			}
		}
		if condition, ok := node.(*ast.IfStmt); ok {
			if assignment, ok := condition.Init.(*ast.AssignStmt); ok {
				for _, value := range assignment.Rhs {
					if hostSysctlCall(value, "unix", "Setns") && hostSysctlReturns(condition.Body) {
						setnsGuard = true
					}
				}
			}
			inodeMismatch := false
			ast.Inspect(condition.Cond, func(child ast.Node) bool {
				if comparison, ok := child.(*ast.BinaryExpr); ok && comparison.Op == token.NEQ {
					left, lok := comparison.X.(*ast.SelectorExpr)
					right, rok := comparison.Y.(*ast.SelectorExpr)
					if lok && rok && left.Sel.Name == "Ino" && right.Sel.Name == "Ino" {
						inodeMismatch = true
					}
				}
				return true
			})
			if inodeMismatch && hostSysctlReturns(condition.Body) {
				identity = condition.Pos()
				identityGuard = true
			}
		}
		return true
	})
	if locks != 1 || unlocks != 0 || !exitDeferred || !initialOpen || !setnsGuard || !identityGuard || !(lock < setns && setns < identity) || len(ioCalls) != 2 {
		return false
	}
	for _, position := range ioCalls {
		if position < identity {
			return false
		}
	}
	return true
}

func hostSysctlDirectIOViolations(root string) ([]string, error) {
	var violations []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		source := strings.ReplaceAll(string(data), "\r\n", "\n")
		if filepath.Clean(path) == filepath.Join(root, "host_sysctl_linux.go") {
			if !hostSysctlThreadValid(source) {
				violations = append(violations, entry.Name()+" lacks thread-bound init selection")
			}
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return err
		}
		values := map[string]string{}
		literal := func(expression ast.Expr) string {
			if text, ok := expression.(*ast.BasicLit); ok && text.Kind == token.STRING {
				value, _ := strconv.Unquote(text.Value)
				return value
			}
			if name, ok := expression.(*ast.Ident); ok {
				return values[name.Name]
			}
			return ""
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if value, ok := node.(*ast.ValueSpec); ok {
				for i, expr := range value.Values {
					if i < len(value.Names) {
						values[value.Names[i].Name] = literal(expr)
					}
				}
			}
			if value, ok := node.(*ast.AssignStmt); ok {
				for i, expr := range value.Rhs {
					if i < len(value.Lhs) {
						if name, ok := value.Lhs[i].(*ast.Ident); ok {
							values[name.Name] = literal(expr)
						}
					}
				}
			}
			if hostSysctlCall(node, "os", "ReadFile") || hostSysctlCall(node, "os", "WriteFile") {
				call := node.(*ast.CallExpr)
				if len(call.Args) > 0 && strings.HasPrefix(literal(call.Args[0]), "/proc/sys/net/netfilter/") {
					violations = append(violations, entry.Name()+" bypasses HostSysctl")
				}
			}
			if call, ok := node.(*ast.CallExpr); ok {
				if function, ok := call.Fun.(*ast.Ident); ok && function.Name == "runCommand" && len(call.Args) > 0 && literal(call.Args[0]) == "sysctl" {
					violations = append(violations, entry.Name()+" bypasses host sysctl thread")
				}
			}
			return true
		})
		return nil
	})
	return violations, err
}

func TestHostSysctlThreadBoundary(t *testing.T) {
	violations, err := hostSysctlDirectIOViolations(filepath.Join(repositoryRoot(t), "test", "natlab"))
	if err != nil || len(violations) != 0 {
		t.Fatalf("host sysctl boundary: %v %v", violations, err)
	}
}

func TestHostSysctlThreadMutations(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "test/natlab/host_sysctl_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !hostSysctlThreadValid(source) {
		t.Fatal("host sysctl positive contract rejected")
	}
	for _, mutation := range []struct{ name, from, to string }{
		{"unlocked_worker", "runtime.LockOSThread()", "runtime.Gosched()"},
		{"missing_init_setns", "unix.Setns(int(initial.Fd()), unix.CLONE_NEWNET)", "unix.Fsync(int(initial.Fd()))"},
		{"return_thread_to_scheduler", "defer runtime.Goexit()", "defer runtime.UnlockOSThread()"},
		{"missing_init_identity", "threadNS.Ino != initNS.Ino", "threadNS.Ino == initNS.Ino"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(source, mutation.from, mutation.to, 1)
			if changed == source || hostSysctlThreadValid(changed) {
				t.Fatal("thread safety mutation escaped")
			}
			t.Log("RED mutation rejected")
		})
	}
	for _, call := range []string{`os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")`, `os.WriteFile(path, []byte("40000"), 0)`} {
		root := t.TempDir()
		fixture := "package natlab\nimport \"os\"\nconst path=\"/proc/sys/net/netfilter/nf_conntrack_max\"\nfunc mutate(){ " + call + " }\n"
		if err := os.WriteFile(filepath.Join(root, "escape_linux.go"), []byte(fixture), 0o600); err != nil {
			t.Fatal(err)
		}
		violations, err := hostSysctlDirectIOViolations(root)
		if err != nil || len(violations) != 1 {
			t.Fatalf("direct file I/O mutation escaped: %v %v", violations, err)
		}
	}
	t.Log("host_sysctl_mutations=6")
}
