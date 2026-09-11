package architecture

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Presentation-I/O ownership is intentionally narrow. As with selection's
// frozen boundary functions, changing these small concurrency primitives needs
// an explicit contract/test review, not just updating an expected hash to green.
// format.Node canonicalization ignores source line endings (Windows included).
var runtimeSnapshotContractFunctions = map[string]string{
	"pkg/client/engine.go:persistState":                              "a48289e23825b3f64b5a7139ec38fb57b033eed7f1ba8c5ca8b4131b372823e3",
	"pkg/client/engine.go:runtimeSnapshotWriterLocked":               "d419ee45a2060a26ade2cc8d2647fb0d225de6e550dd16b7e91aecbdd063b07e",
	"pkg/client/runtime_snapshot_writer.go:newRuntimeSnapshotWriter": "f2d7b53da7f102cfcf73b6f0abef72d23c9712b511c8184ec5f3b79f9766f755",
	"pkg/client/runtime_snapshot_writer.go:request":                  "30af723e7e3e0dad6a9e51d3d72e0c2c4525abd1f5eae08f952ad155e7d95c0c",
	"pkg/client/runtime_snapshot_writer.go:seal":                     "347892fa71f58e73bd8f1d1411b9da4c7f918845bc7a2e0d106dca7ba0f904fb",
	"pkg/client/runtime_snapshot_writer.go:run":                      "2c53d6998a3351cee93f98c5b03e2cdd8b2cfc47438a61ba83d9abf1b3e6252d",
	"pkg/client/runtime_snapshot_writer.go:wait":                     "2ee53827af229a3c8ad4ef921516814af6ca349d574c5f3ab477085d183bdb42",
	"pkg/client/runtime_io_lock.go:lockRuntimeFile":                  "6a9e996eadc4be9143cddc5d3b29313101debb4fae93cb200f694fc73671d4e1",
	"pkg/client/runtime_io_lock.go:runtimeFileLockKey":               "63fb4da829bf0225417b47a2e02f83858526259c0059b2bfed357048788b3bd6",
}

func runtimeSnapshotBoundaryViolations(sources map[string]string) []string {
	var violations []string
	for key, want := range runtimeSnapshotContractFunctions {
		parts := strings.SplitN(key, ":", 2)
		body := selectionFunction(sources[parts[0]], parts[1])
		if body == "" || fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != want {
			violations = append(violations, "snapshot concurrency contract changed: "+key)
		}
	}
	require := func(file, name string, parts ...string) {
		body := selectionFunction(sources[file], name)
		for _, part := range parts {
			if !strings.Contains(body, part) {
				violations = append(violations, file+":"+name+":missing "+part)
			}
		}
	}
	require("pkg/client/engine.go", "Start", "if e.stopping || e.snapshotWriter != nil {\n\t\te.mu.Unlock()\n\t\treturn ErrRuntimeSnapshotDrainPending\n\t}", "stopErr := e.Stop()", "err = errors.Join(err, stopErr)", "e.mu.Lock()\n\te.tun = tun\n\te.mu.Unlock()")
	require("pkg/client/engine.go", "Stop", "if !e.stopMu.TryLock() {\n\t\treturn ErrRuntimeSnapshotDrainPending\n\t}", "defer e.stopMu.Unlock()", "if !e.started && !e.stopping", "e.stopping = true", "writer.seal()", "context.WithTimeout(context.Background(), runtimeSnapshotDrainTimeout)", "if err := writer.wait(ctx); err != nil {", "return errors.Join(err, e.stopErr)", "e.snapshotWriter = nil", "e.stopping = false")
	stop := selectionFunction(sources["pkg/client/engine.go"], "Stop")
	if strings.Index(stop, "writer.seal()") >= strings.Index(stop, "e.wg.Wait()") || strings.Index(stop, "writer.wait(ctx)") >= strings.Index(stop, "e.snapshotWriter = nil") {
		violations = append(violations, "seal/network-cleanup/join/release ordering changed")
	}
	for _, op := range []struct{ name, read string }{{"LoadRuntimeState", "true"}, {"WriteRuntimeState", "false"}, {"RemoveRuntimeState", "false"}, {"RemoveRuntimeStateIfInstance", "false"}} {
		require("pkg/client/runtime.go", op.name, "unlock, err := lockRuntimeFile(path, "+op.read+")", "defer unlock()")
	}
	if !strings.Contains(sources["pkg/client/runtime_snapshot_writer.go"], "const runtimeSnapshotDrainTimeout = 2 * time.Second") {
		violations = append(violations, "presentation drain wait changed")
	}
	if strings.Contains(sources["pkg/client/runtime.go"], "runtimeStateIOMu") {
		violations = append(violations, "package-global all-file I/O lock restored")
	}
	constructors, literals := 0, 0
	for filename, source := range sources {
		if !strings.HasPrefix(filename, "pkg/client/") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
		if err != nil {
			violations = append(violations, filename+":parse")
			continue
		}
		if filename == "pkg/client/runtime_snapshot_writer.go" || filename == "pkg/client/runtime_io_lock.go" {
			aliases, _, err := sourceImports(file)
			if err != nil {
				violations = append(violations, filename+":imports")
			}
			for _, path := range aliases {
				switch path {
				case "context", "errors", "sync", "time", "path/filepath", "runtime", "strings":
				default:
					violations = append(violations, filename+":unapproved capability "+path)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.Ident:
				if n.Name == "newRuntimeSnapshotWriter" {
					constructors++
					if filename != "pkg/client/engine.go" && filename != "pkg/client/runtime_snapshot_writer.go" {
						violations = append(violations, filename+":unapproved writer constructor reference")
					}
				}
			case *ast.CompositeLit:
				if name, ok := n.Type.(*ast.Ident); ok && name.Name == "runtimeSnapshotWriter" {
					literals++
					if filename != "pkg/client/runtime_snapshot_writer.go" {
						violations = append(violations, filename+":writer literal outside owner")
					}
				}
			}
			return true
		})
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Name.Name == "runtimeSnapshotWriterLocked" {
				continue
			}
			receiver, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			name, ok := receiver.X.(*ast.Ident)
			if !ok || name.Name != "engine" {
				continue
			}
			// Inspect identifiers, not only calls, so a function alias cannot
			// move synchronous snapshot I/O back onto an engine callback.
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if id, ok := node.(*ast.Ident); ok {
					switch id.Name {
					case "WriteRuntimeState", "LoadRuntimeState", "RemoveRuntimeState", "RemoveRuntimeStateIfInstance", "atomicWriteRuntimeFile", "lockRuntimeFile":
						violations = append(violations, filename+":"+fn.Name.Name+":synchronous snapshot I/O")
					}
				}
				return true
			})
		}
	}
	if constructors != 2 || literals != 1 { // declaration + one owner call; one allocation
		violations = append(violations, "snapshot writer has additional construction paths")
	}
	return violations
}

func TestRuntimeSnapshotProductionBoundary(t *testing.T) {
	if violations := runtimeSnapshotBoundaryViolations(selectionProductionSources(t)); len(violations) != 0 {
		t.Fatal(strings.Join(violations, "\n"))
	}
}

func TestRuntimeSnapshotBoundaryDetectsMutations(t *testing.T) {
	base := selectionProductionSources(t)
	mutations := []struct{ file, old, replacement string }{
		{"pkg/client/engine.go", "writer.request()", "WriteRuntimeState(e.statePath, nil)"},
		{"pkg/client/engine.go", "writer.request()", "go writer.request()"},
		{"pkg/client/engine.go", "e.stopping || e.snapshotWriter != nil", "false"},
		{"pkg/client/engine.go", "writer.seal()", "writer.request()"},
		{"pkg/client/engine.go", "if err := writer.wait(ctx); err != nil {", "if err := error(nil); err != nil {"},
		{"pkg/client/engine.go", "return errors.Join(err, e.stopErr)", "return nil"},
		{"pkg/client/engine.go", "stopErr := e.Stop()", "stopErr := error(nil)"},
		{"pkg/client/runtime_snapshot_writer.go", "make(chan struct{}, 1)", "make(chan struct{}, 8)"},
		{"pkg/client/runtime_snapshot_writer.go", "w.write()", "go w.write()"},
		{"pkg/client/runtime_snapshot_writer.go", "w.write()", "w.remove(); w.write()"},
		{"pkg/client/runtime_snapshot_writer.go", "return ErrRuntimeSnapshotDrainPending", "return nil"},
		{"pkg/client/runtime_snapshot_writer.go", "if w.closing {", "if false {"},
		{"pkg/client/runtime_snapshot_writer.go", "2 * time.Second", "20 * time.Second"},
		{"pkg/client/runtime_snapshot_writer.go", "\"context\"", "\"context\"; sockets \"net\""},
		{"pkg/client/runtime_io_lock.go", "filepath.Abs(RuntimeStatePath(path))", "filepath.Abs(\"one-global-lock\")"},
		{"pkg/client/runtime_io_lock.go", "entry.refs++", "entry.refs = 1"},
		{"pkg/client/runtime_io_lock.go", "delete(runtimeFileLocks.entries, key)", "_ = key"},
		{"pkg/client/runtime_io_lock.go", "entry.mu.Lock()", "runtimeFileLocks.Lock(); entry.mu.Lock()"},
		{"pkg/client/runtime.go", "unlock, err := lockRuntimeFile(path, true)", "unlock, err := lockRuntimeFile(\"one-global-lock\", true)"},
		{"pkg/client/peer_manager.go", "e.persistState()", "write := WriteRuntimeState; _ = write(e.statePath, nil)"},
		{"pkg/client/engine.go", "e.mu.Lock()\n\te.tun = tun\n\te.mu.Unlock()", "e.tun = tun"},
		{"pkg/client/engine.go", "if !e.stopMu.TryLock()", "if false"},
	}
	for i, mutation := range mutations {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			sources := make(map[string]string, len(base))
			for key, source := range base {
				sources[key] = strings.ReplaceAll(source, "\r\n", "\n")
			}
			if !strings.Contains(sources[mutation.file], mutation.old) {
				t.Fatal("mutation anchor missing")
			}
			sources[mutation.file] = strings.Replace(sources[mutation.file], mutation.old, mutation.replacement, 1)
			if len(runtimeSnapshotBoundaryViolations(sources)) == 0 {
				t.Fatal("snapshot ownership/drain mutation escaped")
			}
		})
	}
}
