package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
)

const loopbackTerminationProducer = "internal/governor/loopback_termination.go"

func loopbackTerminationReferences(path string, file *ast.File) error {
	var violation error
	ast.Inspect(file, func(node ast.Node) bool {
		id, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		switch id.Name {
		case "AcquireLoopbackAttempt", "RegisterLoopbackPreFinish":
			if path != loopbackTerminationProducer && path != terminalRevokeConsumer {
				violation = fmt.Errorf("unreviewed two-phase consumer: %s", path)
			}
		case "registerPairingDrain":
			if path != loopbackTerminationProducer && path != "internal/governor/pairing_gate.go" {
				violation = fmt.Errorf("unreviewed accounting drain: %s", path)
			}
		}
		return true
	})
	return violation
}

func TestLoopbackTwoPhaseCapabilityConsumers(t *testing.T) {
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
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		if err := loopbackTerminationReferences(filepath.ToSlash(rel), file); err != nil {
			t.Error(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if governor.LoopbackFinalizationTimeout != 15*time.Second {
		t.Fatal("accounting bound changed")
	}
}

func terminalFunction(source []byte, name string) (*ast.FuncDecl, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "boundary.go", source, 0)
	if err != nil {
		return nil, err
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn, nil
		}
	}
	return nil, fmt.Errorf("missing function %s", name)
}

func twoPhaseWriterOrder(source []byte) error {
	fn, err := terminalFunction(source, "finishLoopback")
	if err != nil {
		return err
	}
	positions := map[string][]token.Pos{}
	forbidden := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		positions[sel.Sel.Name] = append(positions[sel.Sel.Name], call.Pos())
		if sel.Sel.Name == "Close" || sel.Sel.Name == "releaseAttemptLocked" {
			forbidden = true
		}
		return true
	})
	previous := token.NoPos
	for _, name := range []string{"preFinishHook", "awaitLoopbackNetwork", "Finish", "recordLoopbackFinishError", "Complete"} {
		calls := positions[name]
		if len(calls) != 1 || calls[0] <= previous {
			return fmt.Errorf("invalid single-writer order: %s", name)
		}
		previous = calls[0]
	}
	if forbidden {
		return fmt.Errorf("writer gained early lease release")
	}
	return nil
}

func twoPhaseCarrierSetup(source []byte) error {
	fn, err := terminalFunction(source, "run")
	if err != nil {
		return err
	}
	var hook, controller, publish, open token.Pos
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "RegisterLoopbackPreFinish":
			hook = call.Pos()
		case "New":
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "probeio" {
				controller = call.Pos()
			}
		case "publish":
			publish = call.Pos()
		case "OpenProbeSocket":
			open = call.Pos()
		}
		return true
	})
	if hook == token.NoPos || !(hook < controller && controller < publish && publish < open) {
		return fmt.Errorf("hook/controller publication order changed")
	}
	return nil
}

func TestLoopbackTwoPhaseOrderAndMutations(t *testing.T) {
	root := repositoryRoot(t)
	producer, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(loopbackTerminationProducer)))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(terminalRevokeConsumer)))
	if err != nil {
		t.Fatal(err)
	}
	if err := twoPhaseWriterOrder(producer); err != nil {
		t.Fatal(err)
	}
	if err := twoPhaseCarrierSetup(consumer); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, from, to string }{
		{"no-revoke", "c.preFinishHook()", "nil"},
		{"double-hook", "hookErr = c.preFinishHook()", "hookErr = c.preFinishHook(); _ = c.preFinishHook()"},
		{"no-network-witness", "c.attempt.awaitLoopbackNetwork()", "nil"},
		{"close-lease-in-hook", "hookErr = c.preFinishHook()", "hookErr = c.preFinishHook(); _ = c.attempt.Close()"},
		{"revoke-after-finish", "hookErr = c.preFinishHook()", "hookErr = c.ledger.Finish(c.receipt, reason); _ = c.preFinishHook()"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(string(producer), mutation.from, mutation.to, 1)
			if changed == string(producer) {
				t.Fatal("mutation did not alter source")
			}
			if twoPhaseWriterOrder([]byte(changed)) == nil {
				t.Fatal("unsafe writer mutation escaped")
			}
		})
	}
	for _, path := range []string{"cmd/wink/main.go", "internal/solverstdio/handler.go", "internal/v2/directconnect/gateb/connect.go", "internal/v2/directconnect/gatea/connect.go", "pkg/meshruntime/runtime.go", "internal/v2/loopbackcarrier/other.go"} {
		for _, body := range []string{"peer.AcquireLoopbackAttempt(ctx, request)", "f := auth.RegisterLoopbackPreFinish; _ = f", "f := (*governor.CommittedCarrierAuthorization).RegisterLoopbackPreFinish; _ = f"} {
			file, err := parser.ParseFile(token.NewFileSet(), "mutation.go", "package mutation; func f(){"+body+"}", 0)
			if err != nil {
				t.Fatal(err)
			}
			if loopbackTerminationReferences(path, file) == nil {
				t.Fatalf("unreviewed consumer escaped: %s", path)
			}
		}
	}
}
