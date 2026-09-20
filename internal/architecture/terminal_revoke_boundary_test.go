package architecture

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/loopbackcarrier"
)

const terminalRevokeProducer = "internal/probeio/terminal_revoke.go"
const terminalRevokeConsumer = "internal/v2/loopbackcarrier/carrier.go"

func TestTerminalRevokeHasOnlyExactLoopbackConsumer(t *testing.T) {
	root := repositoryRoot(t)
	references := 0
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
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		path = filepath.ToSlash(relative)
		ast.Inspect(parsed, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok && id.Name == "RevokeForTerminal" {
				references++
			}
			return true
		})
		if err := terminalRevokeReferences(path, parsed); err != nil {
			t.Error(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if references != 3 {
		t.Fatalf("terminal API declarations/references=%d, want producer plus loopback defer and hook", references)
	}
}

func terminalRevokeReferences(path string, parsed *ast.File) error {
	var violation error
	ast.Inspect(parsed, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Name == "RevokeForTerminal" && path != terminalRevokeProducer && path != terminalRevokeConsumer {
			violation = fmt.Errorf("%s gained terminal probe revocation", path)
		}
		return true
	})
	return violation
}

// These small reviewed bodies deliberately have no extensibility point. A
// early return, reordered FINISH, lease.Close, refund, or handoff
// capability here requires a new review, not a looser source gate. Formatting
// and comments are irrelevant; the comparison is of parsed statement trees.
const terminalRevokeBody = `{
if c == nil { return nil }
c.stopLocal()
c.handoffOnce.Do(func() { close(c.handoffDone) })
<-c.watchDone
return c.drain.Complete()
}`

const terminalFinishBody = `{
if controller != nil { err = errors.Join(err, controller.RevokeForTerminal()) }
finishErr := carrier.authorization.Finish(reason)
if finishErr != nil { err = errors.Join(err, ErrCarrierTerminal, finishErr) }
if controller != nil { err = errors.Join(err, controller.Close()) }
}`

func canonicalTerminalNode(node ast.Node) string {
	var buffer bytes.Buffer
	if err := format.Node(&buffer, token.NewFileSet(), node); err != nil {
		return "invalid"
	}
	return buffer.String()
}

func terminalBody(text string) (*ast.BlockStmt, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "contract.go", "package contract; func contract() "+text, 0)
	if err != nil {
		return nil, err
	}
	return file.Decls[0].(*ast.FuncDecl).Body, nil
}

func terminalRevokeOrder(source []byte, producer bool) error {
	parsed, err := parser.ParseFile(token.NewFileSet(), "contract.go", source, 0)
	if err != nil {
		return err
	}
	wantBody := terminalFinishBody
	if producer {
		wantBody = terminalRevokeBody
	}
	want, err := terminalBody(wantBody)
	if err != nil {
		return err
	}
	var body *ast.BlockStmt
	for _, declaration := range parsed.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if producer && fn.Name.Name == "RevokeForTerminal" {
			body = fn.Body
		}
		if !producer && fn.Name.Name == "run" {
			for _, statement := range fn.Body.List {
				deferred, ok := statement.(*ast.DeferStmt)
				if !ok {
					continue
				}
				literal, ok := deferred.Call.Fun.(*ast.FuncLit)
				if !ok {
					continue
				}
				// run currently has one deferred function literal, its terminal
				// owner. An extra literal cannot silently replace this witness.
				if body != nil {
					return fmt.Errorf("ambiguous terminal defer")
				}
				body = literal.Body
			}
		}
	}
	if body == nil || canonicalTerminalNode(body) != canonicalTerminalNode(want) {
		return fmt.Errorf("terminal revocation/drain/FINISH/Close order changed")
	}
	return nil
}

func TestTerminalRevokeOrderAndFrozenAdmission(t *testing.T) {
	for _, file := range []string{terminalRevokeProducer, terminalRevokeConsumer} {
		source, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		if err := terminalRevokeOrder(source, file == terminalRevokeProducer); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	if !terminalAdmissionUnchanged(loopbackcarrier.AttemptCost()) {
		t.Fatal("terminal revocation reduced or changed full admission")
	}
}

func terminalAdmissionUnchanged(cost governor.AttemptCost) bool {
	return cost == (governor.AttemptCost{
		Resources: governor.Resources{Sockets: 1, Targets: 1, FiveTuples: 1, Packets: 3, PacketsPerSecond: 3},
		Duration:  15 * time.Second, Heavyweight: true,
	})
}

func TestTerminalRevokeBoundaryMutations(t *testing.T) {
	for _, path := range []string{"cmd/wink/main.go", "internal/solverstdio/server.go", "internal/probeio/other.go", "internal/v2/directconnect/gatea/connect.go", "internal/v2/directconnect/gateb/connect.go", "pkg/meshruntime/runtime.go", "internal/v2/loopbackcarrier/other.go"} {
		for _, use := range []string{"c.RevokeForTerminal()", "f := c.RevokeForTerminal; _ = f", "f := (*p.Controller).RevokeForTerminal; _ = f"} {
			parsed, err := parser.ParseFile(token.NewFileSet(), "mutation.go", "package mutation; func f() { "+use+" }", 0)
			if err != nil {
				t.Fatal(err)
			}
			if terminalRevokeReferences(path, parsed) == nil {
				t.Fatalf("unauthorized reference escaped: %s", path)
			}
		}
	}
	mutations := []struct {
		name, body string
		producer   bool
	}{
		{"finish-first", strings.Replace(terminalFinishBody, "if controller != nil { err = errors.Join(err, controller.RevokeForTerminal()) }\nfinishErr := carrier.authorization.Finish(reason)", "finishErr := carrier.authorization.Finish(reason)\nif controller != nil { err = errors.Join(err, controller.RevokeForTerminal()) }", 1), false},
		{"skip-revoke", strings.Replace(terminalFinishBody, "controller.RevokeForTerminal()", "nil", 1), false},
		{"skip-finish-on-revoke-error", strings.Replace(terminalFinishBody, "finishErr :=", "if err != nil { return }; finishErr :=", 1), false},
		{"socket-still-open", strings.Replace(terminalRevokeBody, "c.stopLocal()", "", 1), true},
		{"close-lease-before-finish", strings.Replace(terminalRevokeBody, "c.stopLocal()", "c.lease.Close(); c.stopLocal()", 1), true},
		{"timer-still-running", strings.Replace(terminalRevokeBody, "c.handoffOnce.Do(func() { close(c.handoffDone) })", "", 1), true},
		{"no-watcher-witness", strings.Replace(terminalRevokeBody, "<-c.watchDone", "", 1), true},
		{"no-drain-witness", strings.Replace(terminalRevokeBody, "return c.drain.Complete()", "return nil", 1), true},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			name := "run"
			body := "{ defer func() " + mutation.body + "() }"
			if mutation.producer {
				name, body = "RevokeForTerminal", mutation.body
			}
			if err := terminalRevokeOrder([]byte("package mutation; func (c *Controller) "+name+"() "+body), mutation.producer); err == nil {
				t.Fatal("terminal order mutation escaped")
			}
		})
	}
	for _, mutate := range []func(*governor.AttemptCost){
		func(c *governor.AttemptCost) { c.Resources.Packets-- },
		func(c *governor.AttemptCost) { c.Resources.PacketsPerSecond-- },
		func(c *governor.AttemptCost) { c.Resources.Sockets-- },
		func(c *governor.AttemptCost) { c.Resources.Targets-- },
		func(c *governor.AttemptCost) { c.Resources.FiveTuples-- },
		func(c *governor.AttemptCost) { c.Duration -= time.Second },
		func(c *governor.AttemptCost) { c.Heavyweight = false },
	} {
		cost := loopbackcarrier.AttemptCost()
		mutate(&cost)
		if terminalAdmissionUnchanged(cost) {
			t.Fatal("reduced admission mutation escaped")
		}
	}
}
