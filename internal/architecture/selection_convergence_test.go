package architecture

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func selectionProductionSources(t *testing.T) map[string]string {
	t.Helper()
	root := repositoryRoot(t)
	sources := map[string]string{}
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filename != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		source, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		sources[filepath.ToSlash(relative)] = string(source)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sources
}

func selectionFunction(source, name string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		return ""
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || name == "newStrategyResolver" && fn.Recv == nil {
			continue
		}
		var output bytes.Buffer
		if err := format.Node(&output, fset, fn); err != nil {
			return ""
		}
		return output.String()
	}
	return ""
}

var selectionFrozenFunctions = map[string]string{
	"pkg/session/selection.go:routeStrategyMessage":        "23272efbcfd4e1df052a00f5c24ec545a3926501fcdd328f8edd96243948be54",
	"pkg/client/peer_session.go:waitSolverDispatchReady":   "5c2856107cdc94a2e50104a4643f9a7442c9c9d0ba1091c2baa5aa2d4882d56b",
	"pkg/client/strategy_factory.go:capabilityWaitTimeout": "1741899b4c571510c4deaee1071aaf129b111034d8375d7b002393568e05f1b9",
}

func selectionBoundaryViolations(sources map[string]string) []string {
	var violations []string
	constructors := 0
	for filename, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
		if err != nil {
			violations = append(violations, filename+":parse")
			continue
		}
		aliases, _, err := sourceImports(file)
		if err != nil {
			violations = append(violations, filename+":imports")
			continue
		}
		for alias, path := range aliases {
			if path == modulePath+"/pkg/session" && alias == "." {
				violations = append(violations, filename+":dot session import")
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			alias, ok := selector.X.(*ast.Ident)
			if !ok || aliases[alias.Name] != modulePath+"/pkg/session" {
				return true
			}
			if selector.Sel.Name == "New" {
				violations = append(violations, filename+":unconfirmed product constructor")
			}
			if selector.Sel.Name == "NewConverging" {
				constructors++
				if filename != "pkg/client/peer_session.go" {
					violations = append(violations, filename+":unapproved converging constructor")
				}
			}
			return true
		})
	}
	if constructors != 1 {
		violations = append(violations, "exactly one converging product constructor required")
	}
	policy := selectionFunction(sources["pkg/client/strategy_factory.go"], "newStrategyResolver")
	for _, field := range []string{"AllowImplicitLegacy", "AllowImplicitOrder", "CompatibilityDefault"} {
		if strings.Contains(policy, field) {
			violations = append(violations, "product implicit policy: "+field)
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
	require("pkg/client/peer_session.go", "newPeerRunner", "return sesspkg.NewConverging(")
	require("pkg/client/peer_session.go", "handlePeerSolverMessage", "if !e.waitSolverDispatchReady(solverDispatchReadyTimeout)", "runner.HandleMessageFrom(e.sessionContext(), nodeID, msg)", "sesspkg.IsSelectionError(err)", "e.handlePeerSessionHookError(nodeID, s, err)")
	require("pkg/session/planning.go", "executeStrategyOutcomes", "{\n\tctx, cancelSelection, err := s.enterSelection(ctx, strategy)\n\tif err != nil {\n\t\treturn nil, err\n\t}")
	require("pkg/session/planning.go", "executePlan", "s.openSelectionExecutor(executor)", "s.closeSelectionExecutor(executor)")
	require("pkg/session/planning.go", "executeCandidateGroup", "s.openSelectionExecutor(group)", "s.closeSelectionExecutor(group)")
	require("pkg/session/selection_agreement.go", "requirePreviousSelectionClosed", "len(a.activeExecutors) != 0")
	require("pkg/session/selection_agreement.go", "enterSelection", "!round.confirmed", "round.entered", "round.strategy != strategy.Name()", "!time.Now().Before(round.deadline)")
	require("pkg/session/selection_agreement.go", "agreeCandidates", "jointSelection(s.cfg", "selectionHash(joint)", "received.selectionBinding != expected", "received.Digest != digest", "s.requirePreviousSelectionClosed()")
	require("pkg/session/selection_agreement.go", "receiveSelectionControl", "binding.ToEpoch != a.local.Epoch", "binding.FromEpoch != a.remote.Epoch")
	// R-a splits the first pass into two bounded windows; both must still be
	// charged to the existing first plan/group and candidate-loop allowance.
	require("pkg/session/selection_agreement.go", "beginSelectionPass", "a.capabilityDeadline = a.passStart.Add(window)")
	require("pkg/session/selection_agreement.go", "selectionCapabilityContext", "deadline := a.capabilityDeadline")
	require("pkg/session/selection_agreement.go", "firstSelectionConfirmDeadline", "anchor := receivedAt", "if anchor.Before(passStart) {\n\t\tanchor = passStart\n\t}", "remaining := passStart.Add(runTimeout).Sub(anchor)", "return anchor.Add(min(window, defaultCapabilityWaitTimeout, remaining))")
	require("pkg/session/selection_agreement.go", "receiveSelectionCapability", "if a.remote == nil {", "receivedAt := time.Now()", "!receivedAt.Before(a.capabilityDeadline)", "a.capabilityReceivedAt = receivedAt", "a.confirmDeadline = firstSelectionConfirmDeadline(")
	require("pkg/session/selection_agreement.go", "agreeCandidates", "if ordinal == 0 {\n\t\tstart, deadline = a.passStart, a.confirmDeadline\n\t}", "budgetStart := start", "budgetStart: budgetStart")
	if strings.Contains(selectionFunction(sources["pkg/session/selection_agreement.go"], "agreeCandidates"), "budgetStart = time.Time{}") {
		violations = append(violations, "first selection cannot discard its execution-budget origin")
	}
	require("pkg/session/selection_agreement.go", "selectionExecutionContext", "start = a.current.budgetStart", "return context.WithDeadline(ctx, start.Add(timeout))")
	require("pkg/session/selection_agreement.go", "subtractSelectionTime", "budget.TimeBudget -= time.Since(start)")
	require("pkg/session/planning.go", "executeStrategyOutcomes", "s.subtractSelectionTime(s.candidateExecutionBudget(len(plans)))")
	require("pkg/session/planning.go", "executeCandidate", "s.selectionExecutionContext(execCtx, s.executionTimeout())")
	require("pkg/session/planning.go", "executeCandidateGroup", "s.selectionExecutionContext(execCtx, s.candidateGroupExecutionTimeout(len(entries)))")
	wait := selectionFunction(sources["pkg/session/envelope.go"], "waitForRemoteCapability")
	if strings.Contains(wait, "return s.remoteCapability(), nil") {
		violations = append(violations, "capability wait may not guess from a snapshot on failure")
	}
	if !strings.Contains(wait, "case <-timer.C:\n\t\t\treturn rproto.Capability{}, selectionDeadline(\"capability_missing\")") {
		violations = append(violations, "capability timeout must fail, never return a guessed snapshot")
	}
	for key, want := range selectionFrozenFunctions {
		parts := strings.SplitN(key, ":", 2)
		body := selectionFunction(sources[parts[0]], parts[1])
		got := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if body == "" || got != want {
			violations = append(violations, "frozen #94/2s function: "+key+":"+got)
		}
	}
	sort.Strings(violations)
	return violations
}

func TestSelectionConvergenceProductionBoundary(t *testing.T) {
	if violations := selectionBoundaryViolations(selectionProductionSources(t)); len(violations) != 0 {
		t.Fatal(strings.Join(violations, "\n"))
	}
}
func TestSelectionConvergenceDetectsBypassMutations(t *testing.T) {
	base := selectionProductionSources(t)
	mutations := []struct{ file, old, replacement string }{
		{"pkg/client/peer_session.go", "sesspkg.NewConverging(", "sesspkg.New("},
		{"pkg/client/peer_session.go", "runner.HandleMessageFrom(e.sessionContext(), nodeID, msg)", "runner.HandleMessage(e.sessionContext(), msg)"},
		{"pkg/client/peer_session.go", "if !e.waitSolverDispatchReady(solverDispatchReadyTimeout)", "if false"},
		{"pkg/client/strategy_factory.go", "DirectStrategy: legacyice.StrategyName,", "AllowImplicitLegacy: true, DirectStrategy: legacyice.StrategyName,"},
		{"pkg/client/strategy_factory.go", "DirectStrategy: legacyice.StrategyName,", "AllowImplicitOrder: true, DirectStrategy: legacyice.StrategyName,"},
		{"pkg/session/envelope.go", "return rproto.Capability{}, selectionDeadline(\"capability_missing\")", "return s.remoteCapability(), nil"},
		{"pkg/session/planning.go", "s.enterSelection(ctx, strategy)", "s.bypassSelection(ctx, strategy)"},
		{"pkg/session/planning.go", "s.closeSelectionExecutor(executor)", "s.runCleanup(executor.Close)"},
		{"pkg/session/selection_agreement.go", "binding.ToEpoch != a.local.Epoch", "false"},
		{"pkg/session/selection_agreement.go", "len(a.activeExecutors) != 0", "false"},
		{"pkg/session/selection_agreement.go", "start, deadline = a.passStart, a.confirmDeadline", "start, deadline = a.passStart, a.capabilityDeadline"},
		{"pkg/session/selection_agreement.go", "return anchor.Add(min(window, defaultCapabilityWaitTimeout, remaining))", "return anchor.Add(min(4*time.Second, remaining))"},
		{"pkg/session/selection_agreement.go", "budgetStart := start", "budgetStart := time.Time{}"},
		{"pkg/session/selection_agreement.go", "return context.WithDeadline(ctx, start.Add(timeout))", "return context.WithTimeout(ctx, timeout)"},
		{"pkg/session/selection_agreement.go", "budget.TimeBudget -= time.Since(start)", "budget.TimeBudget -= 0"},
		{"pkg/session/selection_agreement.go", "receivedAt := time.Now()", "receivedAt := at"},
		{"pkg/session/selection_agreement.go", "!receivedAt.Before(a.capabilityDeadline)", "false"},
		{"pkg/session/planning.go", "s.subtractSelectionTime(s.candidateExecutionBudget(len(plans)))", "s.candidateExecutionBudget(len(plans))"},
		{"pkg/session/planning.go", "s.selectionExecutionContext(execCtx, s.candidateGroupExecutionTimeout(len(entries)))", "context.WithTimeout(execCtx, s.candidateGroupExecutionTimeout(len(entries)))"},
		{"pkg/session/selection.go", "func (s *Session) routeStrategyMessage(msg solver.Message) strategyMessageTarget {\n\ts.strategyMu.Lock()", "func (s *Session) routeStrategyMessage(msg solver.Message) strategyMessageTarget {\n\ts.strategyMu.RLock()"},
		{"pkg/session/selection_agreement.go", "if anchor.Before(passStart)", "if false"},
	}
	for index, mutation := range mutations {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			sources := make(map[string]string, len(base))
			for k, v := range base {
				sources[k] = strings.ReplaceAll(v, "\r\n", "\n")
			}
			source := sources[mutation.file]
			if !strings.Contains(source, mutation.old) {
				t.Fatal("mutation anchor missing")
			}
			sources[mutation.file] = strings.Replace(source, mutation.old, mutation.replacement, 1)
			if len(selectionBoundaryViolations(sources)) == 0 {
				t.Fatal("production selection bypass escaped")
			}
		})
	}
	sources := make(map[string]string, len(base)+1)
	for k, v := range base {
		sources[k] = v
	}
	sources["pkg/client/unapproved.go"] = "package client\nimport bypass \"winkyou/pkg/session\"\nvar unconfirmed = bypass.New\n"
	if len(selectionBoundaryViolations(sources)) == 0 {
		t.Fatal("aliased production constructor escaped")
	}
}
