package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// A second timer is not an observation of context's own cancellation callback.
// Keep this source contract separate from the loaded wall-clock reproduction.
func TestCompletionPhaseDoesNotInferContextExpiryFromIndependentTimer(t *testing.T) {
	name := filepath.Join(repositoryRoot(t), "internal", "probeio", "wireguard_completion_phase_test.go")
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, name, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, violation := range completionTimerViolations(fset, parsed) {
		t.Error(violation)
	}
}

type completionTimerRead struct {
	context string
	pos     token.Pos
}

func completionTimerViolations(fset *token.FileSet, parsed *ast.File) []string {
	var violations []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		// Object identity follows declaration aliases across the callback bodies
		// while keeping a shadowed deadline variable distinct from its parent.
		bindings := make(map[*ast.Object]ast.Expr)
		bind := func(names []ast.Expr, values []ast.Expr) {
			for index, name := range names {
				identifier, ok := name.(*ast.Ident)
				if !ok || identifier.Obj == nil || len(values) == 0 {
					continue
				}
				if _, exists := bindings[identifier.Obj]; exists {
					continue
				}
				if index < len(values) {
					bindings[identifier.Obj] = values[index]
				} else if len(values) == 1 {
					bindings[identifier.Obj] = values[0]
				}
			}
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch item := node.(type) {
			case *ast.AssignStmt:
				bind(item.Lhs, item.Rhs)
			case *ast.ValueSpec:
				names := make([]ast.Expr, len(item.Names))
				for index, name := range item.Names {
					names[index] = name
				}
				bind(names, item.Values)
			}
			return true
		})

		var waits, reads []completionTimerRead
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "waitCompletionBoundary" && len(call.Args) == 1 {
				if context := completionDeadlineContext(call.Args[0], bindings, 0); context != "" {
					waits = append(waits, completionTimerRead{context: context, pos: call.Pos()})
				}
			}
			if method, ok := call.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Err" && len(call.Args) == 0 {
				reads = append(reads, completionTimerRead{context: completionContextKey(method.X, bindings, 0), pos: call.Pos()})
			}
			return true
		})
		for _, wait := range waits {
			for _, read := range reads {
				if read.pos > wait.pos && read.context == wait.context {
					violations = append(violations, fmt.Sprintf("%s:%d: independent timer must not establish context expiry via Err; observe that context's Done instead",
						function.Name.Name, fset.Position(wait.pos).Line))
					break
				}
			}
		}
	}
	return violations
}

func completionDeadlineContext(expression ast.Expr, bindings map[*ast.Object]ast.Expr, depth int) string {
	if depth > 32 {
		return ""
	}
	switch item := expression.(type) {
	case *ast.ParenExpr:
		return completionDeadlineContext(item.X, bindings, depth+1)
	case *ast.Ident:
		if value := bindings[item.Obj]; value != nil {
			return completionDeadlineContext(value, bindings, depth+1)
		}
	case *ast.CallExpr:
		if function, ok := item.Fun.(*ast.Ident); ok && function.Name == "completionChallengeDeadline" && len(item.Args) == 2 {
			if gate := completionContextKey(item.Args[1], bindings, depth+1); gate != "" {
				return gate + ".challengeCtx"
			}
		}
		if method, ok := item.Fun.(*ast.SelectorExpr); ok {
			switch method.Sel.Name {
			case "Add":
				return completionDeadlineContext(method.X, bindings, depth+1)
			case "Deadline":
				return completionContextKey(method.X, bindings, depth+1)
			}
		}
	}
	return ""
}

func completionContextKey(expression ast.Expr, bindings map[*ast.Object]ast.Expr, depth int) string {
	if depth > 32 {
		return ""
	}
	switch item := expression.(type) {
	case *ast.ParenExpr:
		return completionContextKey(item.X, bindings, depth+1)
	case *ast.Ident:
		switch value := bindings[item.Obj].(type) {
		case *ast.Ident:
			return completionContextKey(value, bindings, depth+1)
		case *ast.SelectorExpr:
			return completionContextKey(value, bindings, depth+1)
		}
		if item.Obj != nil {
			return fmt.Sprintf("%s@%d", item.Name, item.Obj.Pos())
		}
		return item.Name
	case *ast.SelectorExpr:
		if owner := completionContextKey(item.X, bindings, depth+1); owner != "" {
			return owner + "." + item.Sel.Name
		}
	}
	return ""
}

func TestCompletionTimerBoundaryRejectsIndependentTimerMutations(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{"finish_callback", `deadline := completionChallengeDeadline(t, gate); finish(func() { waitCompletionBoundary(deadline.Add(200*time.Millisecond)) }); if !errors.Is(gate.challengeCtx.Err(), context.DeadlineExceeded) { t.Fatal("expiry") }`},
		{"responder_margin", `deadline := completionChallengeDeadline(t, gate); waitCompletionBoundary(deadline.Add(500*time.Millisecond)); if gate.challengeCtx.Err() == nil { t.Fatal("expiry") }`},
		{"inline_deadline", `waitCompletionBoundary(completionChallengeDeadline(t, gate).Add(time.Second)); if gate.challengeCtx.Err() != nil { t.Fatal("expiry") }`},
		{"direct_context_deadline", `deadline, _ := gate.challengeCtx.Deadline(); waitCompletionBoundary(deadline.Add(time.Second)); if gate.challengeCtx.Err() == nil { t.Fatal("expiry") }`},
		{"arrival_alias", `deadline := completionChallengeDeadline(t, gate); arrival := deadline.Add(time.Second); go func() { waitCompletionBoundary(arrival) }(); if gate.challengeCtx.Err() == nil { t.Fatal("expiry") }`},
		{"var_alias", `var deadline = completionChallengeDeadline(t, gate); var arrival = deadline.Add(time.Second); waitCompletionBoundary(arrival); if gate.challengeCtx.Err() == nil { t.Fatal("expiry") }`},
		{"context_alias", `ctx := gate.challengeCtx; deadline, _ := ctx.Deadline(); waitCompletionBoundary(deadline.Add(time.Second)); if gate.challengeCtx.Err() == nil { t.Fatal("expiry") }`},
		{"detach_callback", `deadline := completionChallengeDeadline(t, gate); hook := func() { waitCompletionBoundary(deadline.Add(time.Second)) }; hook(); if !errors.Is(gate.challengeCtx.Err(), context.DeadlineExceeded) { t.Fatal("expiry") }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if violations := parseCompletionTimerFixture(t, test.body); len(violations) != 1 {
				t.Fatalf("timer mutation escaped: violations=%v", violations)
			}
		})
	}
}

func TestCompletionTimerBoundaryAllowsObservedAndAbsoluteWaits(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{"actual_done", `<-gate.challengeCtx.Done(); if !errors.Is(gate.challengeCtx.Err(), context.DeadlineExceeded) { t.Fatal("expiry") }`},
		{"bounded_done", `select { case <-gate.challengeCtx.Done(): case <-ctx.Done(): t.Fatal("guard") }; if !errors.Is(gate.challengeCtx.Err(), context.DeadlineExceeded) { t.Fatal("expiry") }`},
		{"arrival_without_context_assertion", `arrival := completionChallengeDeadline(t, gate).Add(time.Second); waitCompletionBoundary(arrival); packets.queueRead(frame)`},
		{"entry_without_context_assertion", `waitCompletionBoundary(completionChallengeDeadline(t, gate).Add(time.Second)); if err := gate.FinishAndActivate(ctx, finish); err != nil { t.Fatal(err) }`},
		{"different_context", `deadline := completionChallengeDeadline(t, gate); waitCompletionBoundary(deadline.Add(time.Second)); if gate.attemptCtx.Err() != nil { t.Fatal("absolute") }`},
		{"not_a_context_deadline", `waitCompletionBoundary(time.Now().Add(time.Second)); if gate.challengeCtx.Err() != nil { t.Fatal("diagnostic") }`},
		{"comment_and_string", `// waitCompletionBoundary(completionChallengeDeadline(t, gate).Add(time.Second)); gate.challengeCtx.Err()
		_ = "waitCompletionBoundary(deadline); gate.challengeCtx.Err()"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if violations := parseCompletionTimerFixture(t, test.body); len(violations) != 0 {
				t.Fatalf("valid observation rejected: violations=%v", violations)
			}
		})
	}
}

func parseCompletionTimerFixture(t *testing.T, body string) []string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "fixture.go", "package fixture\nfunc TestFixture(t *testing.T) {\n"+body+"\n}", 0)
	if err != nil {
		t.Fatal(err)
	}
	return completionTimerViolations(fset, parsed)
}

func TestCompletionTimerBoundaryChecksHelpersAndSeparatesBindings(t *testing.T) {
	for _, test := range []struct {
		name       string
		source     string
		violations int
	}{
		{"helper", `func helper(ctx context.Context) { deadline, _ := ctx.Deadline(); waitCompletionBoundary(deadline.Add(time.Second)); if ctx.Err() == nil { panic("expiry") } }`, 1},
		{"separate_functions", `func wait(ctx context.Context) { deadline, _ := ctx.Deadline(); waitCompletionBoundary(deadline.Add(time.Second)) }; func check(ctx context.Context) { if ctx.Err() == nil { panic("expiry") } }`, 0},
		{"shadowed_context", `func check(ctx context.Context) { deadline, _ := ctx.Deadline(); waitCompletionBoundary(deadline.Add(time.Second)); { ctx := other; if ctx.Err() == nil { panic("different context") } } }`, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, "fixture.go", "package fixture\n"+test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := completionTimerViolations(fset, parsed); len(got) != test.violations {
				t.Fatalf("scope gate violations=%v, want count=%d", got, test.violations)
			}
		})
	}
}
