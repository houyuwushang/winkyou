package architecture

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Baseline 97c3750 job bodies, ignoring blank lines/indentation only. Removing
// exactly the authorized env/collector must recover the original complete job:
// all test commands, counts, env, timeouts, selection and setup stay frozen.
var fixtureTimingJobs = []struct{ file, job, artifact, digest string }{
	{"ci.yml", "gate-c1b-memory-pipelines", "fixture-timing-pipelines-${{ matrix.os }}", "c8753ea561dc5e92652f36f3beb6672911aec5b80a1c997833b23c2589a37f72"},
	{"ci.yml", "gate-c1b-memory-phases", "fixture-timing-phases-${{ matrix.os }}", "e9d96820f6ce840c59e59a3a37b918d2ef80b1feca1807346139d942d5a236c3"},
	{"ci.yml", "gate-c1b-memory-fresh100", "fixture-timing-fresh100-${{ matrix.os }}", "ed010cf64c468c66e08751c2059a802a8855d8dd957905bff307175758f3b63b"},
	{"session-liveness.yml", "owner", "fixture-timing-owner-${{ matrix.os }}", "1fe56af339d19f1e6f3d76a45223a697e53fdb66ccb047b50ea0c9569f7dbd5f"},
	{"session-liveness.yml", "real-wireguard", "fixture-timing-liveness-ubuntu-latest", "bfa2703e31a45df40a0d3b3dd7a964ce940eb1f8dde3d5e8a44f8eb3f03d6ddd"},
	{"session-liveness.yml", "real-wireguard-windows", "fixture-timing-liveness-windows-latest-${{ matrix.case }}", "ca0b6aacc7e23398b33a8e2e0d008bb33e610984c46c428c1f345afef8d25c3a"},
}

func fixtureTimingJobValid(data []byte, job, artifact, digest string) bool {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	starts := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:\n`).FindAllStringIndex(text, -1)
	for index, start := range starts {
		if text[start[0]:start[1]] != "  "+job+":\n" {
			continue
		}
		end := len(text)
		if index+1 < len(starts) {
			end = starts[index+1][0]
		}
		block := text[start[0]:end]
		const env = "      WINKYOU_FIXTURE_TIMING_DIR: ${{ github.workspace }}/../fixture-timing\n"
		capture := "      - name: Preserve numeric fixture timing\n        if: always()\n        uses: ./.github/actions/fixture-timing\n        with:\n          artifact-name: " + artifact + "\n"
		if strings.Count(block, env) != 1 || strings.Count(block, capture) != 1 {
			return false
		}
		block = strings.Replace(block, env, "", 1)
		block = strings.Replace(block, capture, "", 1)
		var lines []string
		for _, line := range strings.Split(block, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(lines, "\n")))) == digest
	}
	return false
}

func TestGateC1bFixtureTimingPreservesCI(t *testing.T) {
	for _, fixture := range fixtureTimingJobs {
		data, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", fixture.file))
		if err != nil || !fixtureTimingJobValid(data, fixture.job, fixture.artifact, fixture.digest) {
			t.Fatalf("timing collection changed original job contract: %s", fixture.job)
		}
		for _, mutation := range [][2]string{
			{"if: always()", "if: success()"},
			{"WINKYOU_FIXTURE_TIMING_DIR", "REMOVED_TIMING_DIR"},
			{"${{ github.workspace }}/../fixture-timing", "${{ runner.temp }}/fixture-timing"},
			{fixture.artifact, "fixture-timing-incorrect"},
		} {
			// Mutate all occurrences so the same invariant is exercised for
			// every job, not just the first matching job in the workflow.
			changed := strings.ReplaceAll(string(data), mutation[0], mutation[1])
			if fixtureTimingJobValid([]byte(changed), fixture.job, fixture.artifact, fixture.digest) {
				t.Fatal("missing success/failure capture was accepted")
			}
		}
		for _, mutation := range [][2]string{
			{"go test ", "go test -count=1 "}, {"timeout-minutes:", "changed-timeout-minutes:"},
			{"halt_on_error=1", "halt_on_error=0"},
		} {
			changed := strings.ReplaceAll(string(data), mutation[0], mutation[1])
			if fixtureTimingJobValid([]byte(changed), fixture.job, fixture.artifact, fixture.digest) {
				t.Fatal("proof command or frozen budget mutation was accepted")
			}
		}
	}
}

func TestGateC1bFixtureTimingJobEnvContext(t *testing.T) {
	// Job env is evaluated before runner.* is an available expression context.
	// Keep capture outside the checkout using the supported github context;
	// step-level upload may still use runner.temp. YAML parsing alone misses it.
	for _, name := range []string{"ci.yml", "session-liveness.yml"} {
		data, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", name))
		if err != nil {
			t.Fatal("workflow unavailable")
		}
		lines := regexp.MustCompile(`(?m)^\s+WINKYOU_FIXTURE_TIMING_DIR: (.+)\r?$`).FindAllStringSubmatch(string(data), -1)
		if len(lines) != 3 {
			t.Fatal("numeric capture job count changed")
		}
		for _, line := range lines {
			if strings.TrimSpace(line[1]) != "${{ github.workspace }}/../fixture-timing" {
				t.Fatal("job env must use a supported context and keep samples outside checkout")
			}
		}
	}
}

func fixtureTimingActionValid(data []byte) bool {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	// Exact approved validate-then-upload action; no raw logs, broad glob,
	// success-only condition, ignored errors or hidden proof command allowed.
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(lines, "\n")))) == "c84e70c15224a13bbf8bf87c288e87f1987cae272fef6ee7857981552e1580a9"
}

func TestGateC1bFixtureTimingArtifactMutations(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "actions", "fixture-timing", "action.yml"))
	if err != nil || !fixtureTimingActionValid(data) {
		t.Fatal("numeric validation and bounded artifact upload contract changed")
	}
	for _, mutation := range [][2]string{
		{"python scripts/ci-fixture-timing.py summarize", "true"},
		{"fixture-timing-export/*.json", "**/*"},
		{"if-no-files-found: error", "if-no-files-found: ignore"},
		{"retention-days: 14", "retention-days: 90"},
	} {
		changed := strings.Replace(string(data), mutation[0], mutation[1], 1)
		if changed == string(data) || fixtureTimingActionValid([]byte(changed)) {
			t.Fatal("unsafe artifact publication accepted")
		}
	}
}

func fixtureTimingCaptureValid(source []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		return false
	}
	registrations, captures := 0, 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runGateC1bMemoryProductProfile" || fn.Body == nil {
			continue
		}
		createdAt, creations := -2, 0
		for index, stmt := range fn.Body.List {
			assignment, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "phases" {
				continue
			}
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			factory, ok := call.Fun.(*ast.Ident)
			if ok && factory.Name == "newGateC1bMemoryPhaseWitness" {
				createdAt, creations = index, creations+1
			}
		}
		if creations != 1 {
			return false
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "persistTiming" {
					captures++
				}
			}
			return true
		})
		for index, stmt := range fn.Body.List {
			if index != createdAt+1 {
				continue // Early fixture failures must also reach capture.
			}
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
	const source = "package fixture; func runGateC1bMemoryProductProfile() { phases := newGateC1bMemoryPhaseWitness(); " + registration + " }"
	if !fixtureTimingCaptureValid([]byte(source)) {
		t.Fatal("valid capture contract rejected")
	}
	for _, mutation := range []string{
		"", "if t.Failed() { " + registration + " }",
		"t.Cleanup(func() { if t.Failed() { phases.persistTiming(t, test, windows) } })",
		"defer phases.persistTiming(t, test, windows)",
		"workMayFail(); " + registration,
		"t.Cleanup(func() { phases.persistTiming(t, test, replacement) })",
		registration + "; " + registration,
	} {
		if fixtureTimingCaptureValid([]byte(strings.Replace(source, registration, mutation, 1))) {
			t.Fatal("conditional, duplicate, early or wrong-source capture accepted")
		}
	}
}
