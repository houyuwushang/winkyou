package loopbackcarrier

import (
	"bufio"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These overlays add timestamp observations to the real implementation only
// in a disposable test binary. There is no production hook, exported runtime
// API, fake clock, changed timer, or replacement fsync. Removing the listed
// insertions must recover the original source byte-for-byte (after CRLF
// normalization). The default governor absence regression also invokes this
// witness; its source is never changed by the overlay.
type absenceInsertion struct{ anchor, suffix string }

var absenceInsertions = map[string][]absenceInsertion{
	"internal/governor/governor.go": {
		{"\tg.attempts[request.ID] = lease\n", "\tabsenceObserveForTest(\"attempt_acquired\", time.Now())\n"},
	},
	"internal/probeio/probeio.go": {
		{"\tstartedAt := now()\n", "\tabsenceObserveForTest(\"probeio_started\", startedAt)\n"},
		{"\ttimer := c.newTimer(c.request.Cost.Duration)\n", "\tabsenceObserveForTest(\"tripwire_timer_armed\", time.Now())\n"},
		{"\t\ttimer.Stop()\n", "\t\tabsenceObserveForTest(\"tripwire_timer_stopped\", time.Now())\n"},
		{"\t\tc.ops.Wait()\n", "\t\tabsenceObserveForTest(\"probeio_workers_stopped\", time.Now())\n"},
	},
	"internal/v2/loopbackcarrier/carrier.go": {
		{"\tcost := AttemptCost()\n", "\tabsenceObserveForTest(\"attempt_acquire_begin\", time.Now())\n"},
		{"\tctx, cancelRun := context.WithTimeout(ctx, AttemptDuration-terminalDrainMargin)\n", "\tabsenceDeadlineForTest, _ := ctx.Deadline()\n\tabsenceObserveForTest(\"presence_deadline\", absenceDeadlineForTest)\n"},
		{"\t\t\terr = errors.Join(err, controller.Close())\n", "\t\t\tabsenceObserveForTest(\"controller_close_return\", time.Now())\n"},
		{"\t\treturn verify(packet)\n\t})\n", "\tabsenceObserveForTest(\"presence_read_return\", time.Now())\n"},
	},
}

const absenceObserverSuffix = `
// Only compiled through the opt-in absence witness test overlay.
var AbsenceObserverForTest func(string, time.Time)
func absenceObserveForTest(point string, at time.Time) {
    if AbsenceObserverForTest != nil { AbsenceObserverForTest(point, at) }
}
`

func absenceRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func absenceSource(t *testing.T, root, relative string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(source), "\r\n", "\n")
}

func absenceOverlay(t *testing.T, relative, original string) string {
	t.Helper()
	modified := original
	for _, insertion := range absenceInsertions[relative] {
		if strings.Count(modified, insertion.anchor) != 1 {
			t.Fatalf("witness anchor drifted: %s", relative)
		}
		modified = strings.Replace(modified, insertion.anchor, insertion.anchor+insertion.suffix, 1)
	}
	recovered := modified
	for _, insertion := range absenceInsertions[relative] {
		recovered = strings.Replace(recovered, insertion.anchor+insertion.suffix, insertion.anchor, 1)
	}
	if recovered != original {
		t.Fatalf("observer changed existing source: %s", relative)
	}
	return modified + absenceObserverSuffix
}

func TestAbsenceWitnessOverlayIsInsertionOnly(t *testing.T) {
	root := absenceRoot(t)
	for relative := range absenceInsertions {
		absenceOverlay(t, relative, absenceSource(t, root, relative))
	}
}

var absenceTemplateTargets = map[string]string{
	"worker": "internal/governor/loopbackcarrier_integration_test.go",
	"export": "internal/governor/loopbackcarrier_export_test.go",
}

// Go 1.23's vet subprocess requires every overlay target to exist physically.
// Append helpers/imports to an existing test file's overlay instead of creating
// virtual new filenames. Never write the source checkout or disable vet.
func appendAbsenceTestTemplate(t *testing.T, original, template string) string {
	t.Helper()
	fset := token.NewFileSet()
	sourceFile, err := parser.ParseFile(fset, "existing_test.go", original, 0)
	if err != nil {
		t.Fatal(err)
	}
	templateFile, err := parser.ParseFile(fset, "template_test.go", template, 0)
	if err != nil || sourceFile.Name.Name != templateFile.Name.Name {
		t.Fatal("absence template package mismatch")
	}
	imports := make(map[string]string)
	for _, spec := range sourceFile.Imports {
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[spec.Path.Value] = name
	}
	var extra []string
	for _, spec := range templateFile.Imports {
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if current, exists := imports[spec.Path.Value]; exists {
			if current != name {
				t.Fatal("absence template import alias mismatch")
			}
			continue
		}
		extra = append(extra, "\t"+name+" "+spec.Path.Value+"\n")
	}
	importInsertion := ""
	if len(extra) != 0 {
		importInsertion = "\nimport (\n" + strings.Join(extra, "") + ")\n"
	}
	packageEnd := fset.Position(sourceFile.Name.End()).Offset
	templateStart := fset.Position(templateFile.Name.End()).Offset
	for _, declaration := range templateFile.Decls {
		if general, ok := declaration.(*ast.GenDecl); ok && general.Tok == token.IMPORT {
			templateStart = fset.Position(general.End()).Offset
		}
	}
	suffix := "\n" + template[templateStart:]
	modified := original[:packageEnd] + importInsertion + original[packageEnd:] + suffix
	// Removing precisely our two insertions recovers all prior test bytes too.
	recovered := modified[:packageEnd] + modified[packageEnd+len(importInsertion):len(modified)-len(suffix)]
	if recovered != original {
		t.Fatal("absence helper changed existing test bytes")
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "combined_test.go", modified, 0); err != nil {
		t.Fatal("absence combined test syntax invalid")
	}
	return modified
}

func TestAbsenceWitnessTemplateAppendIsInsertionOnly(t *testing.T) {
	root := absenceRoot(t)
	for name, target := range absenceTemplateTargets {
		original := absenceSource(t, root, target) // also requires physical target
		template := absenceSource(t, root, "internal/v2/loopbackcarrier/testdata/absence_"+name+"_test.go.txt")
		appendAbsenceTestTemplate(t, original, template)
	}
}

func TestAbsenceDefaultRegressionRequiresObservedLifecycle(t *testing.T) {
	root := absenceRoot(t)
	source := absenceSource(t, root, "internal/governor/loopbackcarrier_integration_test.go")
	if !defaultAbsenceUsesObservedLifecycle(source) {
		t.Fatal("default absence regression must require the real lifecycle witness, not Connect wall time")
	}
	for _, mutation := range []string{
		strings.Replace(source, "runObservedAbsenceLifecycle(t)", "t.Skip(\"disabled\")", 1),
		strings.Replace(source, "runObservedAbsenceLifecycle(t)", "", 1),
		strings.Replace(source, "runObservedAbsenceLifecycle(t)", "if false { runObservedAbsenceLifecycle(t) }", 1),
	} {
		if defaultAbsenceUsesObservedLifecycle(mutation) {
			t.Fatal("disabled/default-regression mutation escaped")
		}
	}
}

func defaultAbsenceUsesObservedLifecycle(source string) bool {
	parsed, err := parser.ParseFile(token.NewFileSet(), "regression_test.go", source, 0)
	if err != nil {
		return false
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip" {
			continue
		}
		if function.Body == nil || len(function.Body.List) != 1 {
			return false
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return false
		}
		name, ok := call.Fun.(*ast.Ident)
		argument, argumentOK := call.Args[0].(*ast.Ident)
		return ok && name.Name == "runObservedAbsenceLifecycle" && argumentOK && argument.Name == "t"
	}
	return false
}

func TestAbsenceWitnessIncludesSocketDeadlineBeforeContextCancellation(t *testing.T) {
	// probeio.contextErrorForIO already attributes the OS deadline correctly
	// even when ctx.Err() is not set yet. Observe ReadFrom's return regardless
	// of that scheduling order; the worker separately checks the actual error.
	insertions := absenceInsertions["internal/v2/loopbackcarrier/carrier.go"]
	read := insertions[len(insertions)-1].suffix
	if !unconditionalAbsenceReadObservation(read) {
		t.Fatal("read-return witness must be unconditional")
	}
	for _, mutation := range []string{
		"if ctx.Err() != nil { " + strings.TrimSpace(read) + " }",
		"return; " + strings.TrimSpace(read),
		strings.ReplaceAll(read, "presence_read_return", "different_point"),
		"",
	} {
		if unconditionalAbsenceReadObservation(mutation) {
			t.Fatal("conditional/missing/misdirected observer mutation escaped")
		}
	}
}

func unconditionalAbsenceReadObservation(source string) bool {
	parsed, err := parser.ParseFile(token.NewFileSet(), "observer.go", "package witness; func observe() {\n"+source+"\n}", 0)
	if err != nil || len(parsed.Decls) != 1 {
		return false
	}
	body := parsed.Decls[0].(*ast.FuncDecl).Body.List
	if len(body) != 1 {
		return false
	}
	statement, ok := body[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return false
	}
	name, ok := call.Fun.(*ast.Ident)
	if !ok || name.Name != "absenceObserveForTest" {
		return false
	}
	point, ok := call.Args[0].(*ast.BasicLit)
	return ok && point.Kind == token.STRING && point.Value == `"presence_read_return"`
}

func TestAbsenceLifecycleWitness(t *testing.T) {
	if os.Getenv("WINKYOU_ABSENCE_WITNESS") != "1" {
		t.Skip("opt-in real-loopback lifecycle measurement, no production instrumentation")
	}
	defer func() {
		if t.Failed() {
			t.Log("ABSENCE_FAILURE stage=observer_or_worker")
		}
	}()
	count := 1
	if value := os.Getenv("WINKYOU_ABSENCE_WITNESS_RUNS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			t.Fatal("invalid measurement count")
		}
		count = parsed
	}
	root, directory := absenceRoot(t), t.TempDir()
	replace := make(map[string]string)
	writeOverlay := func(relative, content string) {
		path := filepath.Join(directory, strconv.Itoa(len(replace))+".go")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		replace[filepath.Join(root, filepath.FromSlash(relative))] = path
	}
	for relative := range absenceInsertions {
		writeOverlay(relative, absenceOverlay(t, relative, absenceSource(t, root, relative)))
	}
	for name, target := range absenceTemplateTargets {
		content := absenceSource(t, root, "internal/v2/loopbackcarrier/testdata/absence_"+name+"_test.go.txt")
		writeOverlay(target, appendAbsenceTestTemplate(t, absenceSource(t, root, target), content))
	}
	mapping, err := json.Marshal(struct{ Replace map[string]string }{replace})
	if err != nil {
		t.Fatal(err)
	}
	mapPath := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(mapPath, mapping, 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "absence-witness.test")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	args := []string{"test", "-overlay", mapPath, "-c", "-o", binary}
	if os.Getenv("WINKYOU_ABSENCE_WITNESS_RACE") == "1" {
		args = append(args, "-race")
	}
	args = append(args, "./internal/governor")
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, "go", args...)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Log("ABSENCE_FAILURE stage=build")
		t.Fatalf("witness build: %v\n%s", err, output)
	}
	deadline := time.Duration(count)*35*time.Second + time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), deadline+time.Minute)
	defer cancel()
	run := exec.CommandContext(ctx, binary, "-test.run=^TestLoopbackAbsenceLifecycleWitnessWorker$", "-test.count=1", "-test.v", "-test.timeout="+deadline.String())
	run.Dir = root
	run.Env = append(os.Environ(), "WINKYOU_ABSENCE_WITNESS_WORKER_RUNS="+strconv.Itoa(count))
	stdout, err := run.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	run.Stderr = &stderr
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		t.Log(scanner.Text())
	}
	if err := run.Wait(); err != nil {
		t.Fatalf("measurement failed: %v\n%s", err, stderr.String())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
