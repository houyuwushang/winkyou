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

// Ordinary I/O only; these narrow concurrency primitives must not quietly
// regain filesystem calls on Record or launch unbounded replacement workers.
// The hash is of format.Node, so CRLF does not change the contract.
var observationPersistenceFunctions = map[string]string{
	"pkg/solver/store/observation_writer.go:NewBufferedObservationStore": "4eeeeaa754404bfad39c54b68d4142e5fade4d35f43ec1b899205881d38196f8",
	"pkg/solver/store/observation_writer.go:newObservationWriter":        "2c21c1094a70ef14600d725e8c4c1116dc1528c3b7f7991330e80ce95161c89f",
	"pkg/solver/store/observation_writer.go:enqueue":                     "6e7a3338713fc8e86ee855d7e471703f304e57e5ef4b30b7fa2f2e193dcfa6e0",
	"pkg/solver/store/observation_writer.go:signal":                      "8c2cc1821aa13c448be62d72c955ce5e68fcaf55a0149be6372eb324f1b94279",
	"pkg/solver/store/observation_writer.go:seal":                        "9faca71ac609722f3531ab2411e5657d978736bd83287f52297e750988da710c",
	"pkg/solver/store/observation_writer.go:run":                         "f9dded50a42e2f5aa60bfdbbb66e51f0de82f946af7d832bbeb2243bb1621d0d",
	"pkg/solver/store/observation_writer.go:stats":                       "e84bf0fec9cd68e613c02de1d794bac6dd6258d039187e5b0be5002a35a7df0c",
	"pkg/solver/store/observation_writer.go:wait":                        "220c7582fc6b97010c76861d1d6cccba937b3979ee14e5c340d3382164267435",
	"pkg/solver/store/observation.go:Record":                             "18c4a66ec7f960bfe90c0f9072c8a4aed697e8586ef6f187d39dc976926b80c2",
	"pkg/solver/store/observation.go:List":                               "3b5ae1fd0242ab2a7af8cd0a53f8c0ca95623cb94f8cda71932d96d1cb00bc05",
	"pkg/solver/store/observation.go:Recent":                             "45db38c8bca239b9de1ae97eead2afeac11b7d0637be690065405a6b41be3c56",
	"pkg/solver/store/observation.go:Seal":                               "3903dadf8128027799abcf548852265f29aa956abeb5934b9e7e5ddc6f47d987",
	"pkg/solver/store/observation.go:Drain":                              "43e8f2cfcd7bffd5adc075ea5690c585af06f4d9741089ebe942191c0db2cd69",
	"pkg/client/engine.go:initObservationStore":                          "690d219f705c9bb95d43d22c6189ac13b9f60e69c64400aaab26f909f63ec7de",
}

func observationPersistenceViolations(sources map[string]string) []string {
	var violations []string
	for key, want := range observationPersistenceFunctions {
		parts := strings.SplitN(key, ":", 2)
		body := selectionFunction(sources[parts[0]], parts[1])
		if body == "" || fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != want {
			violations = append(violations, "observation ownership contract changed: "+key)
		}
	}
	init := selectionFunction(sources["pkg/client/engine.go"], "initObservationStore")
	if !strings.Contains(init, "solverstore.NewBufferedObservationStore(e.observationStorePath(), e.removeObservationState)") || strings.Contains(init, "solverstore.NewObservationStore(") {
		violations = append(violations, "client observation sink must opt into bounded persistence")
	}
	start := selectionFunction(sources["pkg/client/engine.go"], "Start")
	stop := selectionFunction(sources["pkg/client/engine.go"], "Stop")
	if !strings.Contains(start, "if e.observationStore != nil && e.stopping {\n\t\te.mu.Unlock()\n\t\treturn solverstore.ErrObservationDrainPending\n\t}") {
		violations = append(violations, "restart allowed while observation drain pending")
	}
	for _, part := range []string{
		"observations := e.observationStore", "observations.Seal()",
		"context.WithTimeout(context.Background(), observationDrainTimeout)",
		"err := observations.Drain(ctx)\n\t\tcancel()\n\t\tif err != nil {\n\t\t\te.setState(EngineStateStopping, errorString(err))\n\t\t\treturn errors.Join(e.stopErr, err)\n\t\t}",
		"if observations == nil {\n\t\t\te.stopErr = e.removeObservationState()\n\t\t}",
		"stats := observations.PersistenceStats()", "logger.Any(\"persistence\", stats)",
		"e.observationStore = nil",
	} {
		if !strings.Contains(stop, part) {
			violations = append(violations, "observation Stop missing "+part)
		}
	}
	if strings.Index(stop, "observations.Seal()") >= strings.Index(stop, "e.wg.Wait()") || strings.Index(stop, "observations.Drain(ctx)") >= strings.Index(stop, "e.observationStore = nil") || strings.Contains(selectionFunction(sources["pkg/client/engine.go"], "cleanupResources"), "e.observationStore = nil") {
		violations = append(violations, "observation seal/drain/release order changed")
	}
	if !strings.Contains(sources["pkg/client/engine.go"], "observationDrainTimeout = 2 * time.Second") {
		// gofmt aligns const columns, so inspect a whitespace-normalized form.
		if !strings.Contains(strings.Join(strings.Fields(sources["pkg/client/engine.go"]), " "), "observationDrainTimeout = 2 * time.Second") {
			violations = append(violations, "ordinary observation drain wait changed")
		}
	}
	writerSource := strings.Join(strings.Fields(sources["pkg/solver/store/observation_writer.go"]), " ")
	for _, part := range []string{"observationQueueCapacity = 128", "observationLineLimit = 16 * 1024"} {
		if !strings.Contains(writerSource, part) {
			violations = append(violations, "observation cap changed")
		}
	}
	bufferedRefs, workerRefs := 0, 0
	for filename, source := range sources {
		// Unrelated source cannot reference these identifiers without spelling
		// them. Keep mutation campaigns cheap without narrowing the file set
		// in which a new consumer or worker allocation would be rejected.
		if filename != "pkg/solver/store/observation_writer.go" &&
			!strings.Contains(source, "NewBufferedObservationStore") &&
			!strings.Contains(source, "newObservationWriter") &&
			!strings.Contains(source, "observationWriter") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
		if err != nil {
			violations = append(violations, filename+":parse")
			continue
		}
		if filename == "pkg/solver/store/observation_writer.go" {
			imports, _, err := sourceImports(file)
			if err != nil {
				violations = append(violations, filename+":imports")
			}
			for _, path := range imports {
				switch path {
				case "context", "encoding/json", "errors", "sync", "winkyou/pkg/solver":
				default:
					violations = append(violations, "observation writer extra capability "+path)
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "NewBufferedObservationStore":
					bufferedRefs++
					if filename != "pkg/client/engine.go" && filename != "pkg/solver/store/observation_writer.go" {
						violations = append(violations, filename+":unapproved buffered sink")
					}
				case "newObservationWriter":
					workerRefs++
					if filename != "pkg/solver/store/observation_writer.go" {
						violations = append(violations, filename+":unapproved worker constructor")
					}
				}
			}
			if lit, ok := n.(*ast.CompositeLit); ok {
				if id, ok := lit.Type.(*ast.Ident); ok && id.Name == "observationWriter" && filename != "pkg/solver/store/observation_writer.go" {
					violations = append(violations, filename+":unapproved worker literal")
				}
			}
			return true
		})
	}
	if bufferedRefs != 2 || workerRefs != 2 {
		violations = append(violations, "additional observation writer construction path")
	}
	return violations
}

func TestObservationPersistenceBoundaryDetectsMutations(t *testing.T) {
	base := selectionProductionSources(t)
	mutations := []struct{ file, old, replacement string }{
		{"pkg/client/engine.go", "solverstore.NewBufferedObservationStore(e.observationStorePath(), e.removeObservationState)", "solverstore.NewObservationStore(e.observationStorePath())"},
		{"pkg/client/engine.go", "observations.Seal()", "_ = observations"},
		{"pkg/client/engine.go", "err := observations.Drain(ctx)", "err := error(nil)"},
		{"pkg/client/engine.go", "if observations == nil {", "if true {"},
		{"pkg/client/engine.go", "e.observationStore != nil && e.stopping", "false"},
		{"pkg/client/engine.go", "observations := e.observationStore", "e.observationStore = nil; observations := e.observationStore"},
		{"pkg/solver/store/observation.go", "s.writer.enqueue(obs)", "s.appendToFile(obs)"},
		{"pkg/solver/store/observation.go", "s.writer.enqueue(obs)", "go s.writer.enqueue(obs)"},
		{"pkg/solver/store/observation.go", "obs = solver.CloneObservation(obs)", "obs = obs"},
		{"pkg/solver/store/observation.go", "return solver.CloneObservations(s.observations)", "return s.observations"},
		{"pkg/solver/store/observation.go", "if s.sealed {", "if false {"},
		{"pkg/solver/store/observation_writer.go", "observationQueueCapacity = 128", "observationQueueCapacity = 4096"},
		{"pkg/solver/store/observation_writer.go", "make(chan struct{}, 1)", "make(chan struct{}, 256)"},
		{"pkg/solver/store/observation_writer.go", "err := w.write(data)", "go w.write(data); err := error(nil)"},
		{"pkg/solver/store/observation_writer.go", "err := w.write(data)", "w.remove(); err := w.write(data)"},
		{"pkg/solver/store/observation_writer.go", "w.size == observationQueueCapacity", "false"},
		{"pkg/solver/store/observation_writer.go", "w.state.WriteErrors++", "w.state.WriteErrors = 0"},
		{"pkg/solver/store/observation_writer.go", "clear(w.queue[:])", "_ = w.queue"},
		{"pkg/solver/store/observation_writer.go", "return ErrObservationDrainPending", "return nil"},
		{"pkg/solver/store/observation_writer.go", "\"context\"", "\"context\"; \"net\""},
		{"pkg/client/peer_session.go", "observationSink = observationStore", "observationSink = solverstore.NewBufferedObservationStore(\"synthetic\", nil)"},
	}
	for i, m := range mutations {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			sources := make(map[string]string, len(base))
			for path, source := range base {
				sources[path] = strings.ReplaceAll(source, "\r\n", "\n")
			}
			if !strings.Contains(sources[m.file], m.old) {
				t.Fatal("mutation anchor missing")
			}
			sources[m.file] = strings.Replace(sources[m.file], m.old, m.replacement, 1)
			if len(observationPersistenceViolations(sources)) == 0 {
				t.Fatal("observation ownership mutation escaped")
			}
		})
	}
}

func TestObservationPersistenceProductionBoundary(t *testing.T) {
	if violations := observationPersistenceViolations(selectionProductionSources(t)); len(violations) != 0 {
		t.Fatal(strings.Join(violations, "\n"))
	}
}
