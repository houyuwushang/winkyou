package cmd

import (
	"errors"
	"testing"

	"winkyou/internal/v2/gatecorchestrator"
)

var errClosedC1bDiagnostic = errors.New("closed child diagnostic pipe")

type closedC1bDiagnostic struct{}

func (closedC1bDiagnostic) Write([]byte) (int, error) { return 0, errClosedC1bDiagnostic }

func TestGateCResponderDiagnosticPipeBeforeAndAfterFinish(t *testing.T) {
	child := newGateCProgressWriter(closedC1bDiagnostic{})
	child.responder = true
	if err := child.Report(gatecorchestrator.Progress{Stage: gatecorchestrator.StagePreflight}); !errors.Is(err, errClosedC1bDiagnostic) {
		t.Fatalf("pre-FINISH diagnostic failure = %v", err)
	}
	for _, stage := range []string{gatecorchestrator.StageFinishRecorded, gatecorchestrator.StageOOBDrained,
		gatecorchestrator.StageDataPlaneReady, gatecorchestrator.StageTerminal} {
		if err := child.Report(gatecorchestrator.Progress{Stage: stage}); err != nil {
			t.Fatalf("detached diagnostic aborted session: %v", err)
		}
	}
	initiator := newGateCProgressWriter(closedC1bDiagnostic{})
	if err := initiator.Report(gatecorchestrator.Progress{Stage: gatecorchestrator.StageFinishRecorded}); !errors.Is(err, errClosedC1bDiagnostic) {
		t.Fatalf("initiator diagnostics unexpectedly detached: %v", err)
	}
}

type countedC1bDiagnostic struct{ writes int }

func (output *countedC1bDiagnostic) Write(payload []byte) (int, error) {
	output.writes++
	return len(payload), nil
}

func TestGateCResponderNeverWritesDetachedOSDiagnosticPipe(t *testing.T) {
	output := &countedC1bDiagnostic{}
	child := newGateCProgressWriter(output)
	child.responder = true
	if err := child.Report(gatecorchestrator.Progress{Stage: gatecorchestrator.StagePreflight}); err != nil || output.writes != 1 {
		t.Fatal("attached diagnostics did not write once")
	}
	for _, stage := range []string{gatecorchestrator.StageFinishRecorded, gatecorchestrator.StageOOBDrained,
		gatecorchestrator.StageDataPlaneReady, gatecorchestrator.StageTerminal} {
		if err := child.Report(gatecorchestrator.Progress{Stage: stage}); err != nil || output.writes != 1 {
			t.Fatal("detached diagnostics reached the underlying OS writer")
		}
	}
}
