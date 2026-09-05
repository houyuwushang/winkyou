//go:build c1bproof

package cmd

import (
	"context"
	"io"

	"winkyou/internal/v2/gatecorchestrator"
)

// ExecuteGateCMemoryProof executes the real Cobra root/flags/commands. The
// only runner substitution is an in-memory process and isolated governor;
// request files, config parsing and responder claim use production paths.
func ExecuteGateCMemoryProof(ctx context.Context, args []string, input io.Reader, output, diagnostic io.Writer,
	proof gatecorchestrator.MemoryProofOptions) (gatecorchestrator.Result, error) {
	if !validGateCProofArgs(args) {
		return gatecorchestrator.Result{}, gatecorchestrator.ErrRequestInvalid
	}
	runner := &gateCMemoryRunner{proof: proof}
	root := newRootCmdWithGateC(runner)
	root.SetArgs(args)
	root.SetIn(input)
	root.SetOut(output)
	root.SetErr(diagnostic)
	err := root.ExecuteContext(ctx)
	return runner.result, err
}

func validGateCProofArgs(args []string) bool {
	if len(args) < 6 || args[0] != "--config" || args[1] == "" || args[2] != "solver" || args[3] != "direct" {
		return false
	}
	return len(args) == 6 && args[4] == "child" && args[5] == "--stdio" ||
		len(args) == 7 && args[4] == "connect" && args[5] == "--request-file" && args[6] != ""
}

type gateCMemoryRunner struct {
	proof  gatecorchestrator.MemoryProofOptions
	result gatecorchestrator.Result
}

func (runner *gateCMemoryRunner) progress(next gatecorchestrator.ProgressReporter) gatecorchestrator.ProgressReporter {
	return func(value gatecorchestrator.Progress) error {
		if err := next(value); err != nil {
			return err
		}
		if runner.proof.Progress != nil {
			return runner.proof.Progress(value)
		}
		return nil
	}
}

func (runner *gateCMemoryRunner) Connect(ctx context.Context, entry gatecorchestrator.InitiatorOptions) (gatecorchestrator.Result, error) {
	entry.Progress = runner.progress(entry.Progress)
	result, err := gatecorchestrator.RunMemoryInitiator(ctx, entry, runner.proof)
	runner.result = result
	return result, err
}
func (runner *gateCMemoryRunner) Child(ctx context.Context, input io.Reader, output io.Writer, entry gatecorchestrator.ResponderOptions) (gatecorchestrator.Result, error) {
	entry.Progress = runner.progress(entry.Progress)
	result, err := gatecorchestrator.RunMemoryResponder(ctx, input, output, entry, runner.proof)
	runner.result = result
	return result, err
}
