//go:build linux && natlab && c1bproof

package cmd

import (
	"context"
	"io"

	"winkyou/internal/v2/gatecorchestrator"
)

// ExecuteGateCNATLabProof uses the real CLI parser and system SSH runner. It
// exists only in the required-netns proof binary, never in an ordinary build.
func ExecuteGateCNATLabProof(ctx context.Context, args []string, input io.Reader, output, diagnostic io.Writer,
	proof gatecorchestrator.NATLabProofOptions) (gatecorchestrator.Result, error) {
	child := len(args) == 4 && args[0] == "solver" && args[1] == "direct" && args[2] == "child" && args[3] == "--stdio"
	if !child && !validGateCProofArgs(args) {
		return gatecorchestrator.Result{}, gatecorchestrator.ErrRequestInvalid
	}
	runner := &gateCNATLabRunner{proof: proof}
	root := newRootCmdWithGateC(runner)
	root.SetArgs(args)
	root.SetIn(input)
	root.SetOut(output)
	root.SetErr(diagnostic)
	err := root.ExecuteContext(ctx)
	return runner.result, err
}

type gateCNATLabRunner struct {
	proof  gatecorchestrator.NATLabProofOptions
	result gatecorchestrator.Result
}

func (runner *gateCNATLabRunner) progress(next gatecorchestrator.ProgressReporter) gatecorchestrator.ProgressReporter {
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

func (runner *gateCNATLabRunner) Connect(ctx context.Context, entry gatecorchestrator.InitiatorOptions) (gatecorchestrator.Result, error) {
	entry.Progress = runner.progress(entry.Progress)
	result, err := gatecorchestrator.RunNATLabInitiator(ctx, entry, runner.proof)
	runner.result = result
	return result, err
}

func (runner *gateCNATLabRunner) Child(ctx context.Context, input io.Reader, output io.Writer, entry gatecorchestrator.ResponderOptions) (gatecorchestrator.Result, error) {
	entry.Progress = runner.progress(entry.Progress)
	result, err := gatecorchestrator.RunNATLabResponder(ctx, input, output, entry, runner.proof)
	runner.result = result
	return result, err
}
