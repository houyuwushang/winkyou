package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"winkyou/internal/solverstdio"
)

type fakeSolverStdioRunner struct {
	called   int
	input    string
	options  solverstdio.Options
	err      error
	response string
}

func (runner *fakeSolverStdioRunner) Serve(ctx context.Context, input io.Reader, output io.Writer, options solverstdio.Options) error {
	runner.called++
	payload, _ := io.ReadAll(input)
	runner.input = string(payload)
	runner.options = options
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runner.response != "" {
		_, _ = io.WriteString(output, runner.response)
	}
	return runner.err
}

func TestSolverServeRequiresStdioAndPassesOnlyLocalStreams(t *testing.T) {
	runner := &fakeSolverStdioRunner{response: "framed-response"}
	command := newSolverServeCmd(&Options{ConfigPath: "explicit.yaml"}, runner)
	command.SetArgs([]string{"--stdio"})
	command.SetIn(strings.NewReader("framed-request"))
	var output bytes.Buffer
	command.SetOut(&output)
	if err := command.Execute(); err != nil {
		t.Fatalf("execute solver serve: %v", err)
	}
	if runner.called != 1 || runner.input != "framed-request" || runner.options.ConfigPath != "explicit.yaml" {
		t.Fatalf("runner state = %+v", runner)
	}
	if output.String() != "framed-response" {
		t.Fatalf("stdout = %q", output.String())
	}
	if command.Flags().Lookup("governor-scope") != nil || command.Flags().Lookup("listen") != nil {
		t.Fatal("stdio command exposes a scope or listener override")
	}
}

func TestSolverServeRejectsMissingStdioBeforeRunner(t *testing.T) {
	runner := &fakeSolverStdioRunner{}
	command := newSolverServeCmd(&Options{}, runner)
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "--stdio is required") || runner.called != 0 {
		t.Fatalf("missing stdio error=%v called=%d", err, runner.called)
	}
}

func TestSolverServePropagatesStartupFailureWithoutWritingProtocolNoise(t *testing.T) {
	runner := &fakeSolverStdioRunner{err: errors.New("governor_lock_unavailable: held by pid 4242")}
	command := newSolverServeCmd(&Options{}, runner)
	command.SilenceUsage = true
	command.SilenceErrors = true
	command.SetArgs([]string{"--stdio"})
	var output bytes.Buffer
	command.SetOut(&output)
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "pid 4242") {
		t.Fatalf("startup error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("startup failure wrote stdout: %q", output.String())
	}
}

func TestRootExposesNestedSolverStdioCommand(t *testing.T) {
	root := newRootCmd()
	command, _, err := root.Find([]string{"solver", "serve"})
	if err != nil {
		t.Fatalf("find solver serve: %v", err)
	}
	if command == nil || command.Name() != "serve" || command.Parent() == nil || command.Parent().Name() != "solver" {
		t.Fatalf("solver command = %+v", command)
	}
}
