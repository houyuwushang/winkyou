package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"winkyou/internal/solverstdio"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/pairgen"
)

type fakeSolverStdioRunner struct {
	called   int
	input    string
	options  solverstdio.Options
	err      error
	response string
}

type fakeDirectPairGenerator struct {
	called  int
	options pairgen.Options
	result  pairgen.Result
	err     error
}

type fakeOOBPairGenerator struct {
	called  int
	options pairgen.OOBOptions
	result  pairgen.OOBResult
	err     error
}

type fakeResponderStager struct {
	stageCalls, cleanupCalls int
	stageValue, cleanupValue string
	err                      error
}

type fakeGateCProductRunner struct {
	connectCalls int
	childCalls   int
	initiator    gatecorchestrator.InitiatorOptions
	responder    gatecorchestrator.ResponderOptions
	childInput   string
	result       gatecorchestrator.Result
	err          error
}

func (runner *fakeGateCProductRunner) Connect(_ context.Context, options gatecorchestrator.InitiatorOptions) (gatecorchestrator.Result, error) {
	runner.connectCalls++
	runner.initiator = options
	_ = options.Progress(gatecorchestrator.Progress{Stage: gatecorchestrator.StagePreflight, RemainingBudget: 2 * time.Second, Cancellable: true})
	_ = options.Progress(gatecorchestrator.Progress{Stage: gatecorchestrator.StageTerminal, Cancellable: false})
	return runner.result, runner.err
}

func (runner *fakeGateCProductRunner) Child(_ context.Context, input io.Reader, _ io.Writer, options gatecorchestrator.ResponderOptions) (gatecorchestrator.Result, error) {
	runner.childCalls++
	runner.responder = options
	payload, _ := io.ReadAll(input)
	runner.childInput = string(payload)
	_ = options.Progress(gatecorchestrator.Progress{Stage: gatecorchestrator.StagePreflight, RemainingBudget: time.Second, Cancellable: true})
	_ = options.Progress(gatecorchestrator.Progress{Stage: gatecorchestrator.StageTerminal, Cancellable: false})
	return runner.result, runner.err
}

func (stager *fakeResponderStager) Stage(value string) error {
	stager.stageCalls++
	stager.stageValue = value
	return stager.err
}

func (stager *fakeResponderStager) Cleanup(value string) error {
	stager.cleanupCalls++
	stager.cleanupValue = value
	return stager.err
}

func (generator *fakeOOBPairGenerator) GenerateOOB(_ context.Context, options pairgen.OOBOptions) (pairgen.OOBResult, error) {
	generator.called++
	generator.options = options
	return generator.result, generator.err
}

func (generator *fakeDirectPairGenerator) Generate(_ context.Context, options pairgen.Options) (pairgen.Result, error) {
	generator.called++
	generator.options = options
	return generator.result, generator.err
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

func TestSolverPairDirectWritesOnlyFixedStatus(t *testing.T) {
	generator := &fakeDirectPairGenerator{}
	command := newSolverPairDirectCmd(generator)
	command.SetArgs([]string{"--out-dir", "operator-selected-private-directory"})
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := command.Execute(); err != nil {
		t.Fatalf("pair direct: %v", err)
	}
	if generator.called != 1 || generator.options.OutDir != "operator-selected-private-directory" ||
		generator.options.ClipboardRole != "" || generator.options.AcknowledgeClipboardHistory {
		t.Fatalf("generator = %+v", generator)
	}
	if stdout.Len() != 0 || stderr.String() != "pair_created\n" || strings.Contains(stderr.String(), generator.options.OutDir) {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestSolverPairDirectClipboardRequiresDoubleConsent(t *testing.T) {
	for _, args := range [][]string{
		{"--out-dir", "private", "--clipboard-role", "initiator"},
		{"--out-dir", "private", "--acknowledge-clipboard-history"},
		{"--out-dir", "private", "--clipboard-role", "both", "--acknowledge-clipboard-history"},
	} {
		generator := &fakeDirectPairGenerator{}
		command := newSolverPairDirectCmd(generator)
		command.SilenceUsage = true
		command.SilenceErrors = true
		command.SetArgs(args)
		if err := command.Execute(); !errors.Is(err, pairgen.ErrInvalidOptions) || generator.called != 0 {
			t.Fatalf("args %v error=%v calls=%d", args, err, generator.called)
		}
	}

	generator := &fakeDirectPairGenerator{result: pairgen.Result{ClipboardUsed: true}}
	command := newSolverPairDirectCmd(generator)
	command.SetArgs([]string{
		"--out-dir", "private", "--clipboard-role", pairgen.ClipboardRoleResponder,
		"--acknowledge-clipboard-history",
	})
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || stderr.String() != "clipboard_history_may_persist_secret\npair_created\n" ||
		generator.options.ClipboardRole != pairgen.ClipboardRoleResponder || !generator.options.AcknowledgeClipboardHistory {
		t.Fatalf("stdout=%q stderr=%q options=%+v", stdout.String(), stderr.String(), generator.options)
	}
}

func TestRootExposesOfflineDirectPairCommand(t *testing.T) {
	root := newRootCmd()
	command, _, err := root.Find([]string{"solver", "pair", "direct"})
	if err != nil || command == nil || command.Name() != "direct" || command.Parent() == nil || command.Parent().Name() != "pair" {
		t.Fatalf("pair command=%+v error=%v", command, err)
	}
}

func TestSolverPairOOBWritesOnlyFixedStatusAndHasNoClipboard(t *testing.T) {
	generator := &fakeOOBPairGenerator{}
	command := newSolverPairOOBCmd(generator)
	command.SetArgs([]string{"--profile", pairgen.OOBProfileAsymmetric, "--mapping-set-role", "responder", "--out-dir", "private-output"})
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if generator.called != 1 || generator.options.Profile != pairgen.OOBProfileAsymmetric ||
		generator.options.MappingSetRole != pairgen.OOBMappingSetResponder || generator.options.OutDir != "private-output" {
		t.Fatal("OOB generator did not receive the exact fixed option set")
	}
	if stdout.Len() != 0 || stderr.String() != "oob_pair_created\n" || strings.Contains(stderr.String(), generator.options.OutDir) {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if command.Flags().Lookup("clipboard-role") != nil || command.Flags().Lookup("acknowledge-clipboard-history") != nil {
		t.Fatal("Gate C pair command exposes clipboard flags")
	}
}

func TestRootExposesOfflineOOBPairCommand(t *testing.T) {
	root := newRootCmd()
	command, _, err := root.Find([]string{"solver", "pair", "oob"})
	if err != nil || command == nil || command.Name() != "oob" || command.Parent() == nil || command.Parent().Name() != "pair" {
		t.Fatalf("pair command=%+v error=%v", command, err)
	}
}

func TestSolverDirectStageAndCleanupWriteOnlyFixedStatus(t *testing.T) {
	stager := &fakeResponderStager{}
	tests := []struct {
		name, value, status string
		command             *cobra.Command
		calls               func() int
		captured            func() string
	}{
		{
			name: "stage", value: "private-request.json", status: "oob_stage_created\n",
			command: newSolverDirectStageCmd(stager), calls: func() int { return stager.stageCalls },
			captured: func() string { return stager.stageValue },
		},
		{
			name: "cleanup", value: "private-manifest.json", status: "oob_stage_cleared\n",
			command: newSolverDirectCleanupCmd(stager), calls: func() int { return stager.cleanupCalls },
			captured: func() string { return stager.cleanupValue },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flag := "--request-file"
			if test.name == "cleanup" {
				flag = "--manifest-file"
			}
			test.command.SetArgs([]string{flag, test.value})
			var stdout, stderr bytes.Buffer
			test.command.SetOut(&stdout)
			test.command.SetErr(&stderr)
			if err := test.command.Execute(); err != nil {
				t.Fatal(err)
			}
			if test.calls() != 1 || test.captured() != test.value || stdout.Len() != 0 || stderr.String() != test.status ||
				strings.Contains(stderr.String(), test.value) {
				t.Fatalf("%s fixed-status or invocation contract mismatch", test.name)
			}
		})
	}
}

func TestRootExposesGateCForegroundEntriesWithoutChangingStaging(t *testing.T) {
	root := newRootCmd()
	for _, path := range [][]string{{"solver", "direct", "stage"}, {"solver", "direct", "cleanup"},
		{"solver", "direct", "child"}, {"solver", "direct", "connect"}} {
		command, _, err := root.Find(path)
		if err != nil || command == nil || command.Name() != path[len(path)-1] {
			t.Fatalf("Find(%v) command=%+v err=%v", path, command, err)
		}
	}
}

func TestGateCForegroundCommandsKeepSecretsOffOutput(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretMarker := "private-secret-marker"
	result := gatecorchestrator.Result{Terminal: "success", DataPlaneReady: true, FinishRecorded: true, SessionEnd: "authenticated_close"}
	runner := &fakeGateCProductRunner{result: result}

	connect := newSolverDirectConnectCmd(&Options{ConfigPath: configPath}, runner)
	connect.SetArgs([]string{"--request-file", secretMarker})
	var connectOut, connectErr bytes.Buffer
	connect.SetOut(&connectOut)
	connect.SetErr(&connectErr)
	if err := connect.Execute(); err != nil {
		t.Fatal(err)
	}
	if runner.connectCalls != 1 || runner.initiator.RequestFile != secretMarker || connectOut.Len() != 0 ||
		strings.Contains(connectErr.String(), secretMarker) || !strings.Contains(connectErr.String(), `"data_plane_ready":true`) {
		t.Fatalf("connect invocation/output mismatch stdout=%q stderr=%q", connectOut.String(), connectErr.String())
	}

	child := newSolverDirectChildCmd(&Options{ConfigPath: configPath}, runner)
	child.SetArgs([]string{"--stdio"})
	child.SetIn(strings.NewReader(secretMarker))
	var childOut, childErr bytes.Buffer
	child.SetOut(&childOut)
	child.SetErr(&childErr)
	if err := child.Execute(); err != nil {
		t.Fatal(err)
	}
	if runner.childCalls != 1 || runner.childInput != secretMarker || childOut.Len() != 0 ||
		strings.Contains(childErr.String(), secretMarker) || !strings.Contains(childErr.String(), `"session_end":"authenticated_close"`) {
		t.Fatalf("child invocation/output mismatch stdout=%q stderr=%q", childOut.String(), childErr.String())
	}
}

func TestGateCConnectRequiresExplicitConfigAndChildRequiresStdio(t *testing.T) {
	runner := &fakeGateCProductRunner{}
	connect := newSolverDirectConnectCmd(&Options{}, runner)
	connect.SetArgs([]string{"--request-file", "private.json"})
	if err := connect.Execute(); !errors.Is(err, gatecorchestrator.ErrRequestInvalid) || runner.connectCalls != 0 {
		t.Fatalf("connect without config error=%v calls=%d", err, runner.connectCalls)
	}
	child := newSolverDirectChildCmd(&Options{}, runner)
	if err := child.Execute(); !errors.Is(err, gatecorchestrator.ErrRequestInvalid) || runner.childCalls != 0 {
		t.Fatalf("child without stdio error=%v calls=%d", err, runner.childCalls)
	}
}
