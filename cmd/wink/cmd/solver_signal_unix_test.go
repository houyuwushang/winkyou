//go:build unix

package cmd

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"winkyou/internal/solverstdio"
	"winkyou/internal/v2/gatecorchestrator"
)

// Each signal goes to a fresh, owned, zero-network subprocess: the old default
// SIGHUP disposition must not terminate the test runner or another fixture.
func TestSolverSignalsCancelExistingRunner(t *testing.T) {
	for _, entry := range []string{"connect", "child", "serve"} {
		for _, signal := range []struct {
			name  string
			value os.Signal
		}{{"sighup", syscall.SIGHUP}, {"sigterm", syscall.SIGTERM}, {"interrupt", os.Interrupt}} {
			t.Run(entry+"/"+signal.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSolverSignalProcess$")
				// The parent owns even the RED helper's files: signal-default
				// termination cannot run the helper's own t.TempDir cleanup.
				configPath := filepath.Join(t.TempDir(), "config.yaml")
				command.Env = append(os.Environ(), "WINKYOU_SOLVER_SIGNAL_ENTRY="+entry,
					"WINKYOU_SOLVER_SIGNAL_CONFIG="+configPath)
				command.Stderr = io.Discard // No machine paths or source diagnostics.
				output, err := command.StdoutPipe()
				if err != nil || command.Start() != nil {
					t.Fatal("signal helper start failed")
				}
				ready := make(chan struct{})
				type outcome struct {
					cancelled bool
					err       error
				}
				done := make(chan outcome, 1)
				go func() {
					scanner := bufio.NewScanner(output)
					scanner.Buffer(make([]byte, 128), 1024)
					var witnessed bool
					for scanner.Scan() {
						switch scanner.Text() {
						case "runner_ready":
							close(ready)
						case "runner_cancelled":
							witnessed = true
						}
					}
					done <- outcome{cancelled: witnessed, err: errors.Join(scanner.Err(), command.Wait())}
				}()
				select {
				case <-ready:
				case <-done:
					t.Fatal("signal helper exited before the real command registered cancellation")
				case <-ctx.Done():
					<-done
					t.Fatal("signal helper startup timed out")
				}
				started := time.Now()
				if command.Process.Signal(signal.value) != nil {
					cancel()
					<-done
					t.Fatal("owned signal delivery failed")
				}
				deadline := time.NewTimer(3 * time.Second)
				defer deadline.Stop()
				select {
				case result := <-done:
					if !result.cancelled || result.err != nil {
						t.Fatalf("signal bypassed caller cancel: entry=%s signal=%s cancelled=%t wall_ms=%d", entry, signal.name, result.cancelled, time.Since(started).Milliseconds())
					}
				case <-deadline.C:
					cancel()
					<-done
					t.Fatal("signal helper did not drain within its fixed bound")
				}
			})
		}
	}
}

func TestSolverSignalProcess(t *testing.T) {
	entry := os.Getenv("WINKYOU_SOLVER_SIGNAL_ENTRY")
	if entry == "" {
		return
	}
	configPath := os.Getenv("WINKYOU_SOLVER_SIGNAL_CONFIG")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal("private signal fixture unavailable")
	}
	runner := &solverSignalRunner{}
	options := &Options{ConfigPath: configPath}
	var command *cobra.Command
	switch entry {
	case "connect":
		command = newSolverDirectConnectCmd(options, runner)
		command.SetArgs([]string{"--request-file", "synthetic-private-request"})
	case "child":
		command = newSolverDirectChildCmd(options, runner)
		command.SetArgs([]string{"--stdio"})
	case "serve":
		command = newSolverServeCmd(options, runner)
		command.SetArgs([]string{"--stdio"})
	default:
		t.Fatal("unknown signal fixture entry")
	}
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	if err := command.ExecuteContext(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal("command did not propagate caller cancellation")
	}
	_, _ = io.WriteString(os.Stdout, "runner_cancelled\n")
}

type solverSignalRunner struct{}

func (*solverSignalRunner) wait(ctx context.Context) error {
	_, _ = io.WriteString(os.Stdout, "runner_ready\n")
	<-ctx.Done()
	return ctx.Err()
}

func (r *solverSignalRunner) Connect(ctx context.Context, _ gatecorchestrator.InitiatorOptions) (gatecorchestrator.Result, error) {
	return gatecorchestrator.Result{}, r.wait(ctx)
}

func (r *solverSignalRunner) Child(ctx context.Context, _ io.Reader, _ io.Writer, _ gatecorchestrator.ResponderOptions) (gatecorchestrator.Result, error) {
	return gatecorchestrator.Result{}, r.wait(ctx)
}

func (r *solverSignalRunner) Serve(ctx context.Context, _ io.Reader, _ io.Writer, _ solverstdio.Options) error {
	return r.wait(ctx)
}
