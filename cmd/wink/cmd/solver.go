package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"winkyou/internal/solverstdio"
)

type solverStdioRunner interface {
	Serve(context.Context, io.Reader, io.Writer, solverstdio.Options) error
}

type systemSolverStdioRunner struct{}

func (systemSolverStdioRunner) Serve(ctx context.Context, input io.Reader, output io.Writer, options solverstdio.Options) error {
	return solverstdio.Serve(ctx, input, output, options)
}

func newSolverCmd(opts *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "solver",
		Short: "Use the versioned local connectivity-solver API",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newSolverServeCmd(opts, systemSolverStdioRunner{}))
	return command
}

func newSolverServeCmd(opts *Options, runner solverStdioRunner) *cobra.Command {
	var stdio bool
	command := &cobra.Command{
		Use:   "serve",
		Short: "Serve the bounded JSON-RPC v1 API over stdin/stdout",
		Long: "Serve the local JSON-RPC v1 API with fixed Content-Length framing. " +
			"This command never opens a listener and fails closed unless it owns the canonical machine governor lock.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if !stdio {
				return errors.New("--stdio is required; no socket-listening mode is available")
			}
			if runner == nil {
				return errors.New("stdio solver runner is unavailable")
			}
			configPath := ""
			if opts != nil {
				configPath = opts.ConfigPath
			}
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt)
			defer stop()
			return runner.Serve(ctx, command.InOrStdin(), command.OutOrStdout(), solverstdio.Options{ConfigPath: configPath})
		},
	}
	command.Flags().BoolVar(&stdio, "stdio", false, "use stdin/stdout Content-Length framing (required)")
	return command
}
