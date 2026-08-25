package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"winkyou/internal/solverstdio"
	"winkyou/internal/v2/pairgen"
)

type solverStdioRunner interface {
	Serve(context.Context, io.Reader, io.Writer, solverstdio.Options) error
}

type systemSolverStdioRunner struct{}

func (systemSolverStdioRunner) Serve(ctx context.Context, input io.Reader, output io.Writer, options solverstdio.Options) error {
	return solverstdio.Serve(ctx, input, output, options)
}

type directPairGenerator interface {
	Generate(context.Context, pairgen.Options) (pairgen.Result, error)
}

type systemDirectPairGenerator struct{}

func (systemDirectPairGenerator) Generate(ctx context.Context, options pairgen.Options) (pairgen.Result, error) {
	return pairgen.Generate(ctx, options)
}

func newSolverCmd(opts *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "solver",
		Short: "Use the versioned local connectivity-solver API",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(
		newSolverServeCmd(opts, systemSolverStdioRunner{}),
		newSolverPairCmd(systemDirectPairGenerator{}),
	)
	return command
}

func newSolverPairCmd(generator directPairGenerator) *cobra.Command {
	command := &cobra.Command{
		Use:   "pair",
		Short: "Create offline, burn-on-use solver pairing material",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newSolverPairDirectCmd(generator))
	return command
}

func newSolverPairDirectCmd(generator directPairGenerator) *cobra.Command {
	var outDir, clipboardRole string
	var acknowledgeClipboardHistory bool
	command := &cobra.Command{
		Use:   "direct",
		Short: "Create one N2 direct-attempt credential pair",
		Long: "Create one initiator artifact, one responder artifact, one secret-free rendezvous admission, " +
			"and a manifest in a new private directory. Nothing is printed to stdout and secret material is never accepted through argv or environment variables.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if generator == nil || outDir == "" {
				return pairgen.ErrInvalidOptions
			}
			if (clipboardRole != "" && clipboardRole != pairgen.ClipboardRoleInitiator && clipboardRole != pairgen.ClipboardRoleResponder) ||
				(clipboardRole == "" && acknowledgeClipboardHistory) || (clipboardRole != "" && !acknowledgeClipboardHistory) {
				return pairgen.ErrInvalidOptions
			}
			if clipboardRole != "" {
				_, _ = io.WriteString(command.ErrOrStderr(), "clipboard_history_may_persist_secret\n")
			}
			if _, err := generator.Generate(command.Context(), pairgen.Options{
				OutDir: outDir, ClipboardRole: clipboardRole,
				AcknowledgeClipboardHistory: acknowledgeClipboardHistory,
			}); err != nil {
				return err
			}
			_, _ = io.WriteString(command.ErrOrStderr(), "pair_created\n")
			return nil
		},
	}
	command.Flags().StringVar(&outDir, "out-dir", "", "new private output directory (required; must not exist)")
	command.Flags().StringVar(&clipboardRole, "clipboard-role", "", "copy exactly one artifact: initiator or responder")
	command.Flags().BoolVar(&acknowledgeClipboardHistory, "acknowledge-clipboard-history", false, "acknowledge that clipboard history may retain the secret")
	return command
}

func newSolverServeCmd(opts *Options, runner solverStdioRunner) *cobra.Command {
	var stdio bool
	command := &cobra.Command{
		Use:   "serve",
		Short: "Serve the bounded, explicitly versioned JSON-RPC API over stdin/stdout",
		Long: "Serve the local JSON-RPC v1 or v2 API with fixed Content-Length framing. " +
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
