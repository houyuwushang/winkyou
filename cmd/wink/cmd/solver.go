package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"winkyou/internal/solverstdio"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecstage"
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

type oobPairGenerator interface {
	GenerateOOB(context.Context, pairgen.OOBOptions) (pairgen.OOBResult, error)
}

type systemOOBPairGenerator struct{}

func (systemOOBPairGenerator) GenerateOOB(ctx context.Context, options pairgen.OOBOptions) (pairgen.OOBResult, error) {
	return pairgen.GenerateOOB(ctx, options)
}

type responderStager interface {
	Stage(string) error
	Cleanup(string) error
}

type systemResponderStager struct{}

func (systemResponderStager) Stage(requestFile string) error {
	return gatecstage.Stage(requestFile, time.Now())
}

func (systemResponderStager) Cleanup(manifestFile string) error {
	payload, err := pairgen.ReadPrivateFile(manifestFile, gatecattempt.MaxManifestBytes)
	if err != nil {
		return gatecstage.ErrStageInvalid
	}
	defer clear(payload)
	manifest, err := gatecattempt.ParseManifest(payload)
	if err != nil {
		return gatecstage.ErrStageInvalid
	}
	return gatecstage.Cleanup(manifest.ArtifactFingerprint)
}

func newSolverCmd(opts *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "solver",
		Short: "Use the versioned local connectivity-solver API",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(
		newSolverServeCmd(opts, systemSolverStdioRunner{}),
		newSolverPairCmd(systemDirectPairGenerator{}, systemOOBPairGenerator{}),
		newSolverDirectCmd(systemResponderStager{}),
	)
	return command
}

func newSolverDirectCmd(stager responderStager) *cobra.Command {
	command := &cobra.Command{
		Use:   "direct",
		Short: "Manage the local one-shot Gate C responder slot",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newSolverDirectStageCmd(stager), newSolverDirectCleanupCmd(stager))
	return command
}

func newSolverDirectStageCmd(stager responderStager) *cobra.Command {
	var requestFile string
	command := &cobra.Command{
		Use:   "stage",
		Short: "Stage one private responder request without active I/O",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if stager == nil || requestFile == "" {
				return gatecstage.ErrStageInvalid
			}
			if err := stager.Stage(requestFile); err != nil {
				return err
			}
			_, _ = io.WriteString(command.ErrOrStderr(), "oob_stage_created\n")
			return nil
		},
	}
	command.Flags().StringVar(&requestFile, "request-file", "", "private responder request file (required)")
	return command
}

func newSolverDirectCleanupCmd(stager responderStager) *cobra.Command {
	var manifestFile string
	command := &cobra.Command{
		Use:   "cleanup",
		Short: "Explicitly clear a fingerprint-matched responder slot",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if stager == nil || manifestFile == "" {
				return gatecstage.ErrStageInvalid
			}
			if err := stager.Cleanup(manifestFile); err != nil {
				return err
			}
			_, _ = io.WriteString(command.ErrOrStderr(), "oob_stage_cleared\n")
			return nil
		},
	}
	command.Flags().StringVar(&manifestFile, "manifest-file", "", "private Gate C manifest file (required)")
	return command
}

func newSolverPairCmd(generator directPairGenerator, oobGenerator oobPairGenerator) *cobra.Command {
	command := &cobra.Command{
		Use:   "pair",
		Short: "Create offline, burn-on-use solver pairing material",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newSolverPairDirectCmd(generator), newSolverPairOOBCmd(oobGenerator))
	return command
}

func newSolverPairOOBCmd(generator oobPairGenerator) *cobra.Command {
	var outDir, profile, mappingSetRole string
	command := &cobra.Command{
		Use:   "oob",
		Short: "Create one Gate C OOB credential pair",
		Long: "Create exactly one initiator artifact, one responder artifact, and one secret-free manifest " +
			"in a new private directory. This offline command has no clipboard or network path.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if generator == nil || outDir == "" || profile == "" {
				return pairgen.ErrInvalidOptions
			}
			if _, err := generator.GenerateOOB(command.Context(), pairgen.OOBOptions{
				OutDir: outDir, Profile: profile, MappingSetRole: mappingSetRole,
			}); err != nil {
				return err
			}
			_, _ = io.WriteString(command.ErrOrStderr(), "oob_pair_created\n")
			return nil
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "fixed profile: predictive, asymmetric, or hard-16k (required)")
	command.Flags().StringVar(&mappingSetRole, "mapping-set-role", "", "asymmetric mapping-set side: initiator or responder")
	command.Flags().StringVar(&outDir, "out-dir", "", "new private output directory (required; must not exist)")
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
