package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"winkyou/internal/solverstdio"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/pairgen"
	"winkyou/pkg/config"
	"winkyou/pkg/version"
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

type gateCProductRunner interface {
	Connect(context.Context, gatecorchestrator.InitiatorOptions) (gatecorchestrator.Result, error)
	Child(context.Context, io.Reader, io.Writer, gatecorchestrator.ResponderOptions) (gatecorchestrator.Result, error)
}

type systemGateCProductRunner struct{}

func (systemGateCProductRunner) Connect(ctx context.Context, options gatecorchestrator.InitiatorOptions) (gatecorchestrator.Result, error) {
	return gatecorchestrator.RunInitiator(ctx, options)
}

func (systemGateCProductRunner) Child(ctx context.Context, input io.Reader, output io.Writer, options gatecorchestrator.ResponderOptions) (gatecorchestrator.Result, error) {
	return gatecorchestrator.RunResponderStdio(ctx, input, output, options)
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
	return newSolverCmdWithGateC(opts, systemGateCProductRunner{})
}

func newSolverCmdWithGateC(opts *Options, product gateCProductRunner) *cobra.Command {
	command := &cobra.Command{
		Use:   "solver",
		Short: "Use the versioned local connectivity-solver API",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(
		newSolverServeCmd(opts, systemSolverStdioRunner{}),
		newSolverPairCmd(systemDirectPairGenerator{}, systemOOBPairGenerator{}),
		newSolverDirectCmd(systemResponderStager{}, product, opts),
	)
	return command
}

func newSolverDirectCmd(stager responderStager, product gateCProductRunner, options *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "direct",
		Short: "Manage the local one-shot Gate C responder slot",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(
		newSolverDirectStageCmd(stager), newSolverDirectCleanupCmd(stager),
		newSolverDirectConnectCmd(options, product), newSolverDirectChildCmd(options, product),
	)
	return command
}

func newSolverDirectConnectCmd(options *Options, runner gateCProductRunner) *cobra.Command {
	var requestFile string
	command := &cobra.Command{
		Use:   "connect",
		Short: "Run one bounded foreground Gate C direct attempt",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if runner == nil || options == nil || options.ConfigPath == "" || requestFile == "" {
				return gatecorchestrator.ErrRequestInvalid
			}
			configuration, err := config.Load(options.ConfigPath)
			if err != nil {
				return gatecorchestrator.ErrRequestInvalid
			}
			progress := newGateCProgressWriter(command.ErrOrStderr())
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt)
			defer stop()
			result, err := runner.Connect(ctx, gatecorchestrator.InitiatorOptions{
				RequestFile: requestFile, Config: configuration, ConfigPath: options.ConfigPath,
				BuildVersion: version.Version, Progress: progress.Report,
			})
			if err != nil {
				return err
			}
			return writeGateCResult(command.ErrOrStderr(), result)
		},
	}
	command.Flags().StringVar(&requestFile, "request-file", "", "private initiator request file (required)")
	return command
}

func newSolverDirectChildCmd(options *Options, runner gateCProductRunner) *cobra.Command {
	var stdio bool
	command := &cobra.Command{
		Use:    "child",
		Short:  "Run the bounded Gate C responder over the forced-command byte stream",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if runner == nil || !stdio {
				return gatecorchestrator.ErrRequestInvalid
			}
			configPath := ""
			if options != nil {
				configPath = options.ConfigPath
			}
			configuration, err := config.Load(configPath)
			if err != nil {
				return gatecorchestrator.ErrRequestInvalid
			}
			progress := newGateCProgressWriter(command.ErrOrStderr())
			progress.responder = true
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt)
			defer stop()
			result, err := runner.Child(ctx, command.InOrStdin(), command.OutOrStdout(), gatecorchestrator.ResponderOptions{
				Config: configuration, ConfigPath: configPath, BuildVersion: version.Version, Progress: progress.Report,
			})
			if err != nil {
				return err
			}
			// FINISH detached the OOB child pipes. A closed diagnostic pipe is
			// expected while the foreground responder owns the data plane.
			if result.FinishRecorded {
				return nil
			}
			return writeGateCResult(command.ErrOrStderr(), result)
		},
	}
	command.Flags().BoolVar(&stdio, "stdio", false, "use the dedicated bounded SSH child byte stream (required)")
	return command
}

type gateCProgressWriter struct {
	mu        sync.Mutex
	encoder   *json.Encoder
	responder bool
	detached  bool
}

func newGateCProgressWriter(output io.Writer) *gateCProgressWriter {
	return &gateCProgressWriter{encoder: json.NewEncoder(output)}
}

func (writer *gateCProgressWriter) Report(progress gatecorchestrator.Progress) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.responder && progress.Stage == gatecorchestrator.StageFinishRecorded {
		writer.detached = true
	}
	// Do not even attempt a write to the detached SSH stderr. A real Unix
	// fd 2 pipe may deliver SIGPIPE before an io.Writer error can be ignored.
	if writer.detached {
		return nil
	}
	err := writer.encoder.Encode(struct {
		Stage             string `json:"stage"`
		RemainingBudgetMS int64  `json:"remaining_budget_ms"`
		Cancellable       bool   `json:"cancellable"`
	}{Stage: progress.Stage, RemainingBudgetMS: progress.RemainingBudget.Milliseconds(), Cancellable: progress.Cancellable})
	return err
}

func writeGateCResult(output io.Writer, result gatecorchestrator.Result) error {
	return json.NewEncoder(output).Encode(struct {
		Terminal       string `json:"terminal"`
		DataPlaneReady bool   `json:"data_plane_ready"`
		FinishRecorded bool   `json:"finish_recorded"`
		SessionEnd     string `json:"session_end"`
	}{
		Terminal: result.Terminal, DataPlaneReady: result.DataPlaneReady,
		FinishRecorded: result.FinishRecorded, SessionEnd: result.SessionEnd,
	})
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
