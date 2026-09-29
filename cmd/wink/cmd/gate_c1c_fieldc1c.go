//go:build fieldc1c

package cmd

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/gatecorchestrator"
)

func addDeploymentCommands(root *cobra.Command, options *Options) {
	var instancePath string
	command := &cobra.Command{Use: "gate-c1c", Short: "Run one explicitly authorized field instance", Args: cobra.NoArgs}
	run := &cobra.Command{Use: "run", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if instancePath == "" || options == nil || options.ConfigPath != "" || options.StatePath != "" || options.Verbose {
			return fieldc1c.ErrInvalid
		}
		ctx, stop := solverSignalContext(command.Context())
		defer stop()
		summary, err := gatecorchestrator.RunFieldInitiator(ctx, instancePath)
		if writeErr := json.NewEncoder(command.OutOrStdout()).Encode(summary); writeErr != nil {
			return fieldc1c.ErrInvalid
		}
		return err
	}}
	run.Flags().StringVar(&instancePath, "instance", "", "canonical private authorization instance (required)")
	command.AddCommand(run)
	addFieldReadOnlyCommands(command)
	root.AddCommand(command)
}

func addFieldReadOnlyCommands(parent *cobra.Command) {
	guard := func(command *cobra.Command, args []string) error {
		if len(args) != 0 {
			return fieldc1c.ErrInvalid
		}
		for _, name := range []string{"config", "state", "verbose"} {
			if flag := command.Flags().Lookup(name); flag != nil && flag.Changed {
				return fieldc1c.ErrInvalid
			}
		}
		return nil
	}
	write := func(command *cobra.Command, value any, result error) error {
		if json.NewEncoder(command.OutOrStdout()).Encode(value) != nil {
			return fieldc1c.ErrInvalid
		}
		return result
	}
	verify := &cobra.Command{Use: "verify-sshd", Args: guard, RunE: func(command *cobra.Command, _ []string) error {
		value, err := gatecorchestrator.VerifyFieldSSHD(command.InOrStdin())
		return write(command, value, err)
	}}
	var jsonOutput bool
	ledger := &cobra.Command{Use: "ledger", Args: guard, RunE: func(command *cobra.Command, _ []string) error {
		if !jsonOutput || !command.Flags().Changed("json") {
			return fieldc1c.ErrInvalid
		}
		value, err := gatecorchestrator.InspectFieldLedger()
		return write(command, value, err)
	}}
	ledger.Flags().BoolVar(&jsonOutput, "json", false, "emit a read-only canonical ledger snapshot")
	var paths gatecorchestrator.FieldDerivePaths
	derive := &cobra.Command{Use: "derive", Args: guard, RunE: func(command *cobra.Command, _ []string) error {
		if !paths.Valid() {
			return fieldc1c.ErrInvalid
		}
		value, err := gatecorchestrator.DeriveFieldTools(paths)
		return write(command, value, err)
	}}
	derive.Flags().StringVar(&paths.Field, "field", "", "absolute path to the reviewed field binary")
	derive.Flags().StringVar(&paths.Router, "router", "", "absolute path to the reviewed router binary")
	derive.Flags().StringVar(&paths.InitiatorConfig, "initiator-config", "", "absolute initiator configuration path")
	derive.Flags().StringVar(&paths.ResponderConfig, "responder-config", "", "absolute responder configuration path")
	for _, command := range []*cobra.Command{verify, ledger, derive} {
		command.SetFlagErrorFunc(func(*cobra.Command, error) error { return fieldc1c.ErrInvalid })
		parent.AddCommand(command)
	}
}

func tryDeploymentChild(command *cobra.Command, options *Options, runner gateCProductRunner) (bool, error) {
	if _, system := runner.(systemGateCProductRunner); !system {
		return false, nil
	}
	if options == nil || options.ConfigPath != "" || options.StatePath != "" || options.Verbose {
		return true, fieldc1c.ErrInvalid
	}
	ctx, stop := solverSignalContext(command.Context())
	defer stop()
	_, err := gatecorchestrator.RunFieldResponder(ctx, command.InOrStdin(), command.OutOrStdout())
	// stdout is exclusively WYRC. The field responder stores diagnostics in
	// its private evidence file, never a possibly detached SSH stderr pipe.
	return true, err
}
