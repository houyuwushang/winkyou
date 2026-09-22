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
	root.AddCommand(command)
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
