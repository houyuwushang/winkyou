//go:build !fieldc1c

package cmd

import "github.com/spf13/cobra"

func addDeploymentCommands(*cobra.Command, *Options) {}
func tryDeploymentChild(*cobra.Command, *Options, gateCProductRunner) (bool, error) {
	return false, nil
}
