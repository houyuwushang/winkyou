package cmd

import (
	"github.com/spf13/cobra"

	"winkyou/pkg/config"
)

type Options struct {
	ConfigPath string
	Verbose    bool
}

func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	opts := &Options{
		ConfigPath: "",
	}

	cmd := &cobra.Command{
		Use:           "wink",
		Short:         "WinkYou - P2P Virtual LAN",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVarP(&opts.ConfigPath, "config", "c", opts.ConfigPath, "config file path (default "+config.DefaultPath()+")")
	cmd.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "enable verbose logging")

	cmd.AddCommand(
		newUpCmd(opts),
		newDownCmd(opts),
		newStatusCmd(opts),
		newPeersCmd(opts),
		newGenkeyCmd(),
		newVersionCmd(),
	)

	return cmd
}
