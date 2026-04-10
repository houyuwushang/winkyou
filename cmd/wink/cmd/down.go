package cmd

import "github.com/spf13/cobra"

func newDownCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Disconnect and stop",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("wink down placeholder: engine not implemented yet")
			return nil
		},
	}
}

