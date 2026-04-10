package cmd

import (
	"github.com/spf13/cobra"

	"winkyou/pkg/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(version.String())
		},
	}
}

