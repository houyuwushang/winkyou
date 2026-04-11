package cmd

import (
	"errors"
	"os"

	winkclient "winkyou/pkg/client"

	"github.com/spf13/cobra"
)

func newDownCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Disconnect and stop",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := winkclient.LoadRuntimeState(opts.ConfigPath)
			if err != nil {
				if errors.Is(err, winkclient.ErrRuntimeStateNotFound) {
					cmd.Println("wink down: no active runtime state")
					return nil
				}
				return err
			}

			var killErr error
			if state.PID > 0 && state.PID != os.Getpid() {
				process, err := os.FindProcess(state.PID)
				if err == nil {
					killErr = process.Kill()
				} else {
					killErr = err
				}
			}

			if err := winkclient.RemoveRuntimeState(opts.ConfigPath); err != nil {
				return err
			}

			if killErr != nil {
				cmd.Printf("wink down: cleared runtime state, process termination returned: %v\n", killErr)
				return nil
			}

			cmd.Printf("wink down: stopped pid=%d\n", state.PID)
			return nil
		},
	}
}
