package cmd

import (
	"github.com/spf13/cobra"

	"winkyou/pkg/logger"
)

func newUpCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Start and connect to the network",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, log, err := loadRuntime(opts)
			if err != nil {
				return err
			}
			defer log.Sync()

			log.Info("starting wink", logger.String("node", cfg.Node.Name), logger.String("backend", cfg.NetIf.Backend))
			cmd.Printf("wink up placeholder: node=%s backend=%s coordinator=%s\n", cfg.Node.Name, cfg.NetIf.Backend, cfg.Coordinator.URL)
			return nil
		},
	}
}

