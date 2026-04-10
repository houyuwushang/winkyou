package cmd

import "github.com/spf13/cobra"

func newStatusCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, log, err := loadRuntime(opts)
			if err != nil {
				return err
			}
			defer log.Sync()

			cmd.Println("WinkYou Status")
			cmd.Println("--------------")
			cmd.Println("State:         Not Connected")
			cmd.Printf("Node:          %s\n", cfg.Node.Name)
			cmd.Printf("Backend:       %s\n", cfg.NetIf.Backend)
			cmd.Println("Virtual IP:    -")
			cmd.Println("Peers:         0 online")
			return nil
		},
	}
}

