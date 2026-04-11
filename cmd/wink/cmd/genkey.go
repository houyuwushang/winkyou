package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"winkyou/pkg/tunnel"
)

func newGenkeyCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a WireGuard key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, err := tunnel.GeneratePrivateKey()
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
			pub := priv.PublicKey()

			if asJSON {
				return writeJSON(cmd, map[string]string{
					"private_key": priv.String(),
					"public_key":  pub.String(),
				})
			}

			cmd.Printf("Private:  %s\n", priv.String())
			cmd.Printf("Public:   %s\n", pub.String())
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output keys as json")
	return cmd
}
