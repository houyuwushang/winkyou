package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	winkclient "winkyou/pkg/client"
)

func newPeersCmd(opts *Options) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "peers",
		Short: "Show connected peers",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := winkclient.LoadRuntimeState(opts.ConfigPath)
			switch {
			case err == nil:
				// have state
			case errors.Is(err, winkclient.ErrRuntimeStateNotFound):
				if asJSON {
					return writeJSON(cmd, []any{})
				}
				cmd.Println("No peers (not connected)")
				return nil
			default:
				return err
			}

			if asJSON {
				return writeJSON(cmd, state.Peers)
			}

			if len(state.Peers) == 0 {
				cmd.Println("No peers")
				return nil
			}

			for i, p := range state.Peers {
				if i > 0 {
					cmd.Println()
				}
				cmd.Printf("Peer %d\n", i+1)
				cmd.Printf("  Name:       %s\n", dashIfEmpty(p.Name))
				cmd.Printf("  Node ID:    %s\n", dashIfEmpty(p.NodeID))
				cmd.Printf("  Virtual IP: %s\n", dashIfEmpty(p.VirtualIP))
				cmd.Printf("  Public Key: %s\n", dashIfEmpty(p.PublicKey))
				cmd.Printf("  State:      %s\n", dashIfEmpty(p.State))
				cmd.Printf("  Endpoint:   %s\n", dashIfEmpty(p.Endpoint))
				cmd.Printf("  Conn Type:  %s\n", dashIfEmpty(p.ConnectionType))
				cmd.Printf("  ICE State:  %s\n", dashIfEmpty(p.ICEState))
				cmd.Printf("  Local Cand: %s\n", dashIfEmpty(p.LocalCandidate))
				cmd.Printf("  Remote Cand: %s\n", dashIfEmpty(p.RemoteCandidate))
				cmd.Printf("  Tx:         %s\n", formatBytes(p.TxBytes))
				cmd.Printf("  Rx:         %s\n", formatBytes(p.RxBytes))
				cmd.Printf("  Xport Tx:   %d pkts / %s\n", p.TransportTxPackets, formatBytes(p.TransportTxBytes))
				cmd.Printf("  Xport Rx:   %d pkts / %s\n", p.TransportRxPackets, formatBytes(p.TransportRxBytes))
				cmd.Printf("  Xport Err:  %s\n", dashIfEmpty(p.TransportLastError))
				if !p.LastHandshake.IsZero() {
					cmd.Printf("  Handshake:  %s\n", p.LastHandshake.Format(time.RFC3339))
				} else {
					cmd.Printf("  Handshake:  -\n")
				}
				if !p.LastSeen.IsZero() {
					cmd.Printf("  Last Seen:  %s\n", p.LastSeen.Format(time.RFC3339))
				} else {
					cmd.Printf("  Last Seen:  -\n")
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output peers as json")
	return cmd
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
