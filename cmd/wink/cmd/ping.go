package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	winkclient "winkyou/pkg/client"
)

func newPingCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "ping <node-name|virtual-ip>",
		Short: "Probe peer reachability via virtual IP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := winkclient.LoadRuntimeState(opts.ConfigPath)
			if err != nil {
				return err
			}
			target := strings.TrimSpace(args[0])
			peer, err := findRuntimePeer(state.Peers, target)
			if err != nil {
				return err
			}
			if peer.VirtualIP == "" {
				return fmt.Errorf("peer %s has no virtual ip", peer.Name)
			}
			start := time.Now()
			conn, err := net.DialTimeout("udp", net.JoinHostPort(peer.VirtualIP, "33434"), 1200*time.Millisecond)
			if err != nil {
				return fmt.Errorf("ping %s (%s) failed: %w", peer.Name, peer.VirtualIP, err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("wink-ping")); err != nil {
				return fmt.Errorf("ping %s (%s) failed: %w", peer.Name, peer.VirtualIP, err)
			}
			latency := time.Since(start)
			cmd.Printf("PING %s (%s) via %s\n", peer.VirtualIP, peer.Name, dashIfEmpty(peer.ConnectionType))
			cmd.Printf("probe sent: time=%s context=%s endpoint=%s\n", latency.Round(time.Millisecond), dashIfEmpty(peer.ConnectionType), dashIfEmpty(peer.Endpoint))
			cmd.Println("note: current ping is UDP send-only probe; it does not wait for remote echo")
			return nil
		},
	}
}

func findRuntimePeer(peers []winkclient.RuntimePeerStatus, target string) (*winkclient.RuntimePeerStatus, error) {
	for i := range peers {
		p := &peers[i]
		if strings.EqualFold(p.Name, target) || p.VirtualIP == target {
			return p, nil
		}
	}
	return nil, fmt.Errorf("peer %q not found", target)
}
