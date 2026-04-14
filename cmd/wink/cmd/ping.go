package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
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

			requestID, err := newPingRequestID()
			if err != nil {
				return err
			}

			start := time.Now()
			conn, err := net.DialTimeout("udp4", net.JoinHostPort(peer.VirtualIP, strconv.Itoa(winkclient.PingPort)), 1200*time.Millisecond)
			if err != nil {
				return fmt.Errorf("ping %s (%s) failed: %w", peer.Name, peer.VirtualIP, err)
			}
			defer conn.Close()

			payload, err := winkclient.MarshalPingRequest(winkclient.PingRequest{ID: requestID})
			if err != nil {
				return err
			}
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return fmt.Errorf("ping %s (%s) failed: %w", peer.Name, peer.VirtualIP, err)
			}
			if _, err := conn.Write(payload); err != nil {
				return fmt.Errorf("ping %s (%s) failed: %w", peer.Name, peer.VirtualIP, err)
			}

			responseBuf := make([]byte, 2048)
			n, err := conn.Read(responseBuf)
			if err != nil {
				return fmt.Errorf("ping %s (%s) timed out waiting for reply: %w", peer.Name, peer.VirtualIP, err)
			}
			response, err := winkclient.UnmarshalPingResponse(responseBuf[:n])
			if err != nil {
				return fmt.Errorf("ping %s (%s) failed to parse reply: %w", peer.Name, peer.VirtualIP, err)
			}
			if response.ID != requestID {
				return fmt.Errorf("ping %s (%s) received mismatched reply id", peer.Name, peer.VirtualIP)
			}

			latency := time.Since(start)
			cmd.Printf("PING %s (%s) via %s\n", peer.VirtualIP, peer.Name, dashIfEmpty(peer.ConnectionType))
			cmd.Printf("reply: time=%s context=%s endpoint=%s\n", latency.Round(time.Millisecond), dashIfEmpty(peer.ConnectionType), dashIfEmpty(peer.Endpoint))
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

func newPingRequestID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate ping id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
