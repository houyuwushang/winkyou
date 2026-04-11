package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"

	"github.com/spf13/cobra"
)

func newStatusCmd(opts *Options) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}

			state, stateErr := winkclient.LoadRuntimeState(opts.ConfigPath)
			switch {
			case stateErr == nil:
				if asJSON {
					return writeJSON(cmd, state)
				}
				printStatus(cmd, state, cfg, runtimeStatePath(opts))
				return nil
			case errors.Is(stateErr, winkclient.ErrRuntimeStateNotFound):
				disconnected := disconnectedStatus(cfg)
				if asJSON {
					return writeJSON(cmd, disconnected)
				}
				printDisconnectedStatus(cmd, cfg)
				return nil
			default:
				return stateErr
			}
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output status as json")
	return cmd
}

func printStatus(cmd *cobra.Command, state *winkclient.RuntimeState, cfg *config.Config, statePath string) {
	displayState := state.Status.State
	if !state.IsFresh(20*time.Second) && state.Status.State != winkclient.EngineStateStopped.String() {
		displayState = "stale"
	}

	knownPeers := len(state.Peers)
	connectedPeers := countPeersByState(state.Peers, winkclient.PeerStateConnected.String())

	cmd.Println("WinkYou Status")
	cmd.Println("--------------")
	cmd.Printf("State:         %s\n", strings.Title(displayState))
	cmd.Printf("Node:          %s\n", firstNonEmpty(state.Status.NodeName, cfg.Node.Name))
	cmd.Printf("Node ID:       %s\n", dashIfEmpty(state.Status.NodeID))
	cmd.Printf("Backend:       %s\n", firstNonEmpty(state.Status.Backend, cfg.NetIf.Backend))
	cmd.Printf("Coordinator:   %s\n", firstNonEmpty(state.Status.CoordinatorURL, cfg.Coordinator.URL))
	cmd.Printf("Virtual IP:    %s\n", dashIfEmpty(state.Status.VirtualIP))
	cmd.Printf("Network CIDR:  %s\n", dashIfEmpty(state.Status.NetworkCIDR))
	cmd.Printf("NAT Type:      %s\n", dashIfEmpty(state.Status.NATType))
	cmd.Printf("Peers:         %d known, %d connected\n", knownPeers, connectedPeers)
	cmd.Printf("Uptime:        %s\n", dashIfEmpty(state.Status.Uptime))
	cmd.Printf("Updated:       %s\n", state.UpdatedAt.Format(time.RFC3339))
	if state.Status.LastError != "" {
		cmd.Printf("Last Error:    %s\n", state.Status.LastError)
	}
	cmd.Printf("State File:    %s\n", statePath)
}

func printDisconnectedStatus(cmd *cobra.Command, cfg *config.Config) {
	cmd.Println("WinkYou Status")
	cmd.Println("--------------")
	cmd.Println("State:         Not Connected")
	cmd.Printf("Node:          %s\n", cfg.Node.Name)
	cmd.Printf("Backend:       %s\n", cfg.NetIf.Backend)
	cmd.Printf("Coordinator:   %s\n", dashIfEmpty(cfg.Coordinator.URL))
	cmd.Println("Virtual IP:    -")
	cmd.Println("Network CIDR:  -")
	cmd.Println("NAT Type:      -")
	cmd.Println("Peers:         0 known, 0 connected")
	cmd.Println("Uptime:        -")
}

func disconnectedStatus(cfg *config.Config) map[string]any {
	return map[string]any{
		"state":           winkclient.EngineStateStopped.String(),
		"node":            cfg.Node.Name,
		"backend":         cfg.NetIf.Backend,
		"coordinator":     cfg.Coordinator.URL,
		"virtual_ip":      "",
		"network_cidr":    "",
		"nat_type":        "",
		"known_peers":     0,
		"connected_peers": 0,
	}
}

func countPeersByState(peers []winkclient.RuntimePeerStatus, state string) int {
	total := 0
	for _, peer := range peers {
		if peer.State == state {
			total++
		}
	}
	return total
}

func writeJSON(cmd *cobra.Command, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(payload))
	return nil
}

func dashIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
