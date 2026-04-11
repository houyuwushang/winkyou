package cmd

import (
	"errors"
	"os"
	"strings"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"

	"github.com/spf13/cobra"
)

type debugOutput struct {
	ConfigPath       string             `json:"config_path"`
	RuntimeStatePath string             `json:"runtime_state_path"`
	ConfigExists     bool               `json:"config_exists"`
	ConfigLoadable   bool               `json:"config_loadable"`
	ConfigError      string             `json:"config_error,omitempty"`
	NodeName         string             `json:"node_name"`
	Backend          string             `json:"backend"`
	CoordinatorURL   string             `json:"coordinator_url"`
	RuntimeState     *runtimeDebugState `json:"runtime_state"`
}

type runtimeDebugState struct {
	Exists       bool      `json:"exists"`
	Message      string    `json:"message,omitempty"`
	State        string    `json:"state,omitempty"`
	NodeID       string    `json:"node_id,omitempty"`
	VirtualIP    string    `json:"virtual_ip,omitempty"`
	NetworkCIDR  string    `json:"network_cidr,omitempty"`
	NATType      string    `json:"nat_type,omitempty"`
	KnownPeers   int       `json:"known_peers"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	Fresh        bool      `json:"fresh"`
	RuntimeError string    `json:"runtime_error,omitempty"`
}

func newDebugCmd(opts *Options) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Show config, runtime state, and basic diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := collectDebugOutput(opts)
			if asJSON {
				return writeJSON(cmd, info)
			}
			printDebugOutput(cmd, info)
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output debug info as json")
	return cmd
}

func collectDebugOutput(opts *Options) *debugOutput {
	resolvedConfigPath := opts.ConfigPath
	if strings.TrimSpace(resolvedConfigPath) == "" {
		resolvedConfigPath = config.DefaultPath()
	}

	info := &debugOutput{
		ConfigPath:       resolvedConfigPath,
		RuntimeStatePath: runtimeStatePath(opts),
		RuntimeState: &runtimeDebugState{
			Exists:     false,
			Message:    "not connected (no runtime state file)",
			KnownPeers: 0,
		},
	}

	if stat, err := os.Stat(resolvedConfigPath); err == nil && !stat.IsDir() {
		info.ConfigExists = true
	}

	cfg, err := loadConfig(opts)
	if err != nil {
		info.ConfigError = err.Error()
		fallback := config.Default()
		info.NodeName = fallback.Node.Name
		info.Backend = fallback.NetIf.Backend
		info.CoordinatorURL = fallback.Coordinator.URL
	} else {
		info.ConfigLoadable = true
		info.NodeName = cfg.Node.Name
		info.Backend = cfg.NetIf.Backend
		info.CoordinatorURL = cfg.Coordinator.URL
	}

	state, stateErr := winkclient.LoadRuntimeState(opts.ConfigPath)
	switch {
	case stateErr == nil:
		info.RuntimeState = &runtimeDebugState{
			Exists:      true,
			State:       state.Status.State,
			NodeID:      state.Status.NodeID,
			VirtualIP:   state.Status.VirtualIP,
			NetworkCIDR: state.Status.NetworkCIDR,
			NATType:     state.Status.NATType,
			KnownPeers:  len(state.Peers),
			UpdatedAt:   state.UpdatedAt,
			Fresh:       state.IsFresh(20 * time.Second),
		}
	case errors.Is(stateErr, winkclient.ErrRuntimeStateNotFound):
	default:
		info.RuntimeState.RuntimeError = stateErr.Error()
		info.RuntimeState.Message = "runtime state unreadable"
	}

	return info
}

func printDebugOutput(cmd *cobra.Command, info *debugOutput) {
	cmd.Println("WinkYou Debug")
	cmd.Println("-------------")
	cmd.Printf("Config Path:        %s\n", info.ConfigPath)
	cmd.Printf("Runtime State Path: %s\n", info.RuntimeStatePath)
	cmd.Printf("Config Exists:      %s\n", yesNo(info.ConfigExists))
	cmd.Printf("Config Loadable:    %s\n", yesNo(info.ConfigLoadable))
	if info.ConfigError != "" {
		cmd.Printf("Config Error:       %s\n", info.ConfigError)
	}
	cmd.Printf("Node Name:          %s\n", dashIfEmpty(info.NodeName))
	cmd.Printf("Backend:            %s\n", dashIfEmpty(info.Backend))
	cmd.Printf("Coordinator URL:    %s\n", dashIfEmpty(info.CoordinatorURL))
	cmd.Printf("Runtime State:      %s\n", yesNo(info.RuntimeState.Exists))
	if info.RuntimeState.Exists {
		cmd.Printf("State:              %s\n", dashIfEmpty(info.RuntimeState.State))
		cmd.Printf("Node ID:            %s\n", dashIfEmpty(info.RuntimeState.NodeID))
		cmd.Printf("Virtual IP:         %s\n", dashIfEmpty(info.RuntimeState.VirtualIP))
		cmd.Printf("Network CIDR:       %s\n", dashIfEmpty(info.RuntimeState.NetworkCIDR))
		cmd.Printf("NAT Type:           %s\n", dashIfEmpty(info.RuntimeState.NATType))
		cmd.Printf("Known Peers:        %d\n", info.RuntimeState.KnownPeers)
		cmd.Printf("Fresh:              %s\n", yesNo(info.RuntimeState.Fresh))
		if !info.RuntimeState.UpdatedAt.IsZero() {
			cmd.Printf("Updated:            %s\n", info.RuntimeState.UpdatedAt.Format(time.RFC3339))
		}
	} else {
		cmd.Printf("State:              %s\n", firstNonEmpty(info.RuntimeState.Message, "not connected"))
		cmd.Printf("Known Peers:        %d\n", info.RuntimeState.KnownPeers)
	}
	if info.RuntimeState.RuntimeError != "" {
		cmd.Printf("Runtime Error:      %s\n", info.RuntimeState.RuntimeError)
	}
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
