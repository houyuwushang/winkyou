package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"
	"winkyou/pkg/nat"
	"winkyou/pkg/netutil"

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
	cmd.AddCommand(newDebugPortAllocCmd(opts))
	return cmd
}

type portAllocSampleJSON struct {
	Server     string `json:"server,omitempty"`
	ServerAddr string `json:"server_addr,omitempty"`
	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  int    `json:"local_port"`
	MappedIP   string `json:"mapped_ip"`
	MappedPort int    `json:"mapped_port"`
}

type portAllocMappingProbeJSON struct {
	Server     string `json:"server"`
	ServerAddr string `json:"server_addr,omitempty"`
	LocalAddr  string `json:"local_addr,omitempty"`
	MappedAddr string `json:"mapped_addr,omitempty"`
	Error      string `json:"error,omitempty"`
}

type portAllocOutput struct {
	// Server is kept for compatibility with the original single-STUN JSON.
	Server             string                      `json:"server"`
	Servers            []string                    `json:"servers"`
	LocalBindInterface string                      `json:"local_bind_interface,omitempty"`
	LocalBindIP        string                      `json:"local_bind_ip,omitempty"`
	MappingType        string                      `json:"mapping_type"`
	MappingError       string                      `json:"mapping_error,omitempty"`
	MappingProbes      []portAllocMappingProbeJSON `json:"mapping_probes,omitempty"`
	SampleCount        int                         `json:"sample_count"`
	Pattern            string                      `json:"pattern"`
	Delta              int                         `json:"delta"`
	MappedIP           string                      `json:"mapped_ip"`
	StableIP           bool                        `json:"stable_ip"`
	Confidence         float64                     `json:"confidence"`
	Predictable        bool                        `json:"predictable"`
	Samples            []portAllocSampleJSON       `json:"samples"`
	Predicted          []int                       `json:"predicted_targets,omitempty"`
}

// newDebugPortAllocCmd probes the NAT's external-port allocation pattern, which
// decides whether the birthday-paradox puncher can predict a peer's next mapped
// port or must fall back to random spraying.
func newDebugPortAllocCmd(opts *Options) *cobra.Command {
	var (
		asJSON     bool
		samples    int
		stunServer []string
	)

	cmd := &cobra.Command{
		Use:   "port-alloc [stun-server...]",
		Short: "Probe the NAT external-port allocation pattern (hole-punch prediction)",
		Args:  cobra.MaximumNArgs(16),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgErr := loadConfig(opts)
			if cfgErr != nil {
				return fmt.Errorf("load config for punch-interface-aware probe: %w", cfgErr)
			}
			servers := append([]string(nil), stunServer...)
			if len(servers) == 0 {
				servers = append(servers, args...)
			}
			if len(servers) == 0 {
				if len(cfg.NAT.STUNServers) > 0 {
					servers = append(servers, cfg.NAT.STUNServers...)
				}
			}
			servers = normalizedPortAllocServers(servers)
			if len(servers) == 0 {
				return errors.New("no STUN server: pass one or more as arguments/--stun flags, or set nat.stun_servers in config")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
			defer cancel()
			var binding *netutil.UDPBinding
			resolved, resolveErr := netutil.ResolveUDPBinding(cfg.NAT.PunchInterface)
			if resolveErr != nil {
				return resolveErr
			}
			binding = resolved

			report, err := nat.ProbePortAllocationWithMappingBound(ctx, servers, samples, binding)
			if err != nil {
				return err
			}

			out := portAllocOutputFromReport(servers, report, binding)
			if asJSON {
				return writeJSON(cmd, out)
			}
			printPortAllocOutput(cmd, out)
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output as json")
	cmd.Flags().IntVar(&samples, "samples", 0, "number of probe sockets (default 8)")
	cmd.Flags().StringArrayVar(&stunServer, "stun", nil, "STUN server; repeat to test mapping behavior (overrides arguments and config)")
	return cmd
}

func portAllocOutputFromReport(servers []string, report nat.PortAllocationReport, binding *netutil.UDPBinding) *portAllocOutput {
	predictable := report.Pattern == nat.PortAllocationSequential || report.Pattern == nat.PortAllocationPreserving

	out := &portAllocOutput{
		Servers:      append([]string(nil), servers...),
		MappingType:  report.MappingNATType.String(),
		MappingError: report.MappingError,
		SampleCount:  len(report.Samples),
		Pattern:      report.Pattern.String(),
		Delta:        report.Delta,
		StableIP:     report.StableIP,
		Confidence:   report.Confidence,
		Predictable:  predictable,
	}
	if binding != nil {
		out.LocalBindInterface = binding.InterfaceName
		out.LocalBindIP = binding.LocalIP.String()
	}
	if len(servers) > 0 {
		out.Server = servers[0]
	}
	if report.MappedIP != nil {
		out.MappedIP = report.MappedIP.String()
	}
	for _, probe := range report.MappingProbes {
		item := portAllocMappingProbeJSON{Server: probe.Server, Error: probe.Error}
		if probe.LocalAddr != nil {
			item.LocalAddr = probe.LocalAddr.String()
		}
		if probe.ServerAddr != nil {
			item.ServerAddr = probe.ServerAddr.String()
		}
		if probe.MappedAddr != nil {
			item.MappedAddr = probe.MappedAddr.String()
		}
		out.MappingProbes = append(out.MappingProbes, item)
	}
	for _, s := range report.Samples {
		ip := ""
		localIP := ""
		if s.MappedIP != nil {
			ip = s.MappedIP.String()
		}
		if s.LocalIP != nil {
			localIP = s.LocalIP.String()
		}
		out.Samples = append(out.Samples, portAllocSampleJSON{
			Server:     s.Server,
			LocalIP:    localIP,
			LocalPort:  s.LocalPort,
			MappedIP:   ip,
			MappedPort: s.MappedPort,
		})
		if s.ServerAddr != nil {
			out.Samples[len(out.Samples)-1].ServerAddr = s.ServerAddr.String()
		}
	}
	if predictable && len(report.Samples) > 0 {
		base := report.Samples[len(report.Samples)-1].MappedPort
		out.Predicted = report.PredictMappedPorts(base, 8)
	}
	return out
}

func printPortAllocOutput(cmd *cobra.Command, out *portAllocOutput) {
	cmd.Println("NAT Port Allocation Probe")
	cmd.Println("-------------------------")
	cmd.Printf("STUN Servers: %s\n", strings.Join(out.Servers, ", "))
	if out.LocalBindInterface != "" || out.LocalBindIP != "" {
		cmd.Printf("Underlay:     %s (%s)\n", dashIfEmpty(out.LocalBindInterface), dashIfEmpty(out.LocalBindIP))
	}
	cmd.Printf("Mapping:      %s\n", out.MappingType)
	if out.MappingError != "" {
		cmd.Printf("Mapping note: %s\n", out.MappingError)
	}
	for _, probe := range out.MappingProbes {
		if probe.MappedAddr != "" {
			cmd.Printf("  %s [%s] -> %s (local %s)\n", probe.Server, dashIfEmpty(probe.ServerAddr), probe.MappedAddr, dashIfEmpty(probe.LocalAddr))
		} else {
			cmd.Printf("  %s -> ERROR: %s\n", probe.Server, probe.Error)
		}
	}
	cmd.Printf("Samples:      %d usable\n", out.SampleCount)
	cmd.Printf("Public IP:    %s (%s)\n", dashIfEmpty(out.MappedIP), stableLabel(out.StableIP))
	switch out.Pattern {
	case "sequential":
		cmd.Printf("Pattern:      sequential (delta %+d, confidence %.2f)\n", out.Delta, out.Confidence)
	default:
		cmd.Printf("Pattern:      %s (confidence %.2f)\n", out.Pattern, out.Confidence)
	}
	if out.Predictable {
		cmd.Println("Prediction:   YES — peers can target predicted ports; birthday-punch uses prediction.")
	} else {
		cmd.Println("Prediction:   NO — birthday-punch will fall back to random spraying.")
	}
	if len(out.Samples) > 0 {
		cmd.Println("Allocation samples (server, local -> mapped):")
		for _, s := range out.Samples {
			cmd.Printf("  %s [%s]: %s:%d -> %s:%d\n", s.Server, dashIfEmpty(s.ServerAddr), dashIfEmpty(s.LocalIP), s.LocalPort, s.MappedIP, s.MappedPort)
		}
	}
	if len(out.Predicted) > 0 {
		cmd.Printf("Predicted next targets: %v\n", out.Predicted)
	}
}

func normalizedPortAllocServers(servers []string) []string {
	seen := make(map[string]struct{}, len(servers))
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		out = append(out, server)
	}
	return out
}

func stableLabel(stable bool) string {
	if stable {
		return "stable"
	}
	return "UNSTABLE — public IP changed across probes"
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

	state, stateErr := winkclient.LoadRuntimeState(runtimeStateKey(opts))
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
