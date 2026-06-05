package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"
	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
	"winkyou/pkg/solver/strategy/relayonly"
	"winkyou/pkg/solver/strategy/tcpframed"
)

type doctorStatus string

const (
	doctorOK   doctorStatus = "ok"
	doctorWarn doctorStatus = "warn"
	doctorFail doctorStatus = "fail"
)

const doctorInbandHealthWindow = 20 * time.Second

const (
	doctorLegacyDirectPreferPlanID = "legacyice/direct_prefer"
	doctorPublicDirectPlanID       = "legacyice/public_direct"
	doctorLegacyRelayOnlyPlanID    = "legacyice/relay_only"
)

type doctorCheck struct {
	Layer      string       `json:"layer"`
	Name       string       `json:"name"`
	Status     doctorStatus `json:"status"`
	Message    string       `json:"message"`
	Suggestion string       `json:"suggestion,omitempty"`
}

type doctorSummary struct {
	OK    int          `json:"ok"`
	Warn  int          `json:"warn"`
	Fail  int          `json:"fail"`
	Worst doctorStatus `json:"worst"`
}

type doctorResult struct {
	Checks  []doctorCheck `json:"checks"`
	Summary doctorSummary `json:"summary"`
}

type doctorFlags struct {
	asJSON       bool
	relay        bool
	strategy     string
	routeTargets []string
}

type doctorProbes struct {
	Coordinator    func(context.Context, *config.Config) doctorCheck
	STUN           func(context.Context, *config.Config) doctorCheck
	TURN           func(context.Context, *config.Config) doctorCheck
	LocalInterface func(context.Context, *config.Config) doctorCheck
	IPForwarding   func(context.Context, *config.Config) doctorCheck
	RouteTable     func(context.Context, doctorAdvertisedRouteProbeInput) doctorCheck
	RouteTarget    func(context.Context, string) doctorCheck
}

type doctorAdvertisedRouteProbeInput struct {
	PeerName      string
	PeerVirtualIP string
	Route         string
}

func newDoctorCmd(opts *Options) *cobra.Command {
	return newDoctorCmdWithProbes(opts, doctorProbes{})
}

func newDoctorCmdWithProbes(opts *Options, probes doctorProbes) *cobra.Command {
	flags := doctorFlags{}
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run layered connectivity diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := runDoctor(cmd.Context(), opts, flags, probes)
			if flags.asJSON {
				return writeJSON(cmd, result)
			}
			printDoctorResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().BoolVar(&flags.asJSON, "json", false, "output diagnostics as json")
	cmd.Flags().BoolVar(&flags.relay, "relay", false, "require relay/TURN diagnostics")
	cmd.Flags().StringVar(&flags.strategy, "strategy", "", "check one strategy by name")
	cmd.Flags().StringArrayVar(&flags.routeTargets, "route-target", nil, "check the OS route selected for a target IP")
	return cmd
}

func runDoctor(ctx context.Context, opts *Options, flags doctorFlags, probes doctorProbes) doctorResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := doctorResult{}
	configPath := opts.ConfigPath
	if strings.TrimSpace(configPath) == "" {
		configPath = config.DefaultPath()
	}
	if _, err := os.Stat(configPath); err == nil {
		result.add(okCheck("config", "config file", "config file exists: "+configPath))
	} else if opts.ConfigPath == "" && os.IsNotExist(err) {
		result.add(warnCheck("config", "config file", "default config file not found; using built-in defaults", "create a config file or pass --config"))
	} else if os.IsNotExist(err) {
		result.add(failCheck("config", "config file", "config file not found: "+configPath, "check --config path"))
	} else if err != nil {
		result.add(failCheck("config", "config file", err.Error(), "check config file permissions"))
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		result.add(failCheck("config", "config loaded", err.Error(), "fix the config validation error"))
		result.finish()
		return result
	}
	result.add(okCheck("config", "config loaded", "config loaded"))
	addConfigChecks(&result, cfg)

	coordinatorProbe := probes.Coordinator
	if coordinatorProbe == nil {
		coordinatorProbe = defaultCoordinatorProbe
	}
	result.add(coordinatorProbe(ctx, cfg))

	stunProbe := probes.STUN
	if stunProbe == nil {
		stunProbe = defaultSTUNProbe
	}
	result.add(stunProbe(ctx, cfg))

	turnProbe := probes.TURN
	if turnProbe == nil {
		turnProbe = func(ctx context.Context, cfg *config.Config) doctorCheck {
			_ = ctx
			return defaultTURNProbe(cfg, flags.relay || requestedStrategy(flags) == relayonly.StrategyName || cfg.Connectivity.Mode == relayonly.StrategyName)
		}
	}
	result.add(turnProbe(ctx, cfg))

	interfaceProbe := probes.LocalInterface
	if interfaceProbe == nil {
		interfaceProbe = defaultLocalInterfaceProbe
	}
	result.add(interfaceProbe(ctx, cfg))

	state, stateErr := winkclient.LoadRuntimeState(runtimeStateKey(opts))
	addStrategyChecks(&result, cfg, flags)
	addCandidateFilterChecks(&result, cfg, state, stateErr)
	addPublicDirectEvidenceChecks(&result, opts)
	addTunnelChecks(&result, state, stateErr)
	routeTableProbe := probes.RouteTable
	if routeTableProbe == nil {
		routeTableProbe = defaultAdvertisedRouteTableProbe
	}
	addAdvertisedRouteChecks(ctx, &result, cfg, state, stateErr, routeTableProbe)
	routeTargetProbe := probes.RouteTarget
	if routeTargetProbe == nil {
		routeTargetProbe = defaultRouteTargetProbe
	}
	addRouteTargetChecks(ctx, &result, flags, routeTargetProbe)
	if len(normalizeStringList(cfg.Node.AdvertiseRoutes)) > 0 {
		ipForwardingProbe := probes.IPForwarding
		if ipForwardingProbe == nil {
			ipForwardingProbe = defaultIPForwardingProbe
		}
		result.add(ipForwardingProbe(ctx, cfg))
	}
	addTransportChecks(&result, state, stateErr)
	addInbandHealthChecks(&result, state, stateErr)
	addMultipathChecks(&result, cfg, state, stateErr)

	result.finish()
	return result
}

func addConfigChecks(result *doctorResult, cfg *config.Config) {
	if strings.TrimSpace(cfg.Coordinator.URL) == "" {
		result.add(failCheck("config", "coordinator url", "coordinator.url is empty", "set coordinator.url to grpc://host:50051"))
	} else {
		result.add(okCheck("config", "coordinator url", cfg.Coordinator.URL))
	}
	if strings.TrimSpace(cfg.Node.Name) == "" {
		result.add(failCheck("config", "node name", "node.name is empty", "set node.name"))
	} else {
		result.add(okCheck("config", "node name", cfg.Node.Name))
	}
	if strings.TrimSpace(cfg.WireGuard.PrivateKey) == "" {
		result.add(failCheck("config", "wireguard key", "wireguard.private_key is empty", "run wink genkey and update the config"))
	} else if strings.HasPrefix(strings.TrimSpace(cfg.WireGuard.PrivateKey), "<") {
		result.add(failCheck("config", "wireguard key", "wireguard.private_key is still a placeholder", "replace it with wink genkey output"))
	} else {
		result.add(okCheck("config", "wireguard key", "wireguard private key configured"))
	}
	if strings.TrimSpace(cfg.NetIf.Backend) == "" {
		result.add(failCheck("config", "netif backend", "netif.backend is empty", "set netif.backend to tun, userspace, proxy, or auto"))
	} else {
		result.add(okCheck("config", "netif backend", cfg.NetIf.Backend))
	}
}

func defaultCoordinatorProbe(ctx context.Context, cfg *config.Config) doctorCheck {
	if strings.TrimSpace(cfg.Coordinator.URL) == "" {
		return failCheck("coordinator", "reachable", "coordinator.url is empty", "set coordinator.url")
	}
	host, err := hostPortFromCoordinatorURL(cfg.Coordinator.URL)
	if err != nil {
		return failCheck("coordinator", "reachable", err.Error(), "use grpc://host:port")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		return failCheck("coordinator", "reachable", err.Error(), "check coordinator host, port, firewall, and auth key")
	}
	_ = conn.Close()
	return okCheck("coordinator", "reachable", "tcp connect succeeded: "+host)
}

func defaultSTUNProbe(ctx context.Context, cfg *config.Config) doctorCheck {
	servers, err := nat.PublicDirectSTUNServerURLs(nat.ICEConfig{
		STUNServers: cfg.NAT.STUNServers,
		TURNServers: doctorNATTURNServers(cfg.NAT.TURNServers),
	})
	if err != nil {
		return warnCheck("nat", "stun", "invalid public direct STUN/TURN configuration: "+err.Error(), "fix nat.stun_servers or UDP nat.turn_servers")
	}
	if len(servers) == 0 {
		return warnCheck("nat", "stun", "no STUN server configured", "configure nat.stun_servers, configure UDP nat.turn_servers for coturn STUN binding, or use TURN/relay_only")
	}

	servers = normalizeStringList(servers)
	if len(servers) == 0 {
		return warnCheck("nat", "stun", "no usable STUN server configured", "remove empty nat.stun_servers entries or configure a reachable STUN/UDP TURN server")
	}
	probeCtx, cancel := context.WithTimeout(ctx, stunMappingProbeTimeout(len(servers)))
	report, err := nat.ProbeSTUNMapping(probeCtx, servers)
	cancel()
	if err != nil {
		return warnCheck("nat", "stun", "all STUN probes failed: "+formatSTUNMappingReport(report), "configure a reachable STUN server near both peers, or use TURN/relay_only")
	}
	message := fmt.Sprintf("nat_type=%s %s", report.NATType.String(), formatSTUNMappingReport(report))
	if report.NATType == nat.NATTypeSymmetric {
		return warnCheck("nat", "stun", message, "public direct may fail with endpoint-dependent mappings; compare natpierce endpoints, configure stable public_endpoint_hints if available, or use relay_only fallback")
	}
	return okCheck("nat", "stun", message)
}

func stunMappingProbeTimeout(serverCount int) time.Duration {
	if serverCount <= 0 {
		return 2 * time.Second
	}
	timeout := time.Duration(serverCount) * 2 * time.Second
	if timeout > 6*time.Second {
		return 6 * time.Second
	}
	return timeout
}

func formatSTUNMappingReport(report nat.STUNMappingReport) string {
	parts := make([]string, 0, len(report.Probes))
	for _, probe := range report.Probes {
		parts = append(parts, formatSTUNMappingProbe(probe))
	}
	if len(parts) == 0 {
		return "no probe results"
	}
	return strings.Join(parts, "; ")
}

func formatSTUNMappingProbe(probe nat.STUNMappingProbe) string {
	if strings.TrimSpace(probe.Error) != "" {
		return fmt.Sprintf("%s error=%s", dashIfEmpty(probe.Server), probe.Error)
	}
	return fmt.Sprintf("%s mapped %s from local %s via %s", dashIfEmpty(probe.Server), formatUDPAddr(probe.MappedAddr), formatUDPAddr(probe.LocalAddr), formatUDPAddr(probe.ServerAddr))
}

func doctorNATTURNServers(servers []config.TURNServerConfig) []nat.TURNServer {
	if len(servers) == 0 {
		return nil
	}
	out := make([]nat.TURNServer, 0, len(servers))
	for _, server := range servers {
		out = append(out, nat.TURNServer{
			URL:      server.URL,
			Username: server.Username,
			Password: server.Password,
		})
	}
	return out
}

func defaultTURNProbe(cfg *config.Config, required bool) doctorCheck {
	if len(cfg.NAT.TURNServers) == 0 {
		if required {
			return failCheck("nat", "turn", "relay diagnostics requested but nat.turn_servers is empty", "configure coturn and nat.turn_servers")
		}
		return warnCheck("nat", "turn", "no TURN server configured", "configure nat.turn_servers to validate relay paths")
	}
	for i, server := range cfg.NAT.TURNServers {
		if strings.TrimSpace(server.URL) == "" || strings.TrimSpace(server.Username) == "" || strings.TrimSpace(server.Password) == "" {
			return failCheck("nat", "turn", fmt.Sprintf("turn server %d is missing url, username, or password", i), "set static coturn credentials")
		}
	}
	return okCheck("nat", "turn", fmt.Sprintf("%d TURN server(s) configured", len(cfg.NAT.TURNServers)))
}

func defaultLocalInterfaceProbe(ctx context.Context, cfg *config.Config) doctorCheck {
	_ = ctx
	backend := strings.ToLower(strings.TrimSpace(cfg.NetIf.Backend))
	if backend == "tun" || backend == "auto" {
		if runtime.GOOS == "linux" {
			if _, err := os.Stat("/dev/net/tun"); err != nil {
				return failCheck("local_interface", "tun", "/dev/net/tun is not available", "load tun module or run with proper permissions")
			}
		}
		if runtime.GOOS == "windows" {
			return warnCheck("local_interface", "wintun", "Wintun requires an elevated terminal", "run PowerShell or cmd as Administrator")
		}
	}
	return okCheck("local_interface", "backend", "backend configured: "+cfg.NetIf.Backend)
}

func defaultIPForwardingProbe(ctx context.Context, cfg *config.Config) doctorCheck {
	routes := normalizeStringList(cfg.Node.AdvertiseRoutes)
	if len(routes) == 0 {
		return okCheck("routing", "ip forwarding", "not required")
	}
	switch runtime.GOOS {
	case "linux":
		raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			return warnCheck("routing", "ip forwarding", "cannot read /proc/sys/net/ipv4/ip_forward: "+err.Error(), "verify sysctl net.ipv4.ip_forward=1 on the gateway peer")
		}
		if strings.TrimSpace(string(raw)) == "1" {
			return okCheck("routing", "ip forwarding", "Linux IPv4 forwarding is enabled")
		}
		return failCheck("routing", "ip forwarding", "Linux IPv4 forwarding is disabled", "enable sysctl net.ipv4.ip_forward=1 and allow forwarding in the firewall")
	case "windows":
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsIPForwardingProbeScript()).CombinedOutput()
		if err != nil {
			detail := strings.TrimSpace(string(output))
			if detail == "" {
				detail = err.Error()
			} else {
				detail += ": " + err.Error()
			}
			return warnCheck("routing", "ip forwarding", "cannot query Windows IP forwarding: "+detail, "run wink doctor from PowerShell and verify Windows IP forwarding on the gateway peer")
		}
		enabled, detail := parseWindowsIPForwardingProbeOutput(string(output))
		if enabled {
			return okCheck("routing", "ip forwarding", "Windows IP forwarding appears enabled: "+detail)
		}
		return failCheck("routing", "ip forwarding", "Windows IP forwarding appears disabled: "+detail, "enable routing on the gateway peer and allow forwarding in Windows Firewall")
	case "darwin":
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(probeCtx, "sysctl", "-n", "net.inet.ip.forwarding").CombinedOutput()
		if err != nil {
			return warnCheck("routing", "ip forwarding", "cannot query macOS forwarding: "+strings.TrimSpace(string(output)), "verify net.inet.ip.forwarding=1 on the gateway peer")
		}
		if strings.TrimSpace(string(output)) == "1" {
			return okCheck("routing", "ip forwarding", "macOS IPv4 forwarding is enabled")
		}
		return failCheck("routing", "ip forwarding", "macOS IPv4 forwarding is disabled", "enable net.inet.ip.forwarding=1 and allow forwarding in the firewall")
	default:
		return warnCheck("routing", "ip forwarding", "IP forwarding check is not implemented for "+runtime.GOOS, "verify OS packet forwarding manually on the gateway peer")
	}
}

func windowsIPForwardingProbeScript() string {
	return strings.Join([]string{
		"$ip = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name IPEnableRouter -ErrorAction SilentlyContinue).IPEnableRouter",
		"$enabled = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.Forwarding -eq 'Enabled' } | ForEach-Object { $_.InterfaceAlias })",
		"Write-Output (\"IPEnableRouter={0}\" -f $ip)",
		"Write-Output (\"ForwardingEnabled={0}\" -f ($enabled -join ','))",
	}, "; ")
}

func parseWindowsIPForwardingProbeOutput(output string) (bool, string) {
	lines := make([]string, 0)
	enabled := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if strings.EqualFold(line, "IPEnableRouter=1") {
			enabled = true
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "forwardingenabled=") {
			_, value, _ := strings.Cut(line, "=")
			value = strings.TrimSpace(value)
			if value != "" && !strings.EqualFold(value, "<nil>") {
				enabled = true
			}
		}
	}
	if len(lines) == 0 {
		return false, "no probe output"
	}
	return enabled, strings.Join(lines, "; ")
}

func addStrategyChecks(result *doctorResult, cfg *config.Config, flags doctorFlags) {
	order := configuredStrategyOrder(cfg)
	if len(order) == 0 {
		result.add(failCheck("strategy", "order", "no strategy order configured", "set connectivity.strategy_order"))
		return
	}
	result.add(okCheck("strategy", "order", strings.Join(order, " -> ")))
	if slices.Contains(order, legacyice.StrategyName) {
		result.add(legacyPlanCheck(cfg))
	}

	strategy := requestedStrategy(flags)
	if strategy == "" {
		return
	}
	if !knownDoctorStrategy(strategy) {
		result.add(failCheck("strategy", "requested", "unknown strategy: "+strategy, "use legacy_ice_udp, relay_only, or tcp_framed"))
		return
	}
	if !slices.Contains(order, strategy) {
		result.add(failCheck("strategy", "requested", strategy+" is not in connectivity.strategy_order", "add it to connectivity.strategy_order"))
		return
	}
	if strategy == tcpframed.StrategyName && !cfg.TCPFramed.Enabled {
		result.add(failCheck("strategy", "tcp_framed", "tcp_framed is in order but tcp_framed.enabled=false", "set tcp_framed.enabled=true"))
		return
	}
	result.add(okCheck("strategy", "requested", strategy+" is locally selectable"))
}

func legacyPlanCheck(cfg *config.Config) doctorCheck {
	plans := []string{doctorLegacyDirectPreferPlanID, doctorPublicDirectPlanID}
	if legacyRelayPlanEnabled(cfg) {
		plans = append(plans, doctorLegacyRelayOnlyPlanID)
		return okCheck("strategy", "legacy plans", strings.Join(plans, " -> "))
	}
	return okCheck("strategy", "legacy plans", strings.Join(plans, " -> ")+" (relay plan disabled: no TURN configured)")
}

func legacyRelayPlanEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	return cfg.NAT.ForceRelay ||
		strings.EqualFold(strings.TrimSpace(cfg.Connectivity.Mode), relayonly.StrategyName) ||
		hasDoctorTURNServers(cfg.NAT.TURNServers)
}

func hasDoctorTURNServers(servers []config.TURNServerConfig) bool {
	for _, server := range servers {
		if strings.TrimSpace(server.URL) != "" {
			return true
		}
	}
	return false
}

func addCandidateFilterChecks(result *doctorResult, cfg *config.Config, state *winkclient.RuntimeState, stateErr error) {
	filterSummary := candidateFilterSummary(cfg)
	if filterSummary == "" {
		result.add(okCheck("nat", "candidate filters", "no candidate filters configured"))
		if check := publicEndpointHintLocalBaseCheck(cfg.NAT.PublicEndpointHints, doctorLocalInterfaceIPs()); check != nil {
			result.add(*check)
		}
		if check := directTrustedCIDRLocalInterfaceCheck(cfg.NAT.DirectTrustedCIDRs, doctorLocalInterfaceAddrs()); check != nil {
			result.add(*check)
		}
		return
	}
	result.add(okCheck("nat", "candidate filters", filterSummary))
	if check := publicEndpointHintLocalBaseCheck(cfg.NAT.PublicEndpointHints, doctorLocalInterfaceIPs()); check != nil {
		result.add(*check)
	}
	if check := directTrustedCIDRLocalInterfaceCheck(cfg.NAT.DirectTrustedCIDRs, doctorLocalInterfaceAddrs()); check != nil {
		result.add(*check)
	}
	if stateErr != nil || state == nil {
		return
	}

	include, _ := parseDoctorCIDRs(cfg.NAT.CandidateCIDRInclude)
	exclude, _ := parseDoctorCIDRs(cfg.NAT.CandidateCIDRExclude)
	if len(include) == 0 && len(exclude) == 0 {
		return
	}
	for _, peer := range state.Peers {
		for _, raw := range []string{peer.LocalCandidate, peer.RemoteCandidate} {
			candidateIP := candidateIP(raw)
			if candidateIP == nil {
				continue
			}
			if ipInDoctorCIDRs(candidateIP, exclude) {
				result.add(failCheck("nat", "candidate selected", raw+" matches nat.candidate_cidr_exclude", "check candidate filters and restart wink up"))
				return
			}
			if len(include) > 0 && !ipInDoctorCIDRs(candidateIP, include) {
				result.add(warnCheck("nat", "candidate selected", raw+" is outside nat.candidate_cidr_include", "confirm runtime state is fresh and filters match the intended underlay"))
				return
			}
		}
	}
	result.add(okCheck("nat", "candidate selected", "runtime candidates satisfy configured CIDR filters"))
}

func doctorLocalInterfaceIPs() []net.IP {
	localAddrs := doctorLocalInterfaceAddrs()
	ips := make([]net.IP, 0, len(localAddrs))
	for _, addr := range localAddrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	return ips
}

type doctorLocalInterfaceAddr struct {
	Name string
	IP   net.IP
}

func doctorLocalInterfaceAddrs() []doctorLocalInterfaceAddr {
	ifaces, err := net.Interfaces()
	if err == nil {
		out := make([]doctorLocalInterfaceAddr, 0)
		for _, iface := range ifaces {
			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				if ip := doctorIPFromAddr(addr); ip != nil {
					out = append(out, doctorLocalInterfaceAddr{
						Name: iface.Name,
						IP:   append(net.IP(nil), ip...),
					})
				}
			}
		}
		return out
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]doctorLocalInterfaceAddr, 0, len(addrs))
	for _, addr := range addrs {
		if ip := doctorIPFromAddr(addr); ip != nil {
			out = append(out, doctorLocalInterfaceAddr{IP: append(net.IP(nil), ip...)})
		}
	}
	return out
}

func doctorIPFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func publicEndpointHintLocalBaseCheck(values []string, localIPs []net.IP) *doctorCheck {
	bases := publicEndpointHintLocalBases(values)
	if len(bases) == 0 {
		return nil
	}
	local := make(map[string]struct{}, len(localIPs))
	for _, ip := range localIPs {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			local[net.IP(v4).String()] = struct{}{}
			continue
		}
		local[ip.String()] = struct{}{}
	}
	missing := make([]string, 0, len(bases))
	present := make([]string, 0, len(bases))
	for _, base := range bases {
		raw := base.String()
		if _, ok := local[raw]; ok {
			present = append(present, raw)
			continue
		}
		missing = append(missing, raw)
	}
	if len(missing) > 0 {
		return checkPtr(warnCheck("nat", "public endpoint hint local base", "mapped public_endpoint_hints reference local base not present on this host: "+strings.Join(missing, ","), "set each mapped hint local base to a real underlay interface IP, not a virtual LAN peer address"))
	}
	return checkPtr(okCheck("nat", "public endpoint hint local base", "mapped public_endpoint_hints local bases are present: "+strings.Join(present, ",")))
}

func directTrustedCIDRLocalInterfaceCheck(values []string, localAddrs []doctorLocalInterfaceAddr) *doctorCheck {
	values = normalizeStringList(values)
	if len(values) == 0 {
		return nil
	}
	prefixes, err := parseDoctorCIDRs(values)
	if err != nil {
		return checkPtr(warnCheck("nat", "direct trusted cidrs", "cannot parse nat.direct_trusted_cidrs: "+err.Error(), "fix nat.direct_trusted_cidrs before trusting non-public direct candidates"))
	}

	suspicious := make([]string, 0)
	matched := make([]string, 0)
	for _, local := range localAddrs {
		if local.IP == nil || local.IP.To4() == nil {
			continue
		}
		for _, prefix := range prefixes {
			if prefix == nil || !prefix.Contains(local.IP) {
				continue
			}
			entry := dashIfEmpty(local.Name) + "=" + local.IP.String()
			if isLikelyVirtualUnderlayInterface(local.Name) {
				suspicious = append(suspicious, entry)
			} else {
				matched = append(matched, entry)
			}
		}
	}
	if len(suspicious) > 0 {
		return checkPtr(warnCheck("nat", "direct trusted cidrs", "nat.direct_trusted_cidrs matches likely virtual/overlay interface(s): "+strings.Join(suspicious, ","), "only trust real underlay CIDRs; do not trust natpierce, Tailscale, Docker, Wintun, or WinkYou virtual peer networks as protected direct evidence"))
	}
	if len(matched) > 0 {
		return checkPtr(okCheck("nat", "direct trusted cidrs", "trusted direct CIDR matches local interface(s): "+strings.Join(matched, ",")))
	}
	return checkPtr(okCheck("nat", "direct trusted cidrs", "trusted direct CIDR configured without local virtual-interface match"))
}

func isLikelyVirtualUnderlayInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, token := range []string{
		"natpierce",
		"tailscale",
		"zerotier",
		"hamachi",
		"wireguard",
		"wintun",
		"wink",
		"docker",
		"vethernet",
		"virtualbox",
		"vmware",
		"loopback",
	} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func publicEndpointHintLocalBases(values []string) []netip.Addr {
	seen := map[string]netip.Addr{}
	for _, raw := range values {
		_, localRaw, ok := strings.Cut(strings.TrimSpace(raw), "/")
		if !ok {
			continue
		}
		local, err := netip.ParseAddrPort(strings.TrimSpace(localRaw))
		if err != nil || !local.Addr().IsValid() {
			continue
		}
		seen[local.Addr().String()] = local.Addr()
	}
	if len(seen) == 0 {
		return nil
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]netip.Addr, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func checkPtr(check doctorCheck) *doctorCheck {
	return &check
}

func addPublicDirectEvidenceChecks(result *doctorResult, opts *Options) {
	path := observationStatePathFromKey(runtimeStateKey(opts))
	observations, err := loadDoctorObservations(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			result.add(warnCheck("nat", "public direct evidence", "observation history not found: "+path, "start wink up, attempt the peer connection, then run wink doctor again"))
			return
		}
		result.add(warnCheck("nat", "public direct evidence", "observation history unreadable: "+err.Error(), "check runtime state permissions and run wink doctor again"))
		return
	}

	evidence := summarizePublicDirectEvidence(observations)
	result.add(evidence.check(path))
}

type publicDirectEvidence struct {
	Planned      *solver.Observation
	LocalGather  *solver.Observation
	RemoteFilter *solver.Observation
	Failure      *solver.Observation
	Success      *solver.Observation
	Selected     *solver.Observation
	Committed    *solver.Observation
}

func summarizePublicDirectEvidence(observations []solver.Observation) publicDirectEvidence {
	var evidence publicDirectEvidence
	for i := range observations {
		obs := &observations[i]
		if !isPublicDirectObservation(*obs) {
			continue
		}
		switch obs.Event {
		case "candidate_planned", "candidate_started":
			evidence.Planned = obs
		case "candidate_gathered":
			if observationDetail(obs, "candidate_side") == "local" || evidence.LocalGather == nil {
				evidence.LocalGather = obs
			}
		case "remote_candidates_filtered":
			evidence.RemoteFilter = obs
		case "candidate_failed", "protected_direct_attempt_failed":
			evidence.Failure = obs
		case "candidate_succeeded", "selected_pair":
			evidence.Success = obs
		case "path_selected":
			evidence.Selected = obs
		case "path_committed":
			evidence.Committed = obs
		}
	}
	return evidence
}

func (e publicDirectEvidence) check(path string) doctorCheck {
	if e.Committed != nil || e.Selected != nil {
		obs := firstObservation(e.Committed, e.Selected)
		role := observationDetail(obs, "path_role")
		dependencies := observationDetail(obs, "path_dependencies")
		if role == "protected_direct" && dependencies == "" {
			return okCheck("nat", "public direct evidence", publicDirectObservationMessage("public direct protected path selected", obs, path))
		}
		return warnCheck("nat", "public direct evidence", publicDirectObservationMessage("public direct selected but not proven protected", obs, path), "check selected candidate addresses; dependent direct-like paths may still rely on an overlay or middle node")
	}
	if e.Success != nil {
		return warnCheck("nat", "public direct evidence", publicDirectObservationMessage("public direct ICE candidate succeeded but was not committed as protected direct", e.Success, path), "verify path_selected/path_committed has path_role=protected_direct and empty path_dependencies before treating this as an independent direct path")
	}
	if e.RemoteFilter != nil && observationCandidateKept(e.RemoteFilter) == 0 {
		return warnCheck("nat", "public direct evidence", publicDirectObservationMessage("remote has no usable public direct candidates", e.RemoteFilter, path), "check the remote peer STUN result, candidate filters, UDP firewall, and whether it only exposes private/100.64/overlay candidates")
	}
	if e.LocalGather != nil && observationCandidateKept(e.LocalGather) == 0 {
		return warnCheck("nat", "public direct evidence", publicDirectObservationMessage("local gather produced no usable public direct candidates", e.LocalGather, path), "check nat.stun_servers, UDP outbound reachability, candidate filters, NAT1To1 public hints, or nat.public_endpoint_hints")
	}
	if e.Failure != nil {
		return warnCheck("nat", "public direct evidence", publicDirectObservationMessage("public direct attempt failed", e.Failure, path), "if natpierce succeeds, compare its mapped endpoint with WinkYou STUN/candidate observations and verify both peers run the latest binary")
	}
	if e.Planned != nil {
		return warnCheck("nat", "public direct evidence", publicDirectObservationMessage("public direct was planned but no final result was recorded", e.Planned, path), "keep both peers online long enough for legacyice/public_direct to gather, exchange, and check candidates")
	}
	return warnCheck("nat", "public direct evidence", "no legacyice/public_direct observations found in "+path, "ensure connectivity.mode is not relay_only, nat.force_relay=false, both peers are updated, and a peer connection has been attempted")
}

func publicDirectObservationMessage(prefix string, obs *solver.Observation, path string) string {
	parts := []string{prefix}
	if obs != nil {
		if obs.Event != "" {
			parts = append(parts, "event="+obs.Event)
		}
		if obs.PlanID != "" {
			parts = append(parts, "plan="+obs.PlanID)
		}
		if obs.PathID != "" {
			parts = append(parts, "path="+obs.PathID)
		}
		if obs.ConnectionType != "" {
			parts = append(parts, "conn="+obs.ConnectionType)
		}
		if obs.LocalAddr != "" {
			parts = append(parts, "local="+obs.LocalAddr)
		}
		if obs.RemoteAddr != "" {
			parts = append(parts, "remote="+obs.RemoteAddr)
		}
		if obs.LocalKind != "" {
			parts = append(parts, "local_kind="+obs.LocalKind)
		}
		if obs.RemoteKind != "" {
			parts = append(parts, "remote_kind="+obs.RemoteKind)
		}
		for _, key := range []string{
			"candidate_total",
			"candidate_kept",
			"candidate_rejected",
			"candidate_reject_reasons",
			"candidate_kept_samples",
			"candidate_rejected_samples",
			"path_role",
			"path_dependencies",
			"local_candidate_kind",
			"remote_candidate_kind",
			"peer_reflexive_pair",
			"public_direct_learned_pair",
			"public_direct_remote_learned",
			"selected_pair_summary",
		} {
			if value := observationDetail(obs, key); value != "" {
				parts = append(parts, key+"="+value)
			}
		}
		if obs.Reason != "" {
			parts = append(parts, "reason="+obs.Reason)
		}
	}
	parts = append(parts, "source="+path)
	return strings.Join(parts, " ")
}

func isPublicDirectObservation(obs solver.Observation) bool {
	if strings.TrimSpace(obs.PlanID) == doctorPublicDirectPlanID {
		return true
	}
	if obs.Details == nil {
		return false
	}
	return strings.TrimSpace(obs.Details["plan_id"]) == doctorPublicDirectPlanID ||
		strings.TrimSpace(obs.Details["mode"]) == "public_direct" ||
		strings.TrimSpace(obs.Details["plan_mode"]) == "public_direct"
}

func observationCandidateKept(obs *solver.Observation) int {
	value, err := strconv.Atoi(observationDetail(obs, "candidate_kept"))
	if err != nil {
		return -1
	}
	return value
}

func observationDetail(obs *solver.Observation, key string) string {
	if obs == nil || obs.Details == nil {
		return ""
	}
	return strings.TrimSpace(obs.Details[key])
}

func firstObservation(values ...*solver.Observation) *solver.Observation {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func loadDoctorObservations(path string) ([]solver.Observation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	observations := make([]solver.Observation, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obs solver.Observation
		if err := json.Unmarshal([]byte(line), &obs); err != nil {
			continue
		}
		observations = append(observations, obs)
	}
	return observations, nil
}

func observationStatePathFromKey(key string) string {
	resolved := strings.TrimSpace(key)
	if resolved == "" {
		resolved = config.DefaultPath()
	}
	dir := filepath.Dir(resolved)
	base := strings.TrimSuffix(filepath.Base(resolved), filepath.Ext(resolved))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "wink"
	}
	return filepath.Join(dir, base+".observations.jsonl")
}

func addTunnelChecks(result *doctorResult, state *winkclient.RuntimeState, stateErr error) {
	if stateErr != nil {
		if errors.Is(stateErr, winkclient.ErrRuntimeStateNotFound) {
			result.add(warnCheck("tunnel", "runtime state", "runtime state not found", "start wink up and keep it running"))
			return
		}
		result.add(failCheck("tunnel", "runtime state", stateErr.Error(), "check runtime state file permissions"))
		return
	}
	if !state.IsFresh(20 * time.Second) {
		result.add(warnCheck("tunnel", "runtime state", "runtime state is stale", "restart wink up or check the running process"))
	} else {
		result.add(okCheck("tunnel", "runtime state", "runtime state is fresh"))
	}
	if len(state.Peers) == 0 {
		result.add(warnCheck("tunnel", "peers", "no online peers in runtime state", "start another client with the same coordinator"))
		return
	}
	connected := 0
	handshakes := 0
	for _, peer := range state.Peers {
		if peer.State == winkclient.PeerStateConnected.String() {
			connected++
		}
		if !peer.LastHandshake.IsZero() {
			handshakes++
		}
	}
	if connected == 0 {
		result.add(warnCheck("tunnel", "peers", "peers exist but none are connected", "check coordinator, strategy selection, and relay/direct reachability"))
	} else {
		result.add(okCheck("tunnel", "peers", fmt.Sprintf("%d connected peer(s)", connected)))
	}
	if handshakes == 0 {
		result.add(warnCheck("tunnel", "wireguard handshake", "no peer handshake recorded", "check selected path and system firewall"))
	} else {
		result.add(okCheck("tunnel", "wireguard handshake", fmt.Sprintf("%d peer handshake(s) recorded", handshakes)))
	}
}

func addAdvertisedRouteChecks(ctx context.Context, result *doctorResult, cfg *config.Config, state *winkclient.RuntimeState, stateErr error, routeTableProbe func(context.Context, doctorAdvertisedRouteProbeInput) doctorCheck) {
	localRoutes := normalizeStringList(nil)
	if cfg != nil {
		localRoutes = normalizeStringList(cfg.Node.AdvertiseRoutes)
	}
	if len(localRoutes) > 0 {
		result.add(okCheck("routing", "advertised routes", "publishing backend route(s): "+strings.Join(localRoutes, ",")))
		result.add(warnCheck("routing", "backend return path", "return path for advertised backend route(s) is not verified: "+strings.Join(localRoutes, ","), "ensure backend hosts route the WinkYou virtual CIDR back through this gateway, or configure gateway SNAT/masquerade"))
	} else {
		result.add(okCheck("routing", "advertised routes", "no local backend routes configured"))
	}

	if stateErr != nil || state == nil || len(state.Peers) == 0 {
		if len(localRoutes) > 0 {
			result.add(warnCheck("routing", "peer advertised routes", "no runtime peer state to verify advertised routes", "start wink up and check peers after they bind"))
		}
		return
	}

	connected := make([]string, 0, len(state.Peers))
	disconnected := make([]string, 0, len(state.Peers))
	routeTableInputs := make([]doctorAdvertisedRouteProbeInput, 0)
	for _, peer := range state.Peers {
		if len(peer.AdvertisedRoutes) == 0 {
			continue
		}
		peerName := firstNonEmpty(peer.Name, peer.NodeID)
		entry := fmt.Sprintf("%s=%s", peerName, strings.Join(peer.AdvertisedRoutes, ","))
		if peer.State == winkclient.PeerStateConnected.String() || peer.DataState == winkclient.PeerDataStateAlive.String() || peer.DataState == winkclient.PeerDataStateBound.String() {
			connected = append(connected, entry)
			for _, route := range peer.AdvertisedRoutes {
				routeTableInputs = append(routeTableInputs, doctorAdvertisedRouteProbeInput{
					PeerName:      peerName,
					PeerVirtualIP: peer.VirtualIP,
					Route:         route,
				})
			}
		} else {
			disconnected = append(disconnected, entry)
		}
	}
	if len(connected) > 0 {
		result.add(okCheck("routing", "peer advertised routes", "active peer backend route(s): "+strings.Join(connected, "; ")))
	}
	if len(disconnected) > 0 {
		result.add(warnCheck("routing", "peer advertised routes", "advertised route(s) from peers that are not bound: "+strings.Join(disconnected, "; "), "connect the gateway peer, then verify WireGuard AllowedIPs and OS route table"))
	}
	for _, input := range routeTableInputs {
		if routeTableProbe != nil {
			result.add(routeTableProbe(ctx, input))
		}
	}
	if len(localRoutes) == 0 && len(connected) == 0 && len(disconnected) == 0 {
		result.add(okCheck("routing", "peer advertised routes", "no peer backend routes observed"))
	}
}

func defaultAdvertisedRouteTableProbe(ctx context.Context, input doctorAdvertisedRouteProbeInput) doctorCheck {
	route := strings.TrimSpace(input.Route)
	gateway := strings.TrimSpace(input.PeerVirtualIP)
	if route == "" || gateway == "" {
		return warnCheck("routing", "os route table", "cannot verify advertised route with empty route or gateway", "check wink peers --json for advertised_routes and virtual_ip")
	}
	switch runtime.GOOS {
	case "windows":
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsRouteTableProbeScript(route)).CombinedOutput()
		if err != nil {
			detail := strings.TrimSpace(string(output))
			if detail == "" {
				detail = err.Error()
			} else {
				detail += ": " + err.Error()
			}
			return failCheck("routing", "os route table", fmt.Sprintf("%s via %s is not installed: %s", route, gateway, detail), "reconnect the peer, run as Administrator, and check Windows route table permissions")
		}
		nextHop, detail := parseRouteProbeNextHop(string(output))
		if nextHop == gateway {
			return okCheck("routing", "os route table", fmt.Sprintf("%s via %s for %s", route, gateway, input.PeerName))
		}
		return failCheck("routing", "os route table", fmt.Sprintf("%s next hop is %s, want %s: %s", route, dashIfEmpty(nextHop), gateway, detail), "remove stale routes and reconnect the gateway peer")
	case "linux":
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(probeCtx, "ip", "-o", "route", "show", route).CombinedOutput()
		detail := strings.TrimSpace(string(output))
		if err != nil {
			if detail == "" {
				detail = err.Error()
			} else {
				detail += ": " + err.Error()
			}
			return failCheck("routing", "os route table", fmt.Sprintf("%s via %s is not installed: %s", route, gateway, detail), "check ip route and reconnect the gateway peer")
		}
		if strings.Contains(detail, "via "+gateway) {
			return okCheck("routing", "os route table", fmt.Sprintf("%s via %s for %s", route, gateway, input.PeerName))
		}
		return failCheck("routing", "os route table", fmt.Sprintf("%s route does not use %s: %s", route, gateway, dashIfEmpty(detail)), "remove stale routes and reconnect the gateway peer")
	default:
		return warnCheck("routing", "os route table", "route table check is not implemented for "+runtime.GOOS, "verify the OS route for "+route+" via "+gateway+" manually")
	}
}

func addRouteTargetChecks(ctx context.Context, result *doctorResult, flags doctorFlags, routeTargetProbe func(context.Context, string) doctorCheck) {
	for _, target := range normalizeStringList(flags.routeTargets) {
		if routeTargetProbe != nil {
			result.add(routeTargetProbe(ctx, target))
		}
	}
}

type doctorRouteTargetProbeResult struct {
	Target         string
	InterfaceAlias string
	InterfaceIndex string
	LocalAddress   string
	NextHop        string
	Detail         string
}

func defaultRouteTargetProbe(ctx context.Context, target string) doctorCheck {
	target = strings.TrimSpace(target)
	if _, err := netip.ParseAddr(target); err != nil {
		return failCheck("routing", "target route", "invalid target IP: "+target, "pass an IP address, for example --route-target 10.6.22.1")
	}
	switch runtime.GOOS {
	case "windows":
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsRouteTargetProbeScript(target)).CombinedOutput()
		detail := strings.TrimSpace(string(output))
		if err != nil {
			if detail == "" {
				detail = err.Error()
			} else {
				detail += ": " + err.Error()
			}
			return failCheck("routing", "target route", target+" route lookup failed: "+detail, "verify the target IP and OS route table")
		}
		return routeTargetCheck(parseWindowsRouteTargetProbeOutput(string(output)))
	case "linux":
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(probeCtx, "ip", "-o", "route", "get", target).CombinedOutput()
		detail := strings.TrimSpace(string(output))
		if err != nil {
			if detail == "" {
				detail = err.Error()
			} else {
				detail += ": " + err.Error()
			}
			return failCheck("routing", "target route", target+" route lookup failed: "+detail, "verify the target IP and OS route table")
		}
		return routeTargetCheck(parseLinuxRouteTargetProbeOutput(target, string(output)))
	default:
		return warnCheck("routing", "target route", "target route check is not implemented for "+runtime.GOOS, "verify the OS route for "+target+" manually")
	}
}

func routeTargetCheck(route doctorRouteTargetProbeResult) doctorCheck {
	target := strings.TrimSpace(route.Target)
	if target == "" {
		target = "target"
	}
	message := target + " uses " + routeTargetRouteSummary(route)
	if isLikelyExternalOverlayInterface(route.InterfaceAlias) {
		return warnCheck("routing", "target route", message, "this target currently routes through an external overlay; to prove WinkYou carries it, advertise the backend route through a WinkYou peer and verify the route points to that peer virtual IP")
	}
	return okCheck("routing", "target route", message)
}

func routeTargetRouteSummary(route doctorRouteTargetProbeResult) string {
	parts := make([]string, 0, 5)
	if route.InterfaceAlias != "" {
		parts = append(parts, "interface="+route.InterfaceAlias)
	}
	if route.InterfaceIndex != "" {
		parts = append(parts, "ifindex="+route.InterfaceIndex)
	}
	if route.LocalAddress != "" {
		parts = append(parts, "local="+route.LocalAddress)
	}
	if route.NextHop != "" {
		parts = append(parts, "next_hop="+route.NextHop)
	}
	if len(parts) == 0 && route.Detail != "" {
		parts = append(parts, route.Detail)
	}
	if len(parts) == 0 {
		return "unknown route"
	}
	return strings.Join(parts, " ")
}

func windowsRouteTargetProbeScript(target string) string {
	return strings.Join([]string{
		fmt.Sprintf("$target = '%s'", strings.ReplaceAll(target, "'", "''")),
		"$route = Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop | Select-Object -First 1",
		"if ($null -eq $route) { throw \"route not found: $target\" }",
		"Write-Output (\"Target={0}\" -f $target)",
		"Write-Output (\"InterfaceAlias={0}\" -f $route.InterfaceAlias)",
		"Write-Output (\"InterfaceIndex={0}\" -f $route.InterfaceIndex)",
		"Write-Output (\"LocalAddress={0}\" -f $route.IPAddress)",
		"Write-Output (\"NextHop={0}\" -f $route.NextHop)",
	}, "; ")
}

func parseWindowsRouteTargetProbeOutput(output string) doctorRouteTargetProbeResult {
	values := parseDoctorKeyValueLines(output)
	return doctorRouteTargetProbeResult{
		Target:         values["target"],
		InterfaceAlias: values["interfacealias"],
		InterfaceIndex: values["interfaceindex"],
		LocalAddress:   values["localaddress"],
		NextHop:        values["nexthop"],
		Detail:         strings.Join(nonEmptyTrimmedLines(output), "; "),
	}
}

func parseLinuxRouteTargetProbeOutput(target, output string) doctorRouteTargetProbeResult {
	fields := strings.Fields(strings.TrimSpace(output))
	route := doctorRouteTargetProbeResult{
		Target: target,
		Detail: strings.Join(nonEmptyTrimmedLines(output), "; "),
	}
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			route.InterfaceAlias = fields[i+1]
		case "via":
			route.NextHop = fields[i+1]
		case "src":
			route.LocalAddress = fields[i+1]
		}
	}
	return route
}

func parseDoctorKeyValueLines(output string) map[string]string {
	values := make(map[string]string)
	for _, line := range nonEmptyTrimmedLines(output) {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return values
}

func nonEmptyTrimmedLines(output string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func isLikelyExternalOverlayInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, token := range []string{
		"natpierce",
		"tailscale",
		"zerotier",
		"hamachi",
		"docker",
		"vethernet",
		"virtualbox",
		"vmware",
		"loopback",
	} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func windowsRouteTableProbeScript(route string) string {
	return strings.Join([]string{
		fmt.Sprintf("$destination = '%s'", strings.ReplaceAll(route, "'", "''")),
		"$route = Get-NetRoute -DestinationPrefix $destination -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1",
		"if ($null -eq $route) { throw \"route not found: $destination\" }",
		"Write-Output (\"DestinationPrefix={0}\" -f $route.DestinationPrefix)",
		"Write-Output (\"NextHop={0}\" -f $route.NextHop)",
	}, "; ")
}

func parseRouteProbeNextHop(output string) (string, string) {
	lines := make([]string, 0)
	nextHop := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "NextHop") {
			nextHop = strings.TrimSpace(value)
		}
	}
	return nextHop, strings.Join(lines, "; ")
}

func addTransportChecks(result *doctorResult, state *winkclient.RuntimeState, stateErr error) {
	if stateErr != nil || state == nil || len(state.Peers) == 0 {
		result.add(warnCheck("transport", "packet transport", "no runtime transport state", "start wink up and connect a peer"))
		return
	}
	for _, peer := range state.Peers {
		if peer.TransportLastError != "" {
			result.add(failCheck("transport", "last error", fmt.Sprintf("%s: %s", firstNonEmpty(peer.Name, peer.NodeID), peer.TransportLastError), "check path reachability and relay firewall"))
			return
		}
	}
	totalTx := uint64(0)
	totalRx := uint64(0)
	for _, peer := range state.Peers {
		totalTx += peer.TransportTxPackets
		totalRx += peer.TransportRxPackets
	}
	if totalTx == 0 && totalRx == 0 {
		result.add(warnCheck("transport", "packet counters", "transport packet counters are zero", "generate traffic, then run wink peers again"))
		return
	}
	result.add(okCheck("transport", "packet counters", fmt.Sprintf("tx=%d rx=%d packets", totalTx, totalRx)))
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func addInbandHealthChecks(result *doctorResult, state *winkclient.RuntimeState, stateErr error) {
	if stateErr != nil || state == nil || len(state.Peers) == 0 {
		result.add(warnCheck("in-band", "peer health", "no runtime in-band health state", "start wink up and connect a bound/alive peer"))
		return
	}

	now := time.Now()
	heartbeatPeers := make([]string, 0, len(state.Peers))
	pathHealthPeers := make([]string, 0, len(state.Peers))
	for _, peer := range state.Peers {
		name := firstNonEmpty(peer.Name, peer.NodeID)
		if runtimeTimeFreshAt(peer.LastInbandHeartbeatAt, now, doctorInbandHealthWindow) {
			heartbeatPeers = append(heartbeatPeers, name)
		}
		if runtimeTimeFreshAt(peer.LastInbandPathHealthAt, now, doctorInbandHealthWindow) {
			pathHealthPeers = append(pathHealthPeers, name)
		}
	}

	if len(heartbeatPeers) == 0 {
		result.add(warnCheck("in-band", "heartbeat", "no fresh in-band heartbeat observed", "keep the peer data path bound and wait for heartbeat exchange; coordinator loss will otherwise show disconnected"))
	} else {
		result.add(okCheck("in-band", "heartbeat", fmt.Sprintf("%d peer(s) fresh: %s", len(heartbeatPeers), strings.Join(heartbeatPeers, ","))))
	}
	if len(pathHealthPeers) == 0 {
		result.add(warnCheck("in-band", "path health", "no fresh in-band path_health observed", "keep traffic flowing over the peer data path; data state will become stale when both tunnel and in-band health are stale"))
	} else {
		result.add(okCheck("in-band", "path health", fmt.Sprintf("%d peer(s) fresh: %s", len(pathHealthPeers), strings.Join(pathHealthPeers, ","))))
	}
}

func addMultipathChecks(result *doctorResult, cfg *config.Config, state *winkclient.RuntimeState, stateErr error) {
	if cfg == nil || !cfg.Connectivity.Multipath.Enabled {
		result.add(warnCheck("multipath", "policy", "multipath is disabled", "set connectivity.multipath.enabled=true and keep connectivity.multipath.protect_direct=true"))
		return
	}
	if relayOnlyPolicyDisablesMultipath(cfg) {
		result.add(warnCheck("multipath", "policy", "relay-only policy keeps sessions single-path even though multipath is enabled in config", "use connectivity.mode=auto with strategy_order relay_only,legacy_ice_udp for relay primary plus protected direct standby; remove nat.force_relay"))
		return
	}
	if stateErr != nil || state == nil || len(state.Peers) == 0 {
		result.add(warnCheck("multipath", "runtime state", "multipath is enabled but no runtime peer state is available", "start wink up and connect a peer"))
		return
	}

	multipathPeers := 0
	protectedPeers := 0
	activeDetails := make([]string, 0, len(state.Peers))
	dependentDetails := make([]string, 0, len(state.Peers))
	for _, peer := range state.Peers {
		if !peer.MultipathEnabled {
			continue
		}
		multipathPeers++
		if len(peer.LastPathDependencies) > 0 || peer.LastPathRole != "" {
			dependentDetails = append(dependentDetails, fmt.Sprintf("%s path=%s role=%s deps=%s", firstNonEmpty(peer.Name, peer.NodeID), dashIfEmpty(peer.LastPathID), dashIfEmpty(peer.LastPathRole), dashIfEmpty(strings.Join(peer.LastPathDependencies, ","))))
		}
		if peer.ProtectedDirectPathID == "" {
			continue
		}
		protectedPeers++
		activeDetails = append(activeDetails, fmt.Sprintf("%s primary=%s protected_direct=%s active=%s", firstNonEmpty(peer.Name, peer.NodeID), dashIfEmpty(peer.PrimaryPathID), peer.ProtectedDirectPathID, dashIfEmpty(peer.ActivePathID)))
	}
	if multipathPeers == 0 {
		result.add(warnCheck("multipath", "runtime state", "multipath is enabled but no peer is using a multipath transport", "connect a peer with multiple successful paths or check strategy_order"))
		return
	}
	if protectedPeers == 0 {
		message := "multipath is enabled but protected direct standby is unavailable"
		if len(dependentDetails) > 0 {
			message += ": " + strings.Join(dependentDetails, "; ")
		}
		result.add(warnCheck("multipath", "protected direct", message, "check direct/P2P reachability; current paths may depend on a coordinator, relay, or middle node"))
		return
	}
	result.add(okCheck("multipath", "protected direct", strings.Join(activeDetails, "; ")))
}

func relayOnlyPolicyDisablesMultipath(cfg *config.Config) bool {
	if cfg == nil || !cfg.Connectivity.Multipath.Enabled {
		return false
	}
	return cfg.NAT.ForceRelay || strings.EqualFold(strings.TrimSpace(cfg.Connectivity.Mode), "relay_only")
}

func runtimeTimeFreshAt(ts, now time.Time, window time.Duration) bool {
	if ts.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if window <= 0 {
		return true
	}
	return !ts.After(now) && now.Sub(ts) <= window
}

func printDoctorResult(cmd *cobra.Command, result doctorResult) {
	for _, check := range result.Checks {
		cmd.Printf("[%s] %s: %s\n", strings.ToUpper(string(check.Status)), check.Name, check.Message)
		if check.Suggestion != "" {
			cmd.Printf("Suggestion: %s\n", check.Suggestion)
		}
	}
	cmd.Printf("Summary: ok=%d warn=%d fail=%d\n", result.Summary.OK, result.Summary.Warn, result.Summary.Fail)
}

func (r *doctorResult) add(check doctorCheck) {
	r.Checks = append(r.Checks, check)
}

func (r *doctorResult) finish() {
	worst := doctorOK
	for _, check := range r.Checks {
		switch check.Status {
		case doctorFail:
			r.Summary.Fail++
			worst = doctorFail
		case doctorWarn:
			r.Summary.Warn++
			if worst != doctorFail {
				worst = doctorWarn
			}
		default:
			r.Summary.OK++
		}
	}
	r.Summary.Worst = worst
}

func okCheck(layer, name, message string) doctorCheck {
	return doctorCheck{Layer: layer, Name: name, Status: doctorOK, Message: message}
}

func warnCheck(layer, name, message, suggestion string) doctorCheck {
	return doctorCheck{Layer: layer, Name: name, Status: doctorWarn, Message: message, Suggestion: suggestion}
}

func failCheck(layer, name, message, suggestion string) doctorCheck {
	return doctorCheck{Layer: layer, Name: name, Status: doctorFail, Message: message, Suggestion: suggestion}
}

func candidateFilterSummary(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	parts := make([]string, 0, 7)
	if cfg.NAT.CandidatePortMin > 0 || cfg.NAT.CandidatePortMax > 0 {
		parts = append(parts, fmt.Sprintf("port_range=%d-%d", cfg.NAT.CandidatePortMin, cfg.NAT.CandidatePortMax))
	}
	if len(cfg.NAT.CandidateInterfaceInclude) > 0 {
		parts = append(parts, "interface_include="+strings.Join(cfg.NAT.CandidateInterfaceInclude, ","))
	}
	if len(cfg.NAT.CandidateInterfaceExclude) > 0 {
		parts = append(parts, "interface_exclude="+strings.Join(cfg.NAT.CandidateInterfaceExclude, ","))
	}
	if len(cfg.NAT.CandidateCIDRInclude) > 0 {
		parts = append(parts, "cidr_include="+strings.Join(cfg.NAT.CandidateCIDRInclude, ","))
	}
	if len(cfg.NAT.CandidateCIDRExclude) > 0 {
		parts = append(parts, "cidr_exclude="+strings.Join(cfg.NAT.CandidateCIDRExclude, ","))
	}
	if strings.TrimSpace(cfg.NAT.NAT1To1CandidateType) != "" {
		parts = append(parts, "nat1to1_candidate_type="+strings.TrimSpace(cfg.NAT.NAT1To1CandidateType))
	}
	if len(cfg.NAT.NAT1To1IPs) > 0 {
		parts = append(parts, "nat1to1_ips="+strings.Join(cfg.NAT.NAT1To1IPs, ","))
	}
	if len(cfg.NAT.PublicEndpointHints) > 0 {
		parts = append(parts, "public_endpoint_hints="+strings.Join(cfg.NAT.PublicEndpointHints, ","))
	}
	if len(cfg.NAT.DirectTrustedCIDRs) > 0 {
		parts = append(parts, "direct_trusted_cidrs="+strings.Join(cfg.NAT.DirectTrustedCIDRs, ","))
	}
	if len(cfg.NAT.PublicDirectTrustedCIDRs) > 0 {
		parts = append(parts, "public_direct_trusted_cidrs="+strings.Join(cfg.NAT.PublicDirectTrustedCIDRs, ","))
	}
	return strings.Join(parts, " ")
}

func parseDoctorCIDRs(values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, prefix, err := net.ParseCIDR(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	return out, nil
}

func candidateIP(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	_, addr, ok := strings.Cut(raw, ":")
	if !ok {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func ipInDoctorCIDRs(ip net.IP, prefixes []*net.IPNet) bool {
	for _, prefix := range prefixes {
		if prefix != nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func requestedStrategy(flags doctorFlags) string {
	return strings.ToLower(strings.TrimSpace(flags.strategy))
}

func configuredStrategyOrder(cfg *config.Config) []string {
	order := append([]string(nil), cfg.Connectivity.StrategyOrder...)
	if len(order) == 0 {
		order = []string{legacyice.StrategyName, relayonly.StrategyName}
	}
	if cfg.Connectivity.Mode == relayonly.StrategyName {
		order = append([]string{relayonly.StrategyName}, removeStrategy(order, relayonly.StrategyName)...)
	}
	return order
}

func removeStrategy(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func knownDoctorStrategy(strategy string) bool {
	switch strategy {
	case legacyice.StrategyName, relayonly.StrategyName, tcpframed.StrategyName:
		return true
	default:
		return false
	}
}

func hostPortFromCoordinatorURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("coordinator url missing host: %q", raw)
	}
	return parsed.Host, nil
}

func formatUDPAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return "-"
	}
	return addr.String()
}
