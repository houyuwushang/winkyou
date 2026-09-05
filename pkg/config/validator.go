package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	validLogLevels              = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	validLogFormats             = map[string]struct{}{"text": {}, "json": {}}
	validLogOutputs             = map[string]struct{}{"stderr": {}, "stdout": {}, "file": {}}
	validBackends               = map[string]struct{}{"auto": {}, "tun": {}, "userspace": {}, "proxy": {}, "memory": {}}
	validConnectivityModes      = map[string]struct{}{"auto": {}, "relay_only": {}}
	validConnectivityStrategies = map[string]struct{}{"legacy_ice_udp": {}, "relay_only": {}, "tcp_framed": {}, "signal_relay": {}, "birthday_punch": {}}
	validTCPFramedRoles         = map[string]struct{}{"auto": {}, "listen": {}, "dial": {}}
)

const maxPublicEndpointHintPortWindow = 512

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}

	if err := validateCIDRList("node.advertise_routes", c.Node.AdvertiseRoutes); err != nil {
		return err
	}

	if err := requireOneOf("log.level", c.Log.Level, validLogLevels); err != nil {
		return err
	}
	if err := requireOneOf("log.format", c.Log.Format, validLogFormats); err != nil {
		return err
	}
	if err := requireOneOf("log.output", c.Log.Output, validLogOutputs); err != nil {
		return err
	}
	if c.Log.Output == "file" && strings.TrimSpace(c.Log.File) == "" {
		return errors.New("log.file is required when log.output=file")
	}

	if strings.TrimSpace(c.Coordinator.URL) != "" {
		if _, err := url.ParseRequestURI(c.Coordinator.URL); err != nil {
			return fmt.Errorf("invalid coordinator.url: %w", err)
		}
	}
	if c.Coordinator.Timeout <= 0 {
		return errors.New("coordinator.timeout must be greater than zero")
	}

	if err := requireOneOf("netif.backend", c.NetIf.Backend, validBackends); err != nil {
		return err
	}
	if c.NetIf.MTU <= 0 {
		return errors.New("netif.mtu must be greater than zero")
	}

	if c.WireGuard.ListenPort < 0 || c.WireGuard.ListenPort > 65535 {
		return errors.New("wireguard.listen_port must be between 0 and 65535")
	}

	for i, server := range c.NAT.STUNServers {
		if strings.TrimSpace(server) == "" {
			return fmt.Errorf("nat.stun_servers[%d] must not be empty", i)
		}
	}
	if c.NAT.PunchInterface != strings.TrimSpace(c.NAT.PunchInterface) {
		return errors.New("nat.punch_interface must not have leading or trailing whitespace")
	}
	if c.NAT.GatherTimeout <= 0 {
		return errors.New("nat.gather_timeout must be greater than zero")
	}
	if c.NAT.ConnectTimeout <= 0 {
		return errors.New("nat.connect_timeout must be greater than zero")
	}
	if c.NAT.CheckTimeout <= 0 {
		return errors.New("nat.check_timeout must be greater than zero")
	}
	if c.NAT.RetryInterval <= 0 {
		return errors.New("nat.retry_interval must be greater than zero")
	}
	if c.NAT.RetryMaxInterval <= 0 {
		return errors.New("nat.retry_max_interval must be greater than zero")
	}
	if c.NAT.RetryMaxInterval < c.NAT.RetryInterval {
		return errors.New("nat.retry_max_interval must be greater than or equal to nat.retry_interval")
	}
	if c.NAT.CandidatePortMin < 0 || c.NAT.CandidatePortMin > 65535 {
		return errors.New("nat.candidate_port_min must be between 0 and 65535")
	}
	if c.NAT.CandidatePortMax < 0 || c.NAT.CandidatePortMax > 65535 {
		return errors.New("nat.candidate_port_max must be between 0 and 65535")
	}
	if (c.NAT.CandidatePortMin == 0) != (c.NAT.CandidatePortMax == 0) {
		return errors.New("nat.candidate_port_min and nat.candidate_port_max must be set together")
	}
	if c.NAT.CandidatePortMin > 0 && c.NAT.CandidatePortMax > 0 && c.NAT.CandidatePortMax < c.NAT.CandidatePortMin {
		return errors.New("nat.candidate_port_max must be greater than or equal to nat.candidate_port_min")
	}
	for i, server := range c.NAT.TURNServers {
		if strings.TrimSpace(server.URL) == "" {
			return fmt.Errorf("nat.turn_servers[%d].url must not be empty", i)
		}
	}
	if err := validateStringList("nat.candidate_interface_include", c.NAT.CandidateInterfaceInclude); err != nil {
		return err
	}
	if err := validateStringList("nat.candidate_interface_exclude", c.NAT.CandidateInterfaceExclude); err != nil {
		return err
	}
	if err := validateCIDRList("nat.candidate_cidr_include", c.NAT.CandidateCIDRInclude); err != nil {
		return err
	}
	if err := validateCIDRList("nat.candidate_cidr_exclude", c.NAT.CandidateCIDRExclude); err != nil {
		return err
	}
	if err := validateCIDRList("nat.direct_trusted_cidrs", c.NAT.DirectTrustedCIDRs); err != nil {
		return err
	}
	if err := validateCIDRList("nat.public_direct_trusted_cidrs", c.NAT.PublicDirectTrustedCIDRs); err != nil {
		return err
	}
	if err := validateNAT1To1CandidateType(c.NAT.NAT1To1CandidateType); err != nil {
		return err
	}
	if err := validateNAT1To1IPs("nat.nat1to1_ips", c.NAT.NAT1To1IPs); err != nil {
		return err
	}
	endpointHintAllowedCIDRs := mergeStringLists(c.NAT.CandidateCIDRInclude, c.NAT.DirectTrustedCIDRs, c.NAT.PublicDirectTrustedCIDRs)
	if err := validatePublicEndpointHints("nat.public_endpoint_hints", c.NAT.PublicEndpointHints, endpointHintAllowedCIDRs); err != nil {
		return err
	}
	if c.NAT.PublicEndpointHintPortWindow < 0 || c.NAT.PublicEndpointHintPortWindow > maxPublicEndpointHintPortWindow {
		return fmt.Errorf("nat.public_endpoint_hint_port_window must be between 0 and %d", maxPublicEndpointHintPortWindow)
	}

	mode := strings.ToLower(strings.TrimSpace(c.Connectivity.Mode))
	if mode == "" {
		mode = "auto"
	}
	if err := requireOneOf("connectivity.mode", mode, validConnectivityModes); err != nil {
		return err
	}
	seenStrategies := make(map[string]struct{}, len(c.Connectivity.StrategyOrder))
	for i, strategy := range c.Connectivity.StrategyOrder {
		name := strings.TrimSpace(strategy)
		if name == "" {
			return fmt.Errorf("connectivity.strategy_order[%d] must not be empty", i)
		}
		if _, ok := validConnectivityStrategies[name]; !ok {
			return fmt.Errorf("invalid connectivity.strategy_order[%d]: %q", i, strategy)
		}
		if _, exists := seenStrategies[name]; exists {
			return fmt.Errorf("duplicate connectivity.strategy_order[%d]: %q", i, strategy)
		}
		seenStrategies[name] = struct{}{}
	}
	if c.Connectivity.Multipath.Enabled && c.Connectivity.Multipath.MaxPaths <= 0 {
		return errors.New("connectivity.multipath.max_paths must be greater than zero when connectivity.multipath.enabled=true")
	}
	if c.Connectivity.Multipath.ActivePathSilenceTimeout < 0 {
		return errors.New("connectivity.multipath.active_path_silence_timeout must be greater than or equal to zero")
	}
	if c.TCPFramed.Enabled {
		if strings.TrimSpace(c.TCPFramed.ListenAddr) == "" {
			return errors.New("tcp_framed.listen_addr must not be empty when tcp_framed.enabled=true")
		}
		role := strings.ToLower(strings.TrimSpace(c.TCPFramed.Role))
		if role == "" {
			role = "auto"
		}
		if err := requireOneOf("tcp_framed.role", role, validTCPFramedRoles); err != nil {
			return err
		}
		if strings.TrimSpace(c.TCPFramed.DialAddr) != "" {
			if err := validateHostPort("tcp_framed.dial_addr", c.TCPFramed.DialAddr); err != nil {
				return err
			}
		}
		if c.TCPFramed.DialTimeout <= 0 {
			return errors.New("tcp_framed.dial_timeout must be greater than zero when tcp_framed.enabled=true")
		}
	}
	if err := validateAutonomousMesh(c.AutonomousMesh); err != nil {
		return err
	}
	if err := validateGateC(c.WireGuard.PrivateKey, c.GateC); err != nil {
		return err
	}

	return nil
}

func validateGateC(privateKey string, gate GateCConfig) error {
	if len(gate.Peers) == 0 {
		return nil
	}
	if len(gate.Peers) > 32 || !canonicalWireGuardKey(privateKey) {
		return errors.New("gate_c requires one canonical local wireguard private key and at most 32 peers")
	}
	seenRefs := make(map[string]struct{}, len(gate.Peers))
	seenInterfaces := make(map[string]struct{}, len(gate.Peers))
	for index, peer := range gate.Peers {
		prefix := fmt.Sprintf("gate_c.peers[%d]", index)
		if !safeGateCName(peer.Ref, 256) || !safeGateCInterfaceName(peer.MemoryInterfaceName) ||
			!canonicalWireGuardKey(peer.PublicKey) ||
			peer.MemoryMTU < 1280 || peer.MemoryMTU > 9000 ||
			peer.SessionCeiling < 5*time.Second || peer.SessionCeiling > 24*time.Hour {
			return fmt.Errorf("%s is not canonical", prefix)
		}
		if _, duplicate := seenRefs[peer.Ref]; duplicate {
			return fmt.Errorf("duplicate %s.ref", prefix)
		}
		seenRefs[peer.Ref] = struct{}{}
		if _, duplicate := seenInterfaces[peer.MemoryInterfaceName]; duplicate {
			return fmt.Errorf("duplicate %s.memory_interface_name", prefix)
		}
		seenInterfaces[peer.MemoryInterfaceName] = struct{}{}
		local, localErr := parseGateCVirtualIP(peer.LocalVirtualIP)
		remote, remoteErr := parseGateCVirtualIP(peer.PeerVirtualIP)
		if localErr != nil || remoteErr != nil || local == remote || len(peer.AllowedIPs) == 0 || len(peer.AllowedIPs) > 16 {
			return fmt.Errorf("%s virtual identity is invalid", prefix)
		}
		seenPrefixes := make(map[string]struct{}, len(peer.AllowedIPs))
		remoteCovered := false
		for allowedIndex, raw := range peer.AllowedIPs {
			allowed, err := netip.ParsePrefix(raw)
			if err != nil || allowed.Addr().Zone() != "" || !allowed.Addr().Is4() || allowed.String() != raw ||
				allowed.Contains(local) {
				return fmt.Errorf("%s.allowed_ips[%d] is invalid", prefix, allowedIndex)
			}
			if _, duplicate := seenPrefixes[raw]; duplicate {
				return fmt.Errorf("duplicate %s.allowed_ips[%d]", prefix, allowedIndex)
			}
			seenPrefixes[raw] = struct{}{}
			remoteCovered = remoteCovered || allowed.Contains(remote)
		}
		if !remoteCovered {
			return fmt.Errorf("%s.allowed_ips does not cover peer_virtual_ip", prefix)
		}
	}
	return nil
}

func canonicalWireGuardKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return false
	}
	zero := true
	for _, octet := range decoded {
		zero = zero && octet == 0
	}
	clear(decoded)
	return !zero
}

func parseGateCVirtualIP(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.Zone() != "" || address.String() != value ||
		!address.IsGlobalUnicast() || address.IsLoopback() || address.IsMulticast() || address.IsUnspecified() {
		return netip.Addr{}, errors.New("invalid Gate C virtual IP")
	}
	return address.Unmap(), nil
}

func safeGateCName(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, "\r\n\t\x00")
}

func safeGateCInterfaceName(value string) bool {
	if len(value) == 0 || len(value) > 32 || value != strings.TrimSpace(value) {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			index > 0 && character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_') {
			continue
		}
		return false
	}
	return true
}

func validateAutonomousMesh(cfg AutonomousMeshConfig) error {
	// The block is an explicit runtime opt-in. Keeping disabled values inert is
	// important for old configurations and for staged configuration generation.
	if !cfg.Enabled {
		return nil
	}

	localID := strings.TrimSpace(cfg.NodeID)
	if localID == "" {
		return errors.New("autonomous_mesh.node_id is required when autonomous_mesh.enabled=true")
	}
	localIP, err := parseIPv6ULA(cfg.VirtualIP)
	if err != nil {
		return fmt.Errorf("invalid autonomous_mesh.virtual_ip: %q (must be a numeric IPv6 ULA)", cfg.VirtualIP)
	}
	if err := validateAutonomousListen("autonomous_mesh.listen", cfg.Listen); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ControlListen) == "" || isDisabledListen(cfg.ControlListen) {
		return errors.New("autonomous_mesh.control_listen is required for managed graceful shutdown")
	}
	if err := validateLoopbackControlAddress("autonomous_mesh.control_listen", cfg.ControlListen); err != nil {
		return err
	}

	seenBootstrap := make(map[string]struct{}, len(cfg.BootstrapPeers))
	for i, peer := range cfg.BootstrapPeers {
		peerID := strings.TrimSpace(peer.NodeID)
		if peerID == "" {
			return fmt.Errorf("autonomous_mesh.bootstrap_peers[%d].node_id must not be empty", i)
		}
		if peerID == localID {
			return fmt.Errorf("autonomous_mesh.bootstrap_peers[%d].node_id must not equal autonomous_mesh.node_id", i)
		}
		if _, exists := seenBootstrap[peerID]; exists {
			return fmt.Errorf("duplicate autonomous_mesh.bootstrap_peers[%d].node_id: %q", i, peer.NodeID)
		}
		seenBootstrap[peerID] = struct{}{}
		if err := validateHostPort(fmt.Sprintf("autonomous_mesh.bootstrap_peers[%d].address", i), peer.Address); err != nil {
			return err
		}
	}

	// The pause gate runs before any legacy recovery-field validation so every
	// attempt to enable a paused path fails with the explicit incident error.
	// The per-entry maintained-peer checks and the recovery-card/secret
	// dependency rules were removed together with reachability: re-enabling
	// these fields requires restoring that validation under a reviewed ADR.
	recoveryCard := strings.TrimSpace(cfg.RecoveryCard)
	if len(cfg.MaintainPeers) > 0 || recoveryCard != "" {
		return errors.New("autonomous_mesh.maintain_peers and recovery_card are unavailable while autonomous birthday recovery is paused; see docs/INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md")
	}
	if strings.TrimSpace(cfg.SelfBootstrapSecretFile) != "" {
		return errors.New("autonomous_mesh.self_bootstrap_secret_file requires autonomous_mesh.recovery_card")
	}
	if cfg.RecoveryDebounce <= 0 {
		return errors.New("autonomous_mesh.recovery_debounce must be greater than zero when autonomous_mesh.enabled=true")
	}

	if target := strings.TrimSpace(cfg.TCPTarget); target != "" {
		if _, err := validateLoopbackTCPAddress("autonomous_mesh.tcp_target", target); err != nil {
			return err
		}
	}

	seenListeners := make(map[string]struct{}, len(cfg.TCPForwards)+len(cfg.VirtualTCPForwards))
	for i, forward := range cfg.TCPForwards {
		remoteID := strings.TrimSpace(forward.RemoteID)
		if err := validateAutonomousRemoteID(
			fmt.Sprintf("autonomous_mesh.tcp_forwards[%d].remote_id", i), localID, remoteID,
		); err != nil {
			return err
		}
		key, err := validateLoopbackTCPAddress(
			fmt.Sprintf("autonomous_mesh.tcp_forwards[%d].listen", i), forward.Listen,
		)
		if err != nil {
			return err
		}
		if _, exists := seenListeners[key]; exists {
			return fmt.Errorf("duplicate autonomous mesh TCP listener: %q", forward.Listen)
		}
		seenListeners[key] = struct{}{}
	}
	for i, forward := range cfg.VirtualTCPForwards {
		remoteID := strings.TrimSpace(forward.RemoteID)
		if err := validateAutonomousRemoteID(
			fmt.Sprintf("autonomous_mesh.virtual_tcp_forwards[%d].remote_id", i), localID, remoteID,
		); err != nil {
			return err
		}
		virtualIP, key, err := validateVirtualTCPAddress(
			fmt.Sprintf("autonomous_mesh.virtual_tcp_forwards[%d].listen", i), forward.Listen,
		)
		if err != nil {
			return err
		}
		if virtualIP == localIP {
			return fmt.Errorf("autonomous_mesh.virtual_tcp_forwards[%d].listen uses this node's virtual IP %s", i, localIP)
		}
		if _, exists := seenListeners[key]; exists {
			return fmt.Errorf("duplicate autonomous mesh TCP listener: %q", forward.Listen)
		}
		seenListeners[key] = struct{}{}
	}

	return nil
}

func validateAutonomousListen(field, value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off", "none", "-":
		return nil
	default:
		return validateHostPort(field, value)
	}
}

func isDisabledListen(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "off", "none", "-":
		return true
	default:
		return false
	}
}

func validateAutonomousRemoteID(field, localID, remoteID string) error {
	if remoteID == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if remoteID == localID {
		return fmt.Errorf("%s must not equal autonomous_mesh.node_id", field)
	}
	return nil
}

func validateLoopbackTCPAddress(field, value string) (string, error) {
	if err := validateHostPort(field, value); err != nil {
		return "", err
	}
	host, portText, _ := net.SplitHostPort(strings.TrimSpace(value))
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("localhost", canonicalPort(portText)), nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("invalid %s: %q (host must be loopback)", field, value)
	}
	return net.JoinHostPort(ip.String(), canonicalPort(portText)), nil
}

func validateVirtualTCPAddress(field, value string) (netip.Addr, string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("invalid %s: %q", field, value)
	}
	virtualIP, err := parseIPv6ULA(host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("invalid %s: %q (must use a numeric IPv6 ULA)", field, value)
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port <= 0 || port > 65535 {
		return netip.Addr{}, "", fmt.Errorf("invalid %s: %q", field, value)
	}
	return virtualIP, netip.AddrPortFrom(virtualIP, uint16(port)).String(), nil
}

func validateLoopbackControlAddress(field, value string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	host = strings.TrimSpace(host)
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("invalid %s: %q (host must be loopback)", field, value)
		}
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	return nil
}

func parseIPv6ULA(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is6() || address.Zone() != "" {
		return netip.Addr{}, errors.New("not a numeric IPv6 address")
	}
	bits := address.As16()
	if bits[0]&0xfe != 0xfc {
		return netip.Addr{}, errors.New("not an IPv6 ULA")
	}
	return address, nil
}

func canonicalPort(value string) string {
	port, _ := strconv.Atoi(strings.TrimSpace(value))
	return strconv.Itoa(port)
}

func validateHostPort(field, value string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	portValue, err := strconv.Atoi(port)
	if err != nil || portValue <= 0 || portValue > 65535 {
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	return nil
}

func requireOneOf(field, value string, allowed map[string]struct{}) error {
	if _, ok := allowed[strings.ToLower(strings.TrimSpace(value))]; !ok {
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	return nil
}

func validateStringList(field string, values []string) error {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
	}
	return nil
}

func validateCIDRList(field string, values []string) error {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("invalid %s[%d]: %q", field, i, value)
		}
	}
	return nil
}

func validateNAT1To1CandidateType(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "host", "srflx", "server_reflexive", "server-reflexive":
		return nil
	default:
		return fmt.Errorf("invalid nat.nat1to1_candidate_type: %q", value)
	}
}

func validateNAT1To1IPs(field string, values []string) error {
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		parts := strings.Split(value, "/")
		if len(parts) == 0 || len(parts) > 2 {
			return fmt.Errorf("invalid %s[%d]: %q", field, i, value)
		}
		for _, part := range parts {
			if net.ParseIP(strings.TrimSpace(part)) == nil {
				return fmt.Errorf("invalid %s[%d]: %q", field, i, value)
			}
		}
		if len(parts) == 2 {
			externalIsV4 := net.ParseIP(strings.TrimSpace(parts[0])).To4() != nil
			localIsV4 := net.ParseIP(strings.TrimSpace(parts[1])).To4() != nil
			if externalIsV4 != localIsV4 {
				return fmt.Errorf("invalid %s[%d]: %q", field, i, value)
			}
		}
	}
	return nil
}

func validatePublicEndpointHints(field string, values []string, trustedCIDRs []string) error {
	trusted, err := parseNetipPrefixes("nat.public_direct_trusted_cidrs", trustedCIDRs)
	if err != nil {
		return err
	}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		public, local, err := parsePublicEndpointHint(value)
		if err != nil ||
			!isPublicEndpointHintAddress(public.Addr(), trusted) ||
			(local.IsValid() && !isPublicEndpointHintLocalAddress(local.Addr(), trusted)) {
			return fmt.Errorf("invalid %s[%d]: %q", field, i, value)
		}
	}
	return nil
}

func mergeStringLists(lists ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, list := range lists {
		for _, value := range list {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func parseNetipPrefixes(field string, values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s[%d]: %q", field, i, value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parsePublicEndpointHint(value string) (netip.AddrPort, netip.AddrPort, error) {
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("invalid endpoint hint")
	}
	public, err := parseEndpointHintAddrPort(parts[0])
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	if len(parts) == 1 {
		return public, netip.AddrPort{}, nil
	}
	local, err := parseEndpointHintAddrPort(parts[1])
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	return public, local, nil
}

func parseEndpointHintAddrPort(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(strings.TrimSpace(value))
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint")
	}
	return endpoint, nil
}

func isPublicEndpointHintAddress(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() {
		return false
	}
	if addrInPrefixes(addr, trusted) {
		return true
	}
	if addr.IsPrivate() {
		return false
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	return !cgnat.Contains(addr) && !benchmark.Contains(addr)
}

func isPublicEndpointHintLocalAddress(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() {
		return false
	}
	if addrInPrefixes(addr, trusted) {
		return true
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	return !cgnat.Contains(addr) && !benchmark.Contains(addr)
}

func addrInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
