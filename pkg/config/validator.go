package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

var (
	validLogLevels              = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	validLogFormats             = map[string]struct{}{"text": {}, "json": {}}
	validLogOutputs             = map[string]struct{}{"stderr": {}, "stdout": {}, "file": {}}
	validBackends               = map[string]struct{}{"auto": {}, "tun": {}, "userspace": {}, "proxy": {}}
	validConnectivityModes      = map[string]struct{}{"auto": {}, "relay_only": {}}
	validConnectivityStrategies = map[string]struct{}{"legacy_ice_udp": {}, "relay_only": {}, "tcp_framed": {}}
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
		if c.TCPFramed.DialTimeout <= 0 {
			return errors.New("tcp_framed.dial_timeout must be greater than zero when tcp_framed.enabled=true")
		}
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
